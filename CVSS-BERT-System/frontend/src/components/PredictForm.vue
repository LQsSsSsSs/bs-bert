<template>
  <div>
    <el-form @submit.prevent>
      <el-form-item label="漏洞描述">
        <el-input v-model="description" type="textarea" :rows="6" placeholder="输入漏洞描述（支持中文/英文）" />
      </el-form-item>
      <el-form-item>
        <el-button type="primary" :loading="loading" :disabled="!description.trim()" @click="onSubmit">
          预测
        </el-button>
      </el-form-item>
    </el-form>

    <el-alert v-if="error" type="error" :title="error" show-icon :closable="false" />

    <el-card v-if="result" style="margin-top: 16px">
      <template #header>
        <span>预测结果</span>
      </template>

      <el-descriptions :column="1" border>
        <el-descriptions-item label="Vector">{{ result.vector }}</el-descriptions-item>
        <el-descriptions-item label="Base Score">{{ result.base_score }}</el-descriptions-item>
        <el-descriptions-item label="Severity">
          <el-tag :type="severityTagType(result.severity)">{{ result.severity }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="Language">{{ result.language }}</el-descriptions-item>
        <el-descriptions-item v-if="result.translated_description" label="Translated">
          {{ result.translated_description }}
        </el-descriptions-item>
      </el-descriptions>

      <div class="result-grid">
        <el-card>
          <template #header>
            <span>单条漏洞雷达图</span>
          </template>
          <div ref="radarRef" class="chart"></div>
        </el-card>

        <el-card>
          <template #header>
            <span>分值解释卡片</span>
          </template>
          <div class="score-card-list">
            <div class="score-card">
              <div class="score-title">综合风险</div>
              <div class="score-value">{{ result.base_score.toFixed(1) }}/10</div>
              <el-progress :percentage="scorePercent" :stroke-width="12" :color="scoreColor" />
            </div>
            <div class="score-card">
              <div class="score-title">可利用性倾向</div>
              <div class="score-value">{{ exploitabilityPercent }}%</div>
              <el-progress :percentage="exploitabilityPercent" :stroke-width="10" color="#2563eb" />
            </div>
            <div class="score-card">
              <div class="score-title">影响面倾向</div>
              <div class="score-value">{{ impactPercent }}%</div>
              <el-progress :percentage="impactPercent" :stroke-width="10" color="#7c3aed" />
            </div>
          </div>
        </el-card>

        <el-card class="full-width">
          <template #header>
            <span>CVSS 子指标明细</span>
          </template>
          <el-table :data="metricRows" stripe border size="small">
            <el-table-column prop="name" label="指标" min-width="180" />
            <el-table-column prop="label" label="预测标签" min-width="140" />
            <el-table-column prop="riskScore" label="风险贡献" width="120">
              <template #default="scope">{{ scope.row.riskScore.toFixed(1) }}</template>
            </el-table-column>
            <el-table-column prop="confidence" label="置信度" width="220">
              <template #default="scope">
                <el-progress :percentage="scope.row.confidence" :stroke-width="8" />
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </div>

      <el-collapse style="margin-top: 12px">
        <el-collapse-item title="Details" name="details">
          <pre style="margin: 0; white-space: pre-wrap">{{ JSON.stringify(result.details, null, 2) }}</pre>
        </el-collapse-item>
        <el-collapse-item v-if="result.cwe" title="CWE" name="cwe">
          <pre style="margin: 0; white-space: pre-wrap">{{ JSON.stringify(result.cwe, null, 2) }}</pre>
        </el-collapse-item>
      </el-collapse>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, onUnmounted, ref, watch } from 'vue'
import * as echarts from 'echarts'
import { predict, type PredictionResponse } from '../api/cvss'

type MetricDetail = {
  label: string
  confidence: number
}

type MetricConfig = {
  key: string
  name: string
  scoreMap: Record<string, number>
}

const description = ref('')
const loading = ref(false)
const result = ref<PredictionResponse | null>(null)
const error = ref<string | null>(null)
const radarRef = ref<HTMLDivElement | null>(null)

const metricConfig: MetricConfig[] = [
  {
    key: 'cvssV3_attackVector',
    name: 'Attack Vector',
    scoreMap: { NETWORK: 10, ADJACENT_NETWORK: 7.5, LOCAL: 4.5, PHYSICAL: 2 }
  },
  {
    key: 'cvssV3_attackComplexity',
    name: 'Attack Complexity',
    scoreMap: { LOW: 9, HIGH: 4 }
  },
  {
    key: 'cvssV3_privilegesRequired',
    name: 'Privileges Required',
    scoreMap: { NONE: 10, LOW: 6.5, HIGH: 3 }
  },
  {
    key: 'cvssV3_userInteraction',
    name: 'User Interaction',
    scoreMap: { NONE: 10, REQUIRED: 5 }
  },
  {
    key: 'cvssV3_scope',
    name: 'Scope',
    scoreMap: { CHANGED: 9, UNCHANGED: 5.5 }
  },
  {
    key: 'cvssV3_confidentialityImpact',
    name: 'Confidentiality Impact',
    scoreMap: { HIGH: 10, LOW: 6, NONE: 1 }
  },
  {
    key: 'cvssV3_integrityImpact',
    name: 'Integrity Impact',
    scoreMap: { HIGH: 10, LOW: 6, NONE: 1 }
  },
  {
    key: 'cvssV3_availabilityImpact',
    name: 'Availability Impact',
    scoreMap: { HIGH: 10, LOW: 6, NONE: 1 }
  }
]

let radarChart: echarts.ECharts | null = null

function normalizeLabel(label: string) {
  return label.toUpperCase()
}

function getMetricDetail(key: string): MetricDetail | null {
  if (!result.value) return null
  const raw = result.value.details[key]
  if (!raw || typeof raw !== 'object') return null
  const detail = raw as Partial<MetricDetail>
  if (typeof detail.label !== 'string' || typeof detail.confidence !== 'number') return null
  return { label: detail.label, confidence: detail.confidence }
}

function getRiskScore(config: MetricConfig, label: string) {
  const normalized = normalizeLabel(label)
  const exact = config.scoreMap[normalized]
  return typeof exact === 'number' ? exact : 5
}

const metricRows = computed(() => {
  return metricConfig
    .map((config) => {
      const detail = getMetricDetail(config.key)
      if (!detail) return null
      const riskScore = getRiskScore(config, detail.label)
      return {
        name: config.name,
        label: detail.label,
        confidence: Number((detail.confidence * 100).toFixed(1)),
        riskScore
      }
    })
    .filter((row): row is { name: string; label: string; confidence: number; riskScore: number } => !!row)
})

const scorePercent = computed(() => {
  if (!result.value) return 0
  return Math.min(100, Math.max(0, result.value.base_score * 10))
})

const exploitabilityPercent = computed(() => {
  const keys = new Set([
    'cvssV3_attackVector',
    'cvssV3_attackComplexity',
    'cvssV3_privilegesRequired',
    'cvssV3_userInteraction'
  ])
  const rows = metricRows.value.filter((row) => {
    const config = metricConfig.find((m) => m.name === row.name)
    return config ? keys.has(config.key) : false
  })
  if (!rows.length) return 0
  const avg = rows.reduce((sum, row) => sum + row.riskScore, 0) / rows.length
  return Number((avg * 10).toFixed(1))
})

const impactPercent = computed(() => {
  const keys = new Set([
    'cvssV3_scope',
    'cvssV3_confidentialityImpact',
    'cvssV3_integrityImpact',
    'cvssV3_availabilityImpact'
  ])
  const rows = metricRows.value.filter((row) => {
    const config = metricConfig.find((m) => m.name === row.name)
    return config ? keys.has(config.key) : false
  })
  if (!rows.length) return 0
  const avg = rows.reduce((sum, row) => sum + row.riskScore, 0) / rows.length
  return Number((avg * 10).toFixed(1))
})

const scoreColor = computed(() => {
  const score = result.value?.base_score ?? 0
  if (score >= 9) return '#cf1322'
  if (score >= 7) return '#d4380d'
  if (score >= 4) return '#d48806'
  return '#389e0d'
})

function severityTagType(severity: string) {
  const s = severity.toUpperCase()
  if (s === 'CRITICAL') return 'danger'
  if (s === 'HIGH') return 'warning'
  if (s === 'MEDIUM') return 'primary'
  if (s === 'LOW') return 'success'
  return 'info'
}

function ensureRadar() {
  if (!radarChart && radarRef.value) {
    radarChart = echarts.init(radarRef.value)
  }
}

function renderRadar() {
  ensureRadar()
  if (!radarChart) return

  radarChart.setOption({
    tooltip: {},
    radar: {
      radius: '62%',
      indicator: metricRows.value.map((row) => ({ name: row.name, max: 10 })),
      splitNumber: 5
    },
    series: [
      {
        type: 'radar',
        data: [
          {
            value: metricRows.value.map((row) => Number(row.riskScore.toFixed(1))),
            name: '风险画像',
            areaStyle: { color: 'rgba(37, 99, 235, 0.25)' },
            lineStyle: { width: 2, color: '#2563eb' },
            itemStyle: { color: '#1d4ed8' }
          }
        ]
      }
    ]
  })
}

function onResize() {
  radarChart?.resize()
}

async function onSubmit() {
  loading.value = true
  error.value = null
  result.value = null
  try {
    result.value = await predict({ description: description.value })
  } catch (e: any) {
    error.value = e?.response?.data?.detail ?? e?.message ?? '请求失败'
  } finally {
    loading.value = false
  }
}

watch(
  () => result.value,
  async (value) => {
    if (!value) return
    await nextTick()
    renderRadar()
  }
)

watch(
  () => metricRows.value,
  async () => {
    if (!result.value) return
    await nextTick()
    renderRadar()
  }
)

window.addEventListener('resize', onResize)

onUnmounted(() => {
  window.removeEventListener('resize', onResize)
  radarChart?.dispose()
  radarChart = null
})
</script>

<style scoped>
.result-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: 12px;
  margin-top: 12px;
}

.full-width {
  grid-column: 1 / -1;
}

.chart {
  width: 100%;
  height: 320px;
}

.score-card-list {
  display: grid;
  gap: 10px;
}

.score-card {
  border: 1px solid #e5e7eb;
  border-radius: 10px;
  padding: 10px;
}

.score-title {
  color: #334155;
  font-size: 13px;
  margin-bottom: 6px;
}

.score-value {
  font-size: 18px;
  font-weight: 700;
  margin-bottom: 8px;
  color: #0f172a;
}
</style>

