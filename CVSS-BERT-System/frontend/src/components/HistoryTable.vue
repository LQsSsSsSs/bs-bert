<template>
  <div>
    <div class="toolbar">
      <span>条数</span>
      <el-input-number v-model="limit" :min="1" :max="200" />
      <el-button type="primary" :loading="loading" @click="load">刷新</el-button>
    </div>

    <el-alert v-if="error" type="error" :title="error" show-icon :closable="false" class="error" />

    <div v-if="rows.length" class="metrics-grid">
      <el-card>
        <template #header>
          <span>严重度分布</span>
        </template>
        <div ref="pieRef" class="chart"></div>
      </el-card>

      <el-card>
        <template #header>
          <span>分数趋势（按时间）</span>
        </template>
        <div ref="lineRef" class="chart"></div>
      </el-card>

      <el-card>
        <template #header>
          <span>严重度统计表</span>
        </template>
        <el-table :data="severityStats" stripe border size="small">
          <el-table-column prop="severity" label="严重度" min-width="120">
            <template #default="scope">
              <el-tag :type="severityTagType(scope.row.severity)">{{ scope.row.severity }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="count" label="数量" width="90" />
          <el-table-column prop="percent" label="占比" width="100">
            <template #default="scope">{{ scope.row.percent }}%</template>
          </el-table-column>
        </el-table>
      </el-card>
    </div>

    <el-table :data="rows" stripe border>
      <el-table-column prop="timestamp" label="时间" width="180">
        <template #default="scope">{{ formatTime(scope.row.timestamp) }}</template>
      </el-table-column>
      <el-table-column prop="severity" label="严重性" width="110">
        <template #default="scope">
          <el-tag :type="severityTagType(scope.row.severity)">
            {{ normalizeSeverity(scope.row.severity) }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="base_score" label="分数" width="90" />
      <el-table-column prop="cvss_vector" label="Vector" min-width="240" />
      <el-table-column prop="source_ip" label="来源" width="140" />
      <el-table-column prop="original_description" label="原始描述" min-width="260" />
    </el-table>
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref } from 'vue'
import * as echarts from 'echarts'
import { getHistory, type HistoryRow } from '../api/cvss'

type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN'

type SeverityStat = {
  severity: Severity
  count: number
  percent: string
}

const limit = ref(10)
const loading = ref(false)
const error = ref<string | null>(null)
const rows = ref<HistoryRow[]>([])
const pieRef = ref<HTMLDivElement | null>(null)
const lineRef = ref<HTMLDivElement | null>(null)

let pieChart: echarts.ECharts | null = null
let lineChart: echarts.ECharts | null = null

const severityOrder: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
const severityColors: Record<Severity, string> = {
  CRITICAL: '#cf1322',
  HIGH: '#d4380d',
  MEDIUM: '#d48806',
  LOW: '#389e0d',
  UNKNOWN: '#595959'
}

function normalizeSeverity(raw: string | null): Severity {
  const value = (raw ?? 'UNKNOWN').toUpperCase()
  if (severityOrder.includes(value as Severity)) {
    return value as Severity
  }
  return 'UNKNOWN'
}

function severityTagType(raw: string | null) {
  const severity = normalizeSeverity(raw)
  if (severity === 'CRITICAL') return 'danger'
  if (severity === 'HIGH') return 'warning'
  if (severity === 'MEDIUM') return 'primary'
  if (severity === 'LOW') return 'success'
  return 'info'
}

function formatTime(value: string) {
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) {
    return value
  }
  return d.toLocaleString('zh-CN', { hour12: false })
}

const severityStats = computed<SeverityStat[]>(() => {
  const counts: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    UNKNOWN: 0
  }

  for (const row of rows.value) {
    counts[normalizeSeverity(row.severity)] += 1
  }

  const total = rows.value.length || 1
  return severityOrder
    .map((severity) => ({
      severity,
      count: counts[severity],
      percent: ((counts[severity] / total) * 100).toFixed(1)
    }))
    .filter((item) => item.count > 0)
})

const trendRows = computed(() => {
  return [...rows.value]
    .filter((row) => typeof row.base_score === 'number')
    .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())
    .slice(-50)
})

function ensureCharts() {
  if (!pieChart && pieRef.value) {
    pieChart = echarts.init(pieRef.value)
  }
  if (!lineChart && lineRef.value) {
    lineChart = echarts.init(lineRef.value)
  }
}

function renderCharts() {
  ensureCharts()

  if (pieChart) {
    pieChart.setOption({
      color: severityStats.value.map((item) => severityColors[item.severity]),
      tooltip: { trigger: 'item' },
      legend: {
        orient: 'vertical',
        right: 2,
        top: 'middle',
        itemWidth: 14,
        itemHeight: 10,
        itemGap: 10
      },
      series: [
        {
          name: '严重度分布',
          type: 'pie',
          radius: ['42%', '70%'],
          avoidLabelOverlap: true,
          data: severityStats.value.map((item) => ({
            name: item.severity,
            value: item.count
          })),
          label: { formatter: '{b}: {d}%' }
        }
      ]
    })
  }

  if (lineChart) {
    lineChart.setOption({
      tooltip: {
        trigger: 'axis',
        valueFormatter: (value: number) => `${Number(value).toFixed(1)}`
      },
      xAxis: {
        type: 'category',
        boundaryGap: false,
        data: trendRows.value.map((row) => formatTime(row.timestamp)),
        axisLabel: { hideOverlap: true }
      },
      yAxis: {
        type: 'value',
        min: 0,
        max: 10,
        splitLine: { show: true }
      },
      series: [
        {
          name: 'Base Score',
          type: 'line',
          smooth: true,
          symbol: 'circle',
          symbolSize: 8,
          lineStyle: { width: 3, color: '#0f766e' },
          itemStyle: { color: '#0f766e' },
          areaStyle: { color: 'rgba(15, 118, 110, 0.2)' },
          data: trendRows.value.map((row) => row.base_score)
        }
      ],
      grid: { left: 48, right: 18, top: 18, bottom: 38 }
    })
  }
}

function onResize() {
  pieChart?.resize()
  lineChart?.resize()
}

async function load() {
  loading.value = true
  error.value = null
  try {
    rows.value = await getHistory(limit.value)
    await nextTick()
    renderCharts()
  } catch (e: any) {
    error.value = e?.response?.data?.detail ?? e?.message ?? '请求失败'
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  window.addEventListener('resize', onResize)
  load()
})

onUnmounted(() => {
  window.removeEventListener('resize', onResize)
  pieChart?.dispose()
  lineChart?.dispose()
  pieChart = null
  lineChart = null
})
</script>

<style scoped>
.toolbar {
  display: flex;
  gap: 12px;
  align-items: center;
  margin-bottom: 12px;
}

.error {
  margin-bottom: 12px;
}

.metrics-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 12px;
  margin-bottom: 12px;
}

.chart {
  width: 100%;
  height: 280px;
}
</style>

