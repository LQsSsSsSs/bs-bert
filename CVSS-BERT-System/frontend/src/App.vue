<template>
  <div class="page">
    <el-page-header content="CVSS-BERT" />

    <el-tabs v-model="active" style="margin-top: 12px">
      <el-tab-pane label="漏洞描述分析" name="predict">
        <PredictForm />
      </el-tab-pane>
      <el-tab-pane label="历史记录" name="history">
        <HistoryTable />
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import PredictForm from './components/PredictForm.vue'
import HistoryTable from './components/HistoryTable.vue'

const active = ref<'predict' | 'history'>('predict')
</script>

