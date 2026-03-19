# WEEKLY 进度报告

## 一、周目标与背景

本周围绕 CVSS-BERT-System 的前端展示能力进行优化，重点目标是将漏洞查询结果从纯文本/表格输出升级为可视化分析界面，提升可读性与研判效率。

核心方向：

1. 在历史记录页增加漏洞指标可视化（饼图、折线图、统计表）。
2. 在预测结果页增加单条漏洞可视化（雷达图、分值解释卡片、子指标明细）。
3. 完成前端构建验证，确保改动可运行。

## 二、对话推进摘要（前端优化相关）

### 1. 需求确认阶段

- 用户提出：增加查询结果的严重度等漏洞指标的直观展示（折线图、饼状图、表格）。
- 执行动作：定位前端代码结构与接口字段，确认展示入口位于历史记录页与预测结果页。

### 2. 历史记录页可视化落地

- 完成内容：
  - 严重度分布饼图
  - 分数趋势折线图（按时间）
  - 严重度统计表（数量+占比）
  - 表格中严重度标签颜色化与时间格式化

### 3. 预测结果页可视化落地

- 用户追加需求：形成“单条 + 历史”两层可视化。
- 完成内容：
  - 单条漏洞雷达图（CVSS 8个子指标）
  - 分值解释卡片（综合风险、可利用性倾向、影响面倾向）
  - CVSS 子指标明细表（指标、标签、风险贡献、置信度）

### 4. 依赖与构建验证

- 新增图表依赖：echarts
- 构建验证：前端 build 成功，改动可编译通过。

## 三、修改文件内容总结

### 1. CVSS-BERT-System/frontend/package.json

改动摘要：

- 新增依赖：echarts
- 目的：支持前端图表能力（饼图、折线图、雷达图）。

### 2. CVSS-BERT-System/frontend/src/components/HistoryTable.vue

改动摘要：

- 新增历史可视化区域 metrics-grid。
- 引入 echarts 并分别渲染：
  - 严重度分布饼图
  - 分数趋势折线图
- 新增严重度统计表：输出各等级数量与占比。
- 新增严重度规范化与标签映射：CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN。
- 新增时间格式化方法，提高时间可读性。
- 新增图表 resize 与组件卸载销毁逻辑，避免内存泄漏。

业务价值：

- 从“只看原始记录”升级为“可快速看分布、看趋势、看结构化统计”。

### 3. CVSS-BERT-System/frontend/src/components/PredictForm.vue

改动摘要：

- 新增预测结果可视化网格 result-grid。
- 新增雷达图：以 CVSS 子指标构建单条漏洞风险画像。
- 新增分值解释卡片：
  - 综合风险（Base Score）
  - 可利用性倾向（AV/AC/PR/UI 聚合）
  - 影响面倾向（S/C/I/A 聚合）
- 新增 CVSS 子指标明细表：
  - 指标名
  - 预测标签
  - 风险贡献分
  - 置信度进度条
- 严重度标签颜色化显示。
- 增加 chart 实例管理与窗口自适应刷新。

业务价值：

- 预测结果由“分数字段”升级为“可解释分析面板”，便于安全人员理解模型输出。

## 四、验证与结果

1. 前端构建验证通过（Vite build success）。
2. 历史记录页与预测页均完成可视化增强。
3. 已形成“单条漏洞分析 + 历史趋势分析”的双层展示能力。

## 五、风险与后续建议

### 当前风险

1. 图表库引入后前端包体积增加，存在 chunk 体积告警。
2. 目前可视化权重映射基于规则表，后续可与业务侧进一步校准。

### 后续建议

1. 对图表模块进行按需懒加载，降低首屏体积。
2. 增加图表导出（PNG/CSV）能力，便于周报和审计留档。
3. 增加筛选维度（时间区间、严重度等级、来源IP）提升分析效率。

## 六、截图预留区（文件修改部分）

> 说明：以下为截图占位，请将实际截图文件放入相应路径后替换。

### 1. 历史记录页可视化改动截图

- 截图A：历史页整体（饼图 + 折线图 + 统计表）
  - 占位：![截图A-历史页整体](docs/screenshots/weekly/history-dashboard.png)
- 截图B：HistoryTable.vue 关键代码片段
  - 占位：![截图B-HistoryTable代码](docs/screenshots/weekly/historytable-code.png)

### 2. 预测结果页可视化改动截图

- 截图C：预测页整体（雷达图 + 分值解释卡片 + 子指标明细）
  - 占位：![截图C-预测页整体](docs/screenshots/weekly/predict-dashboard.png)
- 截图D：PredictForm.vue 关键代码片段
  - 占位：![截图D-PredictForm代码](docs/screenshots/weekly/predictform-code.png)

### 3. 依赖与构建验证截图

- 截图E：package.json 中 echarts 依赖
  - 占位：![截图E-package依赖](docs/screenshots/weekly/package-echarts.png)
- 截图F：前端 build 成功终端输出
  - 占位：![截图F-build成功](docs/screenshots/weekly/frontend-build-success.png)
