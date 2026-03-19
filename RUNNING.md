# RUNNING

本文档用于说明如何在 Windows 下使用 conda 环境 `bert` 启动 CVSS-BERT-System，并补充项目技术栈与系统架构说明。

## 1. 路径说明

- 仓库根目录: `d:\Codebase\bert_1\web-\www.bert.com`
- 后端目录: `d:\Codebase\bert_1\web-\www.bert.com\CVSS-BERT-System`
- 前端目录: `d:\Codebase\bert_1\web-\www.bert.com\CVSS-BERT-System\frontend`

## 2. 技术栈

### 后端

- Python 3.10
- FastAPI + Uvicorn
- SQLAlchemy + PyMySQL（MySQL）
- PyTorch + Transformers + PEFT（LoRA）
- CVSS 评分库（`cvss`）
- 翻译与语言识别：`deep-translator`、`langdetect`
- CWE 信息抓取：`requests`、`beautifulsoup4`

### 前端

- Vue 3 + TypeScript
- Element Plus
- Vite
- Axios
- ECharts（用于雷达图、饼图、折线图）

## 3. 系统架构

```text
Browser (Vue3 + Element Plus + ECharts)
            |
            | HTTP/JSON
            v
FastAPI (Plugin-based API)
   - /predict  -> 加载 CVSSPredictor，推理 CVSS 各子指标并生成分值
   - /history  -> 查询历史请求日志
            |
            +--> CVSS BERT 模型目录 (CVSS-BERT-Model/bert-classifier)
            |
            +--> MySQL (保存预测历史)
```

说明：

- 后端通过插件机制加载 `predict`、`history`、`health` 路由。
- `predict` 插件调用 `app/services/predictor.py` 中的懒加载单例，避免重复加载大模型。
- 前端分为两层可视化：
   - 单条预测页：严重度标签 + 雷达图 + 分值解释卡片 + 子指标明细表。
   - 历史页：严重度分布饼图 + 分数趋势折线图 + 统计表。

## 4. 创建或更新 conda 环境

在 PowerShell 中执行：

```powershell
cd d:\Codebase\bert_1\web-\www.bert.com\CVSS-BERT-System
conda env create -f environment.yml
```

如环境已存在，使用：

```powershell
conda env update -f environment.yml --prune
```

## 5. 后端初始化检测（推荐）

```powershell
cd d:\Codebase\bert_1\web-\www.bert.com\CVSS-BERT-System
conda run -n bert python -c "from app.main import create_app; create_app(); print('create_app_ok')"
```

预期输出包含：`create_app_ok`

## 6. 启动后端服务

```powershell
cd d:\Codebase\bert_1\web-\www.bert.com\CVSS-BERT-System
conda run -n bert python main.py
```

默认监听：

- `http://127.0.0.1:8000`
- API 文档：`http://127.0.0.1:8000/docs`

## 7. 启动前端服务

新开一个 PowerShell 窗口执行：

```powershell
cd d:\Codebase\bert_1\web-\www.bert.com\CVSS-BERT-System\frontend
npm install
npm run dev
```

Vite 会输出访问地址（通常是 `http://127.0.0.1:5173`）。

## 8. 前端生产构建检查

```powershell
cd d:\Codebase\bert_1\web-\www.bert.com\CVSS-BERT-System\frontend
npm run build
```

## 9. 常见问题排查

### 9.1 端口 8000 被占用（WinError 10048）

查看占用：

```powershell
netstat -ano | findstr :8000
```

结束占用进程（替换 PID）：

```powershell
taskkill /PID <PID> /F
```

然后重新执行后端启动命令。

### 9.2 conda 环境不存在

```powershell
conda env list
```

若无 `bert`，回到第 4 节创建环境。

### 9.3 模块导入失败

请确认：

- 当前目录在 `CVSS-BERT-System`
- 使用 `conda run -n bert ...` 启动

## 10. 快速冒烟测试

1. 打开 `http://127.0.0.1:8000/docs`。
2. 调用 `POST /predict`，输入一段漏洞描述。
3. 打开前端页面，确认：
    - 预测页显示严重度标签、雷达图、分值解释卡、指标明细表。
    - 历史页显示饼图、折线图、统计表。
