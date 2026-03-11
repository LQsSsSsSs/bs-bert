# CVSS-BERT 智能漏洞评估系统 (Linux CentOS 9 版)

## 1. 项目简介
CVSS-BERT 是一个基于 BERT 大语言模型的智能漏洞评估系统，能够根据自然语言描述自动预测 CVSS v3.1 评分向量、严重程度以及 CWE 漏洞类型。系统包含 Web 可视化界面 (Streamlit) 和 RESTful API (FastAPI) 两种访问方式，并提供服务器日志实时攻击检测功能。

## 2. 系统架构

本系统采用现代化的微服务架构设计：

*   **前端展示层 (Presentation Layer)**: 使用 Streamlit 构建的交互式 Web 界面，提供漏洞评估、历史记录查询和实时日志监控可视化。
*   **API 服务层 (API Layer)**: 使用 FastAPI 提供高性能的 RESTful 接口，支持外部系统集成。
*   **核心服务层 (Service Layer)**: 
    *   `CVSSPredictor`: 封装了基于 BERT 的深度学习模型 (Peft/LoRA 微调)，负责核心预测逻辑。
    *   `LogParser`: 负责解析 Nginx/Apache/SSH 等系统日志，提取潜在攻击特征。
*   **数据持久层 (Data Layer)**: 使用 MySQL 存储历史评估记录和检测日志。
*   **模型层 (Model Layer)**: 位于 `../CVSS-BERT-Model` 目录，包含多个针对 CVSS 不同指标微调的 BERT 模型适配器。

### 目录结构
```
├── CVSS-BERT-System/      # 核心代码
│   ├── app.py             # Streamlit 前端入口
│   ├── main.py            # FastAPI 后端入口
│   ├── predictor_service.py # 模型预测服务封装
│   ├── log_parser.py      # 日志解析逻辑
│   ├── db_utils.py        # 数据库操作工具
│   ├── requirements.txt   # Python 依赖
│   ├── schema.sql         # 数据库建表语句
│   ├── setup_centos.sh    # CentOS 9 环境安装脚本
│   ├── start.sh           # 启动脚本
│   └── Web-logs/          # 日志监控目录
└── CVSS-BERT-Model/       # 预训练模型文件 (必须存在于同级目录)
```

## 3. 环境搭建 (CentOS 9 Stream)

### 3.1 前置准备
确保您的服务器安装了 CentOS 9 Stream，并且具有 root 权限。
同时，确保 `CVSS-BERT-Model` 文件夹位于 `CVSS-BERT-System` 的**同级目录**。

### 3.2 自动安装依赖
我们提供了一键安装脚本，用于配置系统环境和 Python 依赖。

> **宝塔面板用户请注意**：如果您使用宝塔面板 (Bt-Panel)，请直接参考 [DEPLOY_WITH_BT_PANEL.md](DEPLOY_WITH_BT_PANEL.md) 进行可视化部署，无需运行下方的 setup 脚本。

#### Linux (CentOS/Ubuntu)
```bash
chmod +x setup_centos.sh
./setup_centos.sh
```

#### Windows
我们为您提供了 Windows 启动脚本 `run_windows.bat`。
1. 确保已安装 Python 3.9+。
2. 确保已安装 MySQL 数据库（如果需要记录功能）。
3. 直接双击运行 `run_windows.bat` 即可自动创建环境并启动。

该脚本会自动执行以下操作：
1. 更新系统软件包。
2. 安装 Python 3.9+, pip, git, mysql-server, mysql-devel, gcc 等必要组件。
3. 启动并配置 MySQL 服务。
4. 创建 Python 虚拟环境并安装项目依赖。

### 3.3 数据库配置
脚本安装完成后，您需要手动创建数据库用户（如果脚本未能自动完成）：

```sql
-- 登录 MySQL
mysql -u root -p

-- 执行以下 SQL 语句
CREATE DATABASE IF NOT EXISTS cvss_bert_db;
CREATE USER 'bert'@'%' IDENTIFIED BY 'Aa123456.';
GRANT ALL PRIVILEGES ON cvss_bert_db.* TO 'bert'@'%';
FLUSH PRIVILEGES;
EXIT;
```

如果您的数据库密码不同，请修改环境变量或 `db_utils.py` 中的默认配置。

## 4. 启动项目

使用提供的启动脚本同时运行 Web 界面和 API 服务：

### Linux
```bash
chmod +x start.sh
./start.sh
```

### Windows
双击 `run_windows.bat` 脚本即可启动。

### 访问服务
*   **Web 界面 (Streamlit)**: http://<服务器IP>:8501
*   **API 文档 (Swagger UI)**: http://<服务器IP>:8000/docs

## 5. 功能说明

### 5.1 漏洞描述评估
在 Web 界面输入漏洞描述（支持中文/英文），点击“开始智能分析”，系统将自动：
1. 识别语言并翻译为英文（如需要）。
2. 调用 BERT 模型预测 CVSS 8大维度指标。
3. 计算 CVSS Base Score 和严重等级。
4. 预测最可能的 CWE 漏洞类型。

### 5.2 实时日志监控
1. 将您的服务器日志（如 Nginx access.log）映射或复制到 `CVSS-BERT-System/Web-logs/` 目录下。
2. 在 Web 界面切换到“服务器日志实时检测”标签页。
3. 点击“开始实时监测”。
4. 系统会自动分析新增日志，识别 SQL 注入、XSS、命令执行等攻击行为，并调用 AI 模型评估攻击风险。

## 6. API 使用示例

**请求预测:**
```bash
curl -X 'POST' \
  'http://localhost:8000/predict' \
  -H 'Content-Type: application/json' \
  -d '{
  "description": "SQL injection vulnerability in login page allows attacker to bypass authentication."
}'
```
