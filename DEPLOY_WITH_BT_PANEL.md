# CentOS 9 + 宝塔面板 (Bt-Panel) 部署指南

本指南将指导您如何在 CentOS 9 Stream 系统上，使用宝塔面板 (Bt-Panel) 部署 CVSS-BERT 智能漏洞评估系统。

## 1. 安装宝塔面板

如果您尚未安装宝塔面板，请连接到您的 CentOS 9 服务器终端（SSH），并执行以下命令安装：

```bash
url=https://download.bt.cn/install/install_lts.sh;if [ -f /usr/bin/curl ];then curl -sSO $url;else wget -O install_lts.sh $url;fi;bash install_lts.sh ed8484bec
```

安装完成后，请保存好终端显示的**面板地址、用户名和密码**。

## 2. 环境软件准备

登录宝塔面板，进入【软件商店】，搜索并安装以下软件：

1.  **MySQL** (推荐 5.7 或 8.0)
2.  **Nginx** (推荐 1.22+，用于反向代理，可选)
3.  **Python项目管理器** (或者直接使用终端安装 Python 环境)
4.  **Supervisor管理器** (强烈推荐，用于后台保活服务)

## 3. 上传项目代码

1.  进入【文件】菜单。
2.  进入 `/www/wwwroot/` 目录（或者您喜欢的其他目录）。
3.  点击【上传】，将本地的 `CVSS-BERT-System` 文件夹和 `CVSS-BERT-Model` 文件夹上传到服务器。
    *   **注意**：`CVSS-BERT-Model` 必须与 `CVSS-BERT-System` 在**同一级**目录。
    *   目录结构应如下所示：
        ```
        /www/wwwroot/
        ├── CVSS-BERT-System/
        └── CVSS-BERT-Model/
        ```

## 4. 数据库配置

1.  进入【数据库】菜单，点击【添加数据库】。
2.  填写数据库信息：
    *   数据库名: `cvss_bert_db`
    *   用户名: `bert`
    *   密码: `Aa123456.` (或者您自定义的密码)
    *   访问权限: 本地服务器 (127.0.0.1)
3.  点击提交。
4.  点击新创建数据库右侧的【管理】(或者【导入】)，选择上传项目中的 `CVSS-BERT-System/schema.sql` 文件进行导入，或者直接复制 SQL 内容执行。

> **注意**: 如果您修改了数据库名、用户名或密码，请务必修改 `CVSS-BERT-System/db_utils.py` 文件中的默认配置，或者在后续启动命令中通过环境变量传入。

## 5. Python 环境配置

为了避免环境冲突，建议使用虚拟环境。您可以通过宝塔的终端操作：

1.  点击面板左侧的【终端】，输入 root 密码登录。
2.  进入项目目录：
    ```bash
    cd /www/wwwroot/CVSS-BERT-System
    ```
3.  安装系统依赖（如果尚未安装）：
    ```bash
    dnf install -y python3-devel mysql-devel gcc
    ```
4.  创建并激活虚拟环境：
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```
5.  安装项目依赖：
    ```bash
    pip install --upgrade pip
    pip install -r requirements.txt
    ```
    *(国内服务器可添加 `-i https://pypi.tuna.tsinghua.edu.cn/simple` 加速)*

## 6. 启动服务 (使用 Supervisor 托管)

为了让服务在后台稳定运行，我们使用宝塔的【Supervisor管理器】。

### 6.1 添加 Streamlit 前端服务

1.  打开【软件商店】->【Supervisor管理器】->【添加守护进程】。
2.  填写配置：
    *   **名称**: `cvss_bert_ui`
    *   **启动用户**: `root`
    *   **运行目录**: `/www/wwwroot/CVSS-BERT-System`
    *   **启动命令**: 
        ```bash
        /www/wwwroot/CVSS-BERT-System/venv/bin/streamlit run /www/wwwroot/CVSS-BERT-System/app.py --server.port 8501 --server.address 0.0.0.0
        ```
        *(注意：必须添加 --server.address 0.0.0.0 才能允许外部访问)*
3.  点击确定。

### 6.2 添加 FastAPI 后端服务

1.  再次点击【添加守护进程】。
2.  填写配置：
    *   **名称**: `cvss_bert_api`
    *   **启动用户**: `root`
    *   **运行目录**: `/www/wwwroot/CVSS-BERT-System`
        *(注意：这是您上传项目的实际路径。如果您上传到了 /root/CVSS-BERT-System，请这里填 /root/CVSS-BERT-System)*
    *   **启动命令**:
        ```bash
        /www/wwwroot/CVSS-BERT-System/venv/bin/python /www/wwwroot/CVSS-BERT-System/main.py
        ```
        *(建议使用 main.py 的绝对路径，防止找不到文件。请将 /www/wwwroot/... 替换为您实际的路径)*
3.  点击确定。

### 6.3 验证状态
确保两个服务的状态都显示为 **"已启动"** (绿色)。

## 7. 放行端口

进入【安全】菜单，放行以下端口：
*   **8501** (Web 界面)
*   **8000** (API 接口)

## 8. 访问项目

*   **Web 界面**: `http://<您的服务器IP>:8501`
*   **API 文档**: `http://<您的服务器IP>:8000/docs`

---

## 进阶：使用 Nginx 反向代理 (可选)

如果您希望通过域名访问（如 `http://cvss.example.com`），可以配置 Nginx。

1.  进入【网站】->【添加站点】。
2.  域名填写您的域名。
3.  PHP版本选择【纯静态】。
4.  创建成功后，点击【设置】->【反向代理】->【添加反向代理】。
5.  **代理名称**: `Streamlit`
6.  **目标URL**: `http://127.0.0.1:8501`
7.  **发送域名**: `$host`
8.  对于 Streamlit，还需要配置 WebSocket 支持。在反向代理配置文件中添加：
    ```nginx
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    ```
