import glob
import streamlit as st
import time
import pandas as pd
import sys
import os

# Add parent directory to sys.path to allow imports
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from predictor_service import CVSSPredictor
from log_parser import LogParser
from db_utils import save_log, get_history, init_db

# Page Config
st.set_page_config(
    page_title="CVSS-BERT AI Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for Modern UI
st.markdown("""
<style>
    /* Global Styling */
    .main {
        background-color: #f8f9fa;
    }
    h1, h2, h3 {
        color: #2c3e50;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
    
    /* Card Styling */
    .stCard {
        background-color: white;
        padding: 20px;
        border-radius: 10px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        margin-bottom: 20px;
    }
    
    /* Metric Card Styling */
    div[data-testid="stMetricValue"] {
        font-size: 2.5rem;
        font-weight: bold;
    }
    
    /* Severity Colors */
    .severity-low { color: #2ecc71; }
    .severity-medium { color: #f1c40f; }
    .severity-high { color: #e67e22; }
    .severity-critical { color: #e74c3c; }
    
    /* Sidebar */
    section[data-testid="stSidebar"] {
        background-color: #2c3e50;
        color: white;
    }
    
    /* Input Area */
    .stTextArea textarea {
        border-radius: 10px;
        border: 1px solid #ced4da;
    }
    
    /* Button */
    .stButton button {
        background-color: #3498db;
        color: white;
        border-radius: 8px;
        border: none;
        padding: 0.5rem 1rem;
        font-weight: 600;
        transition: all 0.3s;
    }
    .stButton button:hover {
        background-color: #2980b9;
        box-shadow: 0 2px 5px rgba(0,0,0,0.2);
    }
</style>
""", unsafe_allow_html=True)

# Initialize Predictor and Parser
predictor = CVSSPredictor()
log_parser = LogParser()

# Sidebar: History & Info
with st.sidebar:
    st.title("🛡️ CVSS-BERT")
    st.markdown("---")
    
    st.subheader("📜 历史检测记录")
    
    # Refresh button for history
    if st.button("🔄 刷新记录"):
        st.cache_data.clear()
        st.rerun()
        
    history = get_history(limit=10)
    
    if history:
        for record in history:
            # Simple card for each history item
            severity_color = "gray"
            sev = record['severity'].upper()
            if sev == "LOW": severity_color = "🟢"
            elif sev == "MEDIUM": severity_color = "🟡"
            elif sev == "HIGH": severity_color = "🟠"
            elif sev == "CRITICAL": severity_color = "🔴"
            
            with st.expander(f"{severity_color} {record['timestamp'].strftime('%H:%M')} - 评分: {record['base_score']}"):
                st.caption(f"**向量:** {record['cvss_vector']}")
                st.caption(f"**描述:** {record['original_description'][:50]}...")
    else:
        st.info("暂无历史记录，请检查数据库连接。")
        st.code(init_db(), language="sql")

# Main Content
st.title("🛡️ CVSS-BERT 智能漏洞评估系统")
st.markdown("### 基于大语言模型的 CVSS 评分预测与分析")

# Function to render prediction results
def render_results(result, original_text, translated_text, source_type="Web-Client"):
    # Save to DB
    saved = save_log(
        original_desc=original_text,
        translated_desc=translated_text,
        cvss_vector=result['vector'],
        base_score=result['base_score'],
        severity=result['severity'],
        source_ip=source_type
    )
    
    if saved:
        st.toast("✅ 检测结果已成功存入数据库！", icon="💾")
    else:
        st.toast("⚠️ 数据库连接失败，结果未保存。", icon="🔌")

    # CWE Prediction Result
    if result.get('cwe'):
        cwe_data = result['cwe']
        cwe_label = cwe_data['label']
        cwe_conf = cwe_data['confidence']
        cwe_info = cwe_data.get('info')
        
        # Default content
        cwe_title_display = cwe_label
        cwe_zh_title_display = ""
        cwe_desc_display = "暂无详细描述"
        cwe_link = "#"
        
        if cwe_info:
            cwe_title_display = f"{cwe_label}: {cwe_info['title']}"
            if cwe_info.get('zh_title'):
                    cwe_zh_title_display = f"({cwe_info['zh_title']})"
            cwe_desc_display = cwe_info['description']
            cwe_link = cwe_info['url']
        
        st.markdown(f"""
        <div style="background-color: #e8f4f8; padding: 15px; border-radius: 10px; border-left: 5px solid #3498db; margin-bottom: 20px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <h4 style="margin:0; color: #2980b9;">🔍 CWE Vulnerability Prediction</h4>
                <span style="background-color: #3498db; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem;">Confidence: {cwe_conf:.2f}</span>
            </div>
            <h3 style="margin: 10px 0 5px 0; color: #2c3e50;">{cwe_title_display}</h3>
            <h4 style="margin: 0 0 10px 0; color: #7f8c8d; font-size: 1.1rem;">{cwe_zh_title_display}</h4>
            <p style="color: #34495e; font-size: 1rem; line-height: 1.5;">{cwe_desc_display}</p>
            <a href="{cwe_link}" target="_blank" style="color: #3498db; text-decoration: none; font-size: 0.9rem;">👉 View Official CWE Definition</a>
        </div>
        """, unsafe_allow_html=True)

    # 4. Display Results
    st.subheader("📊 评估结果")

    # Metrics Row
    m1, m2, m3 = st.columns(3)
    
    # Color coding for severity
    sev_color = "normal"
    s = result['severity'].upper()
    if s == "CRITICAL": sev_color = "off" # Red inverse
    elif s == "HIGH": sev_color = "off" 
    
    m1.metric("基础评分 (Base Score)", result['base_score'])
    m2.metric("严重等级 (Severity)", result['severity'])
    
    risk_level = "中等 (Medium)"
    if result['base_score'] >= 9.0:
        risk_level = "严重 (Critical)"
    elif result['base_score'] >= 7.0:
        risk_level = "高危 (High)"
    elif result['base_score'] >= 4.0:
        risk_level = "中等 (Medium)"
    else:
        risk_level = "低危 (Low)"
        
    m3.metric("风险等级", risk_level)
    
    # Vector String
    st.code(result['vector'], language="text")
    
    # Detailed Breakdown
    with st.expander("🔍 查看详细指标分析", expanded=True):
        d_cols = st.columns(2)
        details = result['details']
        
        # Sort metrics by confidence descending to show highest hits first
        metrics_list = sorted(details.items(), key=lambda x: x[1]['confidence'], reverse=True)
        
        half = len(metrics_list) // 2
        
        with d_cols[0]:
            for k, v in metrics_list[:half]:
                name = k.replace("cvssV3_", "").replace("Impact", "")
                st.markdown(f"**{name}:** `{v['label']}` *(置信度: {v['confidence']:.2f})*")
                
        with d_cols[1]:
            for k, v in metrics_list[half:]:
                name = k.replace("cvssV3_", "").replace("Impact", "")
                st.markdown(f"**{name}:** `{v['label']}` *(置信度: {v['confidence']:.2f})*")
    
    # Highlight Highest Confidence Result
    top_metric = metrics_list[0]
    top_name = top_metric[0].replace("cvssV3_", "").replace("Impact", "")
    st.success(f"🎯 **命中率最高的结果**: {top_name} = **{top_metric[1]['label']}** (置信度: {top_metric[1]['confidence']:.2f})")

# Tabs
tab1, tab2 = st.tabs(["📄 漏洞描述分析", "🖥️ 服务器日志实时检测"])

# Tab 1: Description Analysis
with tab1:
    col1, col2 = st.columns([2, 1])
    with col1:
        st.markdown('<div class="stCard">', unsafe_allow_html=True)
        vuln_desc = st.text_area(
            "请输入漏洞描述:",
            height=150,
            placeholder="支持多种语言描述，英文命中率最高！"
        )
        
        predict_btn = st.button("🚀 开始智能分析", use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

        if predict_btn and vuln_desc:
            with st.spinner("🤖 AI 正在深入分析漏洞特征..."):
                # 1. Language Detection & Translation
                lang, translated_text = predictor.detect_and_translate(vuln_desc)
                
                if lang != 'en':
                    st.info(f"🌐 检测到 **{lang.upper()}** 语言。已自动翻译为英文进行处理。")
                    with st.expander("查看翻译后的英文描述"):
                        st.write(translated_text)
                else:
                    translated_text = vuln_desc
                
                # 2. Prediction
                result = predictor.predict(translated_text)
                
                # 3. Render Results
                render_results(result, vuln_desc, translated_text, "Web-Client-Desc")

    with col2:
        st.markdown("### 📈 实时风险监控")
        # Placeholder for charts if history exists
        if history:
            df = pd.DataFrame(history)
            if not df.empty:
                st.markdown("**近期漏洞严重性分布**")
                st.bar_chart(df['severity'].value_counts())
                st.markdown("**风险评分趋势图**")
                st.line_chart(df['base_score'].head(20))
        else:
            st.markdown("*暂无统计数据*")
            st.image("https://placehold.co/400x300?text=Waiting+for+Data", use_column_width=True)

import glob

# ... (Imports remain same) ...

# ... (Previous Code) ...

# Tab 2: Log Analysis (Real-time Monitor)
with tab2:
    st.markdown("### 🛡️ 服务器日志实时自动监测")
    st.info("正在监控文件夹: `CVSS-BERT-System/Web-logs/*.log`")
    
    # Session state for monitoring
    if 'monitoring' not in st.session_state:
        st.session_state.monitoring = False
    if 'processed_files' not in st.session_state:
        st.session_state.processed_files = {} # {filepath: last_position}

    monitor_col1, monitor_col2 = st.columns([3, 1])
    
    with monitor_col1:
        # Start/Stop Button
        if st.button("🚀 " + ("停止监测" if st.session_state.monitoring else "开始实时监测")):
            st.session_state.monitoring = not st.session_state.monitoring
            st.rerun()
            
        if st.session_state.monitoring:
            st.success("✅ 监测服务运行中... (每60秒自动扫描)")
            status_placeholder = st.empty()
            log_container = st.container()
            
            # Monitoring Loop
            while st.session_state.monitoring:
                log_dir = os.path.join(os.path.dirname(__file__), 'Web-logs')
                log_files = glob.glob(os.path.join(log_dir, "*.log"))
                
                new_logs_found = False
                
                status_placeholder.markdown(f"🔄 正在扫描 {len(log_files)} 个日志文件... ({time.strftime('%H:%M:%S')})")
                
                for file_path in log_files:
                    try:
                        # Get last position
                        last_pos = st.session_state.processed_files.get(file_path, 0)
                        current_size = os.path.getsize(file_path)
                        
                        if current_size > last_pos:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                f.seek(last_pos)
                                new_lines = f.readlines()
                                st.session_state.processed_files[file_path] = f.tell()
                                
                            for line in new_lines:
                                line = line.strip()
                                if not line: continue
                                new_logs_found = True
                                
                                # Process Log
                                with log_container:
                                    parsed = log_parser.parse_log(line)
                                    if parsed:
                                        # Only process and show attacks
                                        if parsed.get('is_attack'):
                                            # AI Prediction for attack logs only
                                            result = predictor.predict(parsed.get('description'))
                                            
                                            st.error(f"🚨 [ALERT] {os.path.basename(file_path)}: 发现潜在攻击行为！")
                                            st.code(line)
                                            
                                            # Render analysis results
                                            render_results(result, line, parsed.get('description'), f"Auto-Monitor-{os.path.basename(file_path)}")
                                            st.markdown("---")
                                        # else:
                                            # Skip normal logs (as requested)
                                            # pass
                                        
                    except Exception as e:
                        st.error(f"Error reading {file_path}: {e}")
                
                if not new_logs_found:
                    # status_placeholder.info("暂无新日志...")
                    pass
                
                time.sleep(60) # Scan every 60 seconds
                # Check if stop was pressed (requires rerun to register button click, 
                # but in a loop we can't easily check button state without rerun. 
                # User has to reload page or we use a more complex async approach. 
                # For Streamlit, simple loop blocks. We rely on user stopping script or closing tab usually, 
                # OR we use st.empty to show running status.)
                # To make "Stop" work, we would need to break loop. Streamlit buttons reset on rerun.
                # A common pattern is just running the loop forever until user stops the app.
    
    with monitor_col2:
        st.markdown("#### 📊 监控统计")
        st.metric("监控文件数", len(glob.glob(os.path.join(os.path.dirname(__file__), 'Web-logs', "*.log"))))
        st.markdown("#### 📝 已处理文件")
        for f, pos in st.session_state.processed_files.items():
            st.text(f"{os.path.basename(f)}: {pos} bytes")

# Footer
st.markdown("---")
st.markdown("© 2025 CVSS-BERT 智能安全评估系统 | 基于 Transformer 架构")
