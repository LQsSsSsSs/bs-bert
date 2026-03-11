import mysql.connector
from mysql.connector import Error
import datetime
import streamlit as st

import os

# Configuration
# 优先从环境变量获取配置，方便部署；默认值为本地开发配置
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")  # 默认连接本地数据库
DB_USER = os.getenv("DB_USER", "bert")
DB_PASSWORD = os.getenv("DB_PASSWORD", "Aa123456.")
DB_NAME = os.getenv("DB_NAME", "cvss_bert_db")
DB_PORT = int(os.getenv("DB_PORT", 3306))

def get_connection():
    """Create a database connection"""
    connection = None
    try:
        connection = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            passwd=DB_PASSWORD,
            database=DB_NAME,
            port=DB_PORT,
            connection_timeout=5
        )
    except Error as e:
        # st.error(f"Error connecting to MySQL: {e}")
        # Return None if connection fails
        return None
    return connection

def init_db():
    """Initialize the database table if it doesn't exist"""
    # This SQL is for reference, might need to be run manually on the server
    # since we might not have permission to create databases remotely
    sql_create_table = """
    CREATE TABLE IF NOT EXISTS vulnerability_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        original_description TEXT,
        translated_description TEXT,
        cvss_vector VARCHAR(255),
        base_score FLOAT,
        severity VARCHAR(50),
        source_ip VARCHAR(50)
    );
    """
    # We won't run this automatically to avoid errors if connection fails
    return sql_create_table

def save_log(original_desc, translated_desc, cvss_vector, base_score, severity, source_ip="localhost"):
    """Save a prediction log to the database"""
    conn = get_connection()
    if conn is None:
        return False
    
    try:
        cursor = conn.cursor()
        query = """
        INSERT INTO vulnerability_logs 
        (original_description, translated_description, cvss_vector, base_score, severity, source_ip, timestamp) 
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        timestamp = datetime.datetime.now()
        values = (original_desc, translated_desc, cvss_vector, base_score, severity, source_ip, timestamp)
        
        cursor.execute(query, values)
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except Error as e:
        st.error(f"Failed to save log: {e}")
        if conn.is_connected():
            conn.close()
        return False

def get_history(limit=50):
    """Retrieve history from database"""
    conn = get_connection()
    if conn is None:
        return []
    
    try:
        cursor = conn.cursor(dictionary=True)
        query = "SELECT * FROM vulnerability_logs ORDER BY timestamp DESC LIMIT %s"
        cursor.execute(query, (limit,))
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return rows
    except Error as e:
        # st.error(f"Failed to fetch history: {e}")
        if conn.is_connected():
            conn.close()
        return []
