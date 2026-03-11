CREATE DATABASE IF NOT EXISTS cvss_bert_db;
USE cvss_bert_db;

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
