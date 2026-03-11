#!/bin/bash

# CVSS-BERT System Setup Script for CentOS 9 Stream
# Must be run as root

if [ "$EUID" -ne 0 ]; then 
  echo "Please run as root"
  exit 1
fi

echo ">>> Starting Installation for CVSS-BERT System on CentOS 9..."

# 1. Update System
echo ">>> Updating system packages..."
dnf update -y

# 2. Install Dependencies
echo ">>> Installing Python, MySQL, and development tools..."
dnf install -y python3 python3-devel python3-pip gcc gcc-c++ mysql-server mysql-devel git

# 3. Start MySQL Service
echo ">>> Starting MySQL Service..."
systemctl enable --now mysqld
systemctl status mysqld | grep "Active"

# 4. Create Database (Optional - assumes default root setup)
echo ">>> Setting up Database..."
# Note: In a production script, you should handle MySQL secure installation.
# Here we try to create the DB and User if possible without password for root (default in fresh CentOS install)
# Or user needs to do it manually as per README.

mysql -u root -e "CREATE DATABASE IF NOT EXISTS cvss_bert_db;" || echo "Warning: Could not create DB automatically. Please check README."
mysql -u root -e "CREATE USER IF NOT EXISTS 'bert'@'%' IDENTIFIED BY 'Aa123456.';" || echo "Warning: Could not create user automatically."
mysql -u root -e "GRANT ALL PRIVILEGES ON cvss_bert_db.* TO 'bert'@'%';" || echo "Warning: Could not grant privileges automatically."
mysql -u root -e "FLUSH PRIVILEGES;"

# 5. Python Environment
echo ">>> Setting up Python Environment..."
# It is recommended to use venv
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# 6. Install Python Requirements
echo ">>> Installing Python Dependencies..."
if [ -f "requirements.txt" ]; then
    # pytorch CPU version is usually sufficient for inference and saves space
    # but we install from requirements.txt directly.
    # If users need GPU, they should install torch with cuda support manually.
    pip install -r requirements.txt
else
    echo "Error: requirements.txt not found!"
    exit 1
fi

# 7. Create Logs Directory
if [ ! -d "Web-logs" ]; then
    mkdir Web-logs
    echo ">>> Created Web-logs directory."
fi

echo ">>> Installation Complete!"
echo ">>> Please check README.md for startup instructions."
