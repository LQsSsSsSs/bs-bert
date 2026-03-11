#!/bin/bash

# Diagnostic Script for CVSS-BERT Deployment
# Run as root

echo "============================================"
echo "   CVSS-BERT Deployment Diagnostic Tool     "
echo "============================================"

# 1. Check if processes are running
echo -e "\n[1] Checking Running Processes..."
UI_PROCESS=$(ps -ef | grep "streamlit" | grep -v grep)
API_PROCESS=$(ps -ef | grep "main.py" | grep -v grep)

if [ -n "$UI_PROCESS" ]; then
    echo "✅ Streamlit UI is RUNNING."
else
    echo "❌ Streamlit UI is NOT RUNNING."
fi

if [ -n "$API_PROCESS" ]; then
    echo "✅ FastAPI Backend is RUNNING."
else
    echo "❌ FastAPI Backend is NOT RUNNING."
fi

# 2. Check Listening Ports
echo -e "\n[2] Checking Listening Ports..."
if command -v netstat &> /dev/null; then
    PORTS=$(netstat -tulpn | grep -E '8501|8000')
    if [ -n "$PORTS" ]; then
        echo "$PORTS"
        
        # Check if listening on 0.0.0.0 or :::
        if echo "$PORTS" | grep -qE "0.0.0.0:8501|:::8501"; then
             echo "✅ Port 8501 is listening on ALL interfaces (Correct)."
        else
             echo "⚠️ Port 8501 might be bound to LOCALHOST only. Please use --server.address 0.0.0.0"
        fi
    else
        echo "❌ No services found listening on port 8501 or 8000."
    fi
else
    echo "⚠️ netstat command not found. Skipping port check."
fi

# 3. Check Firewall
echo -e "\n[3] Checking System Firewall (firewalld)..."
if systemctl is-active --quiet firewalld; then
    echo "🔥 Firewalld is ACTIVE."
    OPEN_PORTS=$(firewall-cmd --list-ports)
    echo "   Open Ports: $OPEN_PORTS"
    
    if echo "$OPEN_PORTS" | grep -q "8501"; then
        echo "✅ Port 8501 is OPEN in firewalld."
    else
        echo "❌ Port 8501 is NOT OPEN in firewalld."
        echo "   👉 Try running: firewall-cmd --zone=public --add-port=8501/tcp --permanent && firewall-cmd --reload"
    fi
else
    echo "ℹ️ Firewalld is NOT active (This is OK if Baota is managing iptables)."
fi

# 4. Check Baota Panel Security (Hint only)
echo -e "\n[4] Reminder for Baota Panel Users"
echo "   Please ensure you have opened ports 8501 and 8000 in the Baota Panel > Security tab."
echo "   Also check your Cloud Provider's Security Group (AWS/Aliyun/Tencent)."

echo -e "\n============================================"
echo "Diagnostic Complete."
