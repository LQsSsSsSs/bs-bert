#!/bin/bash

# Startup Script for CVSS-BERT System
# Run this from the CVSS-BERT-System directory

# Activate Virtual Environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Function to kill background processes on exit
cleanup() {
    echo "Stopping services..."
    kill $API_PID
    kill $UI_PID
    exit
}

trap cleanup SIGINT SIGTERM

echo ">>> Starting CVSS-BERT API (FastAPI) on port 8000..."
python3 main.py > api.log 2>&1 &
API_PID=$!
echo "API PID: $API_PID"

echo ">>> Starting CVSS-BERT UI (Streamlit) on port 8501..."
streamlit run app.py --server.port 8501 --server.address 0.0.0.0 > ui.log 2>&1 &
UI_PID=$!
echo "UI PID: $UI_PID"

echo ">>> Services Started!"
echo ">>> API: http://localhost:8000/docs"
echo ">>> UI:  http://localhost:8501"
echo ">>> Logs are being written to api.log and ui.log"
echo ">>> Press Ctrl+C to stop all services."

# Wait for processes
wait
