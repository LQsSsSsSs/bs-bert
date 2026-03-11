@echo off
REM Windows Startup Script for CVSS-BERT System

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Python is not installed or not in PATH. Please install Python 3.9+ first.
    pause
    exit /b
)

REM Check if virtual environment exists
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
)

REM Activate virtual environment
call venv\Scripts\activate

REM Install dependencies if needed (simple check)
if not exist "venv\Lib\site-packages\fastapi" (
    echo Installing dependencies...
    pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo Failed to install dependencies.
        pause
        exit /b
    )
)

echo Starting CVSS-BERT System...

REM Start FastAPI in background
start "CVSS-BERT API" cmd /c "python main.py"

REM Start Streamlit
echo Starting Web Interface...
streamlit run app.py --server.port 8501 --server.address 0.0.0.0

pause
