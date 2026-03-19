import uvicorn
import sys
import os

# Add parent directory to sys.path
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from app.main import create_app

app = create_app()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
