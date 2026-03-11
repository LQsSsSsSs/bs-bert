import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import sys
import os

# Add parent directory to sys.path
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from predictor_service import CVSSPredictor
from db_utils import save_log, get_history

# Initialize FastAPI app
app = FastAPI(
    title="CVSS-BERT API",
    description="API for predicting CVSS vector and score from vulnerability description",
    version="1.0.0"
)

# Initialize Predictor (Load models once on startup)
predictor = CVSSPredictor()

# Pydantic models for request/response
class PredictionRequest(BaseModel):
    description: str

class CWEDetail(BaseModel):
    label: str
    confidence: float
    info: dict = None

class MetricDetail(BaseModel):
    label: str
    confidence: float

class PredictionResponse(BaseModel):
    vector: str
    base_score: float
    severity: str
    details: dict
    cwe: CWEDetail = None
    translated_description: str = None
    language: str

@app.post("/predict", response_model=PredictionResponse)
async def predict_vulnerability(request: PredictionRequest):
    try:
        # 1. Language Detection & Translation
        lang, translated_text = predictor.detect_and_translate(request.description)
        
        # 2. Prediction
        result = predictor.predict(translated_text)
        
        # 3. Save to DB (Async in production ideally, but sync here for simplicity)
        save_log(
            original_desc=request.description,
            translated_desc=translated_text if lang != 'en' else "",
            cvss_vector=result['vector'],
            base_score=result['base_score'],
            severity=result['severity'],
            source_ip="API-Client"
        )
        
        # Add extra info to response
        result['language'] = lang
        if lang != 'en':
            result['translated_description'] = translated_text
            
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/history")
async def get_prediction_history(limit: int = 10):
    return get_history(limit)

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
