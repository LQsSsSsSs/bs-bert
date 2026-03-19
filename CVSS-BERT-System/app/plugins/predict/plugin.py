from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.crud import create_log
from app.db.session import get_db
from app.services.predictor import get_predictor


router = APIRouter()


class PredictionRequest(BaseModel):
    description: str


class CWEDetail(BaseModel):
    label: str
    confidence: float
    info: dict | None = None


class PredictionResponse(BaseModel):
    vector: str
    base_score: float
    severity: str
    details: dict
    cwe: CWEDetail | None = None
    translated_description: str | None = None
    language: str


@router.post("/predict", response_model=PredictionResponse)
def predict_vulnerability(
    payload: PredictionRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    predictor = get_predictor()
    try:
        lang, translated_text = predictor.detect_and_translate(payload.description)
        result = predictor.predict(translated_text)

        source_ip = getattr(getattr(request, "client", None), "host", None) or "API-Client"
        try:
            create_log(
                db,
                original_desc=payload.description,
                translated_desc=translated_text if lang != "en" else "",
                cvss_vector=result["vector"],
                base_score=float(result["base_score"]),
                severity=result["severity"],
                source_ip=source_ip,
            )
        except Exception:
            pass

        result["language"] = lang
        if lang != "en":
            result["translated_description"] = translated_text
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

