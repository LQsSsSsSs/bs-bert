from __future__ import annotations

from threading import Lock

from predictor_service import CVSSPredictor

_predictor: CVSSPredictor | None = None
_predictor_lock = Lock()


def get_predictor() -> CVSSPredictor:
    global _predictor
    if _predictor is None:
        with _predictor_lock:
            if _predictor is None:
                _predictor = CVSSPredictor()
    return _predictor
