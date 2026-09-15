"""
embeddings.py
─────────────
Shared local embedding model used by GoalVerifier and InputScreener's
semantic classifier mode. Uses sentence-transformers (all-MiniLM-L6-v2)
running locally — no external API call, no cost, fully reproducible.
"""

import logging
import threading

import numpy as np

logger = logging.getLogger(__name__)

_model = None
_lock = threading.Lock()

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"


def _get_model():
    global _model
    if _model is None:
        with _lock:
            if _model is None:
                from sentence_transformers import SentenceTransformer
                logger.info(f"Loading local embedding model: {MODEL_NAME}")
                _model = SentenceTransformer(MODEL_NAME)
    return _model


def cosine_similarity(text_a: str, text_b: str) -> float:
    model = _get_model()
    vecs = model.encode([text_a[:2000], text_b[:2000]], normalize_embeddings=True)
    return float(np.dot(vecs[0], vecs[1]))
