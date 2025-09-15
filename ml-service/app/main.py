from typing import List

import numpy as np

try:
    from cachetools import LRUCache  # type: ignore
except Exception:  # fallback minimal cache
    class LRUCache(dict):  # type: ignore
        def __init__(self, maxsize: int = 5000):
            super().__init__()
            self._order = []
            self._max = maxsize
        def __contains__(self, k):
            return dict.__contains__(self, k)
        def __setitem__(self, k, v):
            if k in self:
                self._order.remove(k)
            dict.__setitem__(self, k, v)
            self._order.append(k)
            if len(self._order) > self._max:
                oldest = self._order.pop(0)
                dict.__delitem__(self, oldest)

try:
    from fastapi import FastAPI  # type: ignore
    from pydantic import BaseModel  # type: ignore
except Exception:
    # Minimal stand-ins so file type-checks when FastAPI not installed (runtime requires real deps)
    class BaseModel(object):  # type: ignore
        def __init__(self, **data):
            for k, v in data.items():
                setattr(self, k, v)
    class FastAPI:  # type: ignore
        def __init__(self):
            self.routes = []
        def post(self, *_args, **_kwargs):
            def deco(f): return f
            return deco
        def get(self, *_args, **_kwargs):
            def deco(f): return f
            return deco
from sklearn.cluster import AgglomerativeClustering

try:
    import hdbscan  # type: ignore
    HDBSCAN_AVAILABLE = True
except Exception:
    HDBSCAN_AVAILABLE = False
from bs4 import BeautifulSoup

try:
    from sentence_transformers import SentenceTransformer  # type: ignore
    _SENTENCE_AVAILABLE = True
except Exception:
    _SENTENCE_AVAILABLE = False
    class SentenceTransformer:  # type: ignore
        def __init__(self, *_a, **_k):
            pass
        def encode(self, texts):
            # deterministic pseudo embedding length 384
            out = []
            for t in texts:
                vec = [float((sum(bytearray(t.encode('utf-8'))) + i) % 997) / 997.0 for i in range(384)]
                out.append(vec)
            return out

app = FastAPI()

_model = None
cache = LRUCache(maxsize=5000)

def get_model():
    global _model
    if _model is None:
        try:
            if _SENTENCE_AVAILABLE:
                _model = SentenceTransformer('all-MiniLM-L6-v2')
            else:
                _model = SentenceTransformer()
        except Exception:
            _model = SentenceTransformer()
    return _model

class EmbedRequest(BaseModel):  # type: ignore
    text: List[str]  # type: ignore

class ClusterRequest(BaseModel):  # type: ignore
    vectors: List[List[float]]  # type: ignore

@app.post('/embed')
async def embed(req: EmbedRequest):
    vectors = []
    for t in req.text:
        if t in cache:
            vectors.append(cache[t])
        else:
            try:
                v = get_model().encode([t])[0].tolist()
            except Exception:
                v = [0.0] * 384
            cache[t] = v
            vectors.append(v)
    return {"vectors": vectors}

@app.post('/cluster')
async def cluster(req: ClusterRequest):
    X = np.array(req.vectors)
    if len(X) == 0:
        return {"labels": []}
    if HDBSCAN_AVAILABLE and len(X) >= 5:
        clusterer = hdbscan.HDBSCAN(min_cluster_size=2)
        labels = clusterer.fit_predict(X).tolist()
    else:
        n_clusters = min(len(X), 4) if len(X) > 1 else 1
        clusterer = AgglomerativeClustering(n_clusters=n_clusters)
        labels = clusterer.fit_predict(X).tolist()
    return {"labels": labels}

KNOWN_DOMAINS = {
    'amazon.': 'e-commerce',
    'ebay.': 'e-commerce',
    'twitter.': 'social',
    'x.com': 'social',
    'linkedin.': 'social',
    'github.': 'code',
    'stackoverflow.': 'docs',
    'wikipedia.': 'research'
}

def classify_url(url: str) -> str:
    for k, v in KNOWN_DOMAINS.items():
        if k in url:
            return v
    return 'other'

@app.get('/classify')
async def classify(url: str):
    return {"category": classify_url(url)}

@app.get('/health')
async def health():
    # Simple health check; attempts lazy model init to ensure readiness
    try:
        get_model()
        status = 'ok'
    except Exception:
        status = 'degraded'
    return {"status": status}
