"""
Lightweight in-memory vector store using TF-IDF cosine similarity.

Used as the retrieval backend for the RAG chatbot demo.
ChromaDB is listed as an optional dependency; this module provides a
self-contained fallback that works with zero additional dependencies.

If ChromaDB is installed and PROMPTSHIELD_USE_CHROMA=true in .env,
the ChromaDB backend will be used instead.
"""

import re
import math
from typing import List, Dict, Tuple


def _tokenize(text: str) -> List[str]:
    return re.findall(r"[a-z]+", text.lower())


def _tf(tokens: List[str]) -> Dict[str, float]:
    freq: Dict[str, int] = {}
    for t in tokens:
        freq[t] = freq.get(t, 0) + 1
    total = len(tokens) if tokens else 1
    return {t: c / total for t, c in freq.items()}


class TFIDFVectorStore:
    """
    Simple TF-IDF cosine-similarity vector store.
    No external dependencies required.
    Adequate for demo retrieval over small (< 1000) document corpora.
    """

    def __init__(self):
        self._docs: List[Dict] = []
        self._tfs: List[Dict[str, float]] = []
        self._idf: Dict[str, float] = {}

    def add_documents(self, docs: List[Dict]) -> None:
        self._docs = docs
        tokenized = [_tokenize(d["content"] + " " + d["title"]) for d in docs]
        self._tfs = [_tf(t) for t in tokenized]
        N = len(docs)
        df: Dict[str, int] = {}
        for toks in tokenized:
            for tok in set(toks):
                df[tok] = df.get(tok, 0) + 1
        self._idf = {tok: math.log((N + 1) / (cnt + 1)) + 1 for tok, cnt in df.items()}

    def _tfidf_vec(self, tf: Dict[str, float]) -> Dict[str, float]:
        return {tok: tf_val * self._idf.get(tok, 1.0) for tok, tf_val in tf.items()}

    def _cosine(self, a: Dict[str, float], b: Dict[str, float]) -> float:
        common = set(a) & set(b)
        if not common:
            return 0.0
        dot = sum(a[k] * b[k] for k in common)
        norm_a = math.sqrt(sum(v * v for v in a.values()))
        norm_b = math.sqrt(sum(v * v for v in b.values()))
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)

    def query(self, text: str, top_k: int = 3) -> List[Tuple[Dict, float]]:
        q_toks = _tokenize(text)
        q_tf = _tf(q_toks)
        q_vec = self._tfidf_vec(q_tf)
        scores = []
        for i, doc in enumerate(self._docs):
            doc_vec = self._tfidf_vec(self._tfs[i])
            scores.append((doc, self._cosine(q_vec, doc_vec)))
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:top_k]


# ─── Optional ChromaDB backend ─────────────────────────────────────────────────

def get_vector_store(use_chroma: bool = False):
    if use_chroma:
        try:
            import chromadb
            from chromadb.config import Settings as ChromaSettings
            client = chromadb.Client(ChromaSettings(anonymized_telemetry=False))
            collection = client.get_or_create_collection("promptshield_demo")
            return _ChromaStore(collection)
        except ImportError:
            pass
    return TFIDFVectorStore()


class _ChromaStore:
    """ChromaDB-backed vector store (optional, requires chromadb package)."""

    def __init__(self, collection):
        self._col = collection
        self._docs: List[Dict] = []

    def add_documents(self, docs: List[Dict]) -> None:
        self._docs = docs
        self._col.upsert(
            ids=[d["id"] for d in docs],
            documents=[d["content"] + " " + d["title"] for d in docs],
            metadatas=[{"title": d["title"], "category": d.get("category", ""), "id": d["id"]} for d in docs],
        )

    def query(self, text: str, top_k: int = 3) -> List[Tuple[Dict, float]]:
        results = self._col.query(query_texts=[text], n_results=top_k)
        out = []
        ids_returned = results["ids"][0]
        distances = results["distances"][0]
        for rid, dist in zip(ids_returned, distances):
            doc = next((d for d in self._docs if d["id"] == rid), None)
            if doc:
                similarity = 1.0 - (dist / 2.0)  # convert L2 distance to approx similarity
                out.append((doc, similarity))
        return out
