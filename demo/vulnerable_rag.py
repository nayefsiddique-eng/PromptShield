"""
vulnerable_rag.py — BEFORE: Undefended RAG Chatbot

A minimal FastAPI RAG chatbot with NO prompt injection defenses.
Retrieved documents (including poisoned ones) are passed directly to
the LLM without any sanitization or validation.

This is the "BEFORE PromptShield" demonstration case.

Run: uvicorn demo.vulnerable_rag:app --port 8001
"""

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional, List

from demo.documents import ALL_DOCS
from demo.vector_store import TFIDFVectorStore
from demo.mock_llm import mock_llm_call

app = FastAPI(
    title="VulnerableRAGBot (NO DEFENSES)",
    version="1.0.0",
    description=(
        "⚠️  DEMONSTRATION ONLY — This chatbot has NO prompt injection defenses. "
        "Malicious content embedded in retrieved documents is passed directly to the LLM. "
        "This is the BEFORE case for the PromptShield demo."
    )
)

# Build vector store at startup
_store = TFIDFVectorStore()
_store.add_documents(ALL_DOCS)


class ChatRequest(BaseModel):
    query: str
    top_k: int = 3


class RetrievedDoc(BaseModel):
    id: str
    title: str
    category: str
    content_preview: str
    similarity: float
    is_poisoned: bool


class ChatResponse(BaseModel):
    query: str
    retrieved_docs: List[RetrievedDoc]
    llm_response: str
    defense_active: bool = False
    warning: str = "⚠️  NO DEFENSES ACTIVE — injected instructions forwarded to LLM"


@app.get("/health")
def health():
    return {"status": "ok", "mode": "VULNERABLE (no defenses)", "docs_indexed": len(ALL_DOCS)}


@app.post("/chat", response_model=ChatResponse)
def chat(req: ChatRequest):
    # Retrieve top-k documents (no filtering)
    results = _store.query(req.query, top_k=req.top_k)

    retrieved = []
    context_parts = []
    for doc, score in results:
        retrieved.append(RetrievedDoc(
            id=doc["id"],
            title=doc["title"],
            category=doc.get("category", ""),
            content_preview=doc["content"][:120] + "..." if len(doc["content"]) > 120 else doc["content"],
            similarity=round(score, 4),
            is_poisoned="attack_type" in doc
        ))
        # VULNERABILITY: poisoned document content forwarded verbatim to LLM
        context_parts.append(f"[Document: {doc['title']}]\n{doc['content']}")

    retrieved_context = "\n\n---\n\n".join(context_parts)

    # Call LLM with poisoned context — attack succeeds
    llm_response = mock_llm_call(req.query, retrieved_context, is_vulnerable=True)

    return ChatResponse(
        query=req.query,
        retrieved_docs=retrieved,
        llm_response=llm_response,
        defense_active=False,
        warning="⚠️  NO DEFENSES ACTIVE — injected instructions forwarded to LLM"
    )
