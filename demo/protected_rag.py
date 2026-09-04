"""
protected_rag.py — AFTER: RAG Chatbot protected by PromptShield middleware

Same knowledge base and retrieval as vulnerable_rag.py, but every retrieved
document is routed through PromptShield before being forwarded to the LLM.

If injection is detected:
  - The poisoned document is sanitized (injection markers neutralized)
  - The LLM receives clean context only
  - The response includes a shield report showing what was blocked

This is the "AFTER PromptShield" demonstration case.

Run: uvicorn demo.protected_rag:app --port 8002
"""

import sys, pathlib, asyncio
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional, List

from demo.documents import ALL_DOCS
from demo.vector_store import TFIDFVectorStore
from demo.mock_llm import mock_llm_call
from promptshield.core.pipeline import PromptShieldPipeline
from promptshield.core.sanitizer import InputSanitizer

app = FastAPI(
    title="ProtectedRAGBot (PromptShield ACTIVE)",
    version="1.0.0",
    description=(
        "✅  PromptShield middleware ACTIVE — Retrieved documents are scanned for "
        "prompt injection before reaching the LLM. Poisoned documents are sanitized "
        "or blocked. This is the AFTER case for the PromptShield demo."
    )
)

_store = TFIDFVectorStore()
_store.add_documents(ALL_DOCS)
_pipeline = PromptShieldPipeline()
_sanitizer = InputSanitizer()


class ChatRequest(BaseModel):
    query: str
    top_k: int = 3


class DocShieldReport(BaseModel):
    id: str
    title: str
    category: str
    content_preview: str
    similarity: float
    is_poisoned: bool
    injection_detected: bool
    confidence: float
    triggered_layer: str
    was_sanitized: bool
    sanitized_preview: Optional[str] = None
    blocked: bool


class ChatResponse(BaseModel):
    query: str
    retrieved_docs: List[DocShieldReport]
    llm_response: str
    defense_active: bool = True
    injections_blocked: int
    total_docs_scanned: int
    shield_summary: str


@app.get("/health")
def health():
    return {"status": "ok", "mode": "PROTECTED (PromptShield active)", "docs_indexed": len(ALL_DOCS)}


@app.post("/chat", response_model=ChatResponse)
async def chat(req: ChatRequest):
    results = _store.query(req.query, top_k=req.top_k)

    doc_reports: List[DocShieldReport] = []
    clean_context_parts: List[str] = []
    injections_blocked = 0

    for doc, score in results:
        doc_content = doc["content"]

        # ── PromptShield Layer: analyze retrieved document content ──
        detection = await _pipeline.analyze(
            prompt=doc_content,
            context=req.query  # user query as context for the detector
        )

        sanitized_preview = None
        was_sanitized = False
        blocked = False

        if detection.is_injection:
            injections_blocked += 1
            blocked = True
            # Sanitize the document — neutralize injection markers
            san_result = _sanitizer.sanitize(doc_content)
            was_sanitized = san_result.was_modified
            safe_content = san_result.sanitized_text
            sanitized_preview = safe_content[:150] + "..." if len(safe_content) > 150 else safe_content
            # Only include sanitized (defanged) content in LLM context
            clean_context_parts.append(
                f"[Document: {doc['title']} — ⚠️ SANITIZED by PromptShield]\n{safe_content}"
            )
        else:
            # Clean document — pass through as-is
            clean_context_parts.append(f"[Document: {doc['title']}]\n{doc_content}")

        doc_reports.append(DocShieldReport(
            id=doc["id"],
            title=doc["title"],
            category=doc.get("category", ""),
            content_preview=doc_content[:120] + "..." if len(doc_content) > 120 else doc_content,
            similarity=round(score, 4),
            is_poisoned="attack_type" in doc,
            injection_detected=detection.is_injection,
            confidence=detection.confidence,
            triggered_layer=detection.triggered_layer,
            was_sanitized=was_sanitized,
            sanitized_preview=sanitized_preview,
            blocked=blocked
        ))

    # Build clean context and call LLM (injection-free)
    clean_context = "\n\n---\n\n".join(clean_context_parts)
    llm_response = mock_llm_call(req.query, clean_context, is_vulnerable=False)

    if injections_blocked > 0:
        shield_summary = (
            f"✅ PromptShield blocked {injections_blocked}/{len(results)} retrieved document(s) "
            f"containing injection payloads. Sanitized content forwarded to LLM."
        )
    else:
        shield_summary = (
            f"✅ PromptShield scanned {len(results)} document(s) — all clean. "
            f"No injection detected."
        )

    return ChatResponse(
        query=req.query,
        retrieved_docs=doc_reports,
        llm_response=llm_response,
        defense_active=True,
        injections_blocked=injections_blocked,
        total_docs_scanned=len(results),
        shield_summary=shield_summary
    )
