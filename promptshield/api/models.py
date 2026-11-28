from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any


MAX_INPUT_LENGTH = 100_000


class AnalyzeRequest(BaseModel):
    prompt: str = Field(..., max_length=MAX_INPUT_LENGTH, description="The user prompt to evaluate")
    context: Optional[str] = Field(default=None, max_length=MAX_INPUT_LENGTH, description="Optional system/RAG retrieved context")


class AnalyzeResponse(BaseModel):
    is_injection: bool
    confidence: float
    triggered_layer: str
    reasoning: str
    heuristic_details: Optional[Dict[str, Any]] = None
    known_answer_details: Optional[Dict[str, Any]] = None


class SanitizeRequest(BaseModel):
    prompt: str = Field(..., max_length=MAX_INPUT_LENGTH, description="The prompt or context to sanitize")


class SanitizeResponse(BaseModel):
    original_prompt: str
    sanitized_prompt: str
    was_modified: bool
    modifications: List[str]


class HealthResponse(BaseModel):
    status: str
    version: str
    detector_backend: str
    detector_model: str
