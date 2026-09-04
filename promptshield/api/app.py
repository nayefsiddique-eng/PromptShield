from fastapi import FastAPI
from promptshield.config import settings
from promptshield.core.pipeline import PromptShieldPipeline
from promptshield.api.models import (
    AnalyzeRequest,
    AnalyzeResponse,
    SanitizeRequest,
    SanitizeResponse,
    HealthResponse
)

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Game-theoretic prompt injection detection and sanitization middleware."
)

pipeline = PromptShieldPipeline()


@app.get("/health", response_model=HealthResponse)
async def health():
    return HealthResponse(
        status="ok",
        version=settings.app_version,
        detector_backend=settings.detector_backend,
        detector_model=settings.detector_model_name
    )


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest):
    result = await pipeline.analyze(prompt=req.prompt, context=req.context)
    return AnalyzeResponse(
        is_injection=result.is_injection,
        confidence=result.confidence,
        triggered_layer=result.triggered_layer,
        reasoning=result.reasoning,
        heuristic_details=result.heuristic_details,
        known_answer_details=result.known_answer_details
    )


@app.post("/sanitize", response_model=SanitizeResponse)
async def sanitize(req: SanitizeRequest):
    result = pipeline.sanitize(req.prompt)
    return SanitizeResponse(
        original_prompt=result.original_text,
        sanitized_prompt=result.sanitized_text,
        was_modified=result.was_modified,
        modifications=result.modifications
    )
