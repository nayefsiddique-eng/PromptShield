from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """PromptShield configuration settings."""
    app_name: str = "PromptShield"
    app_version: str = "0.1.0"
    debug: bool = False

    # Detection threshold for heuristic confidence (0.0 to 1.0)
    heuristic_threshold: float = 0.65

    # Known-answer detection settings (DataSentinel approach)
    # NOTE: In Phase 1, we use zero-shot / few-shot prompting on a detector model
    # (or local deterministic model mock when API keys are unset).
    # No fine-tuning was performed in this deployment stage; this is explicitly documented.
    detector_backend: str = "heuristic_and_canary"  # "heuristic_and_canary", "openai", or "ollama"
    detector_api_base: Optional[str] = None
    detector_api_key: Optional[str] = None
    detector_model_name: str = "gpt-4o-mini"
    detector_temperature: float = 0.0

    class Config:
        env_prefix = "PROMPTSHIELD_"
        env_file = ".env"


settings = Settings()
