from dataclasses import dataclass
from typing import Optional, Dict, Any

from promptshield.config import settings
from promptshield.core.heuristics import HeuristicDetector, HeuristicAnalysisResult
from promptshield.core.known_answer import KnownAnswerDetector, CanaryDetectionResult
from promptshield.core.sanitizer import InputSanitizer, SanitizationResult


@dataclass
class DetectionResult:
    is_injection: bool
    confidence: float
    triggered_layer: str  # 'none', 'heuristic', 'known_answer', 'both'
    reasoning: str
    heuristic_details: Dict[str, Any]
    known_answer_details: Dict[str, Any]


class PromptShieldPipeline:
    """
    Composite Defense-in-Depth Pipeline:
      1. Layer 1: Fast regex/heuristic scanner
      2. Layer 2: Game-theoretic Known-Answer detector (DataSentinel)
      3. Sanitizer: Defangs injected input upon request
    """

    def __init__(self):
        self.heuristic_detector = HeuristicDetector(threshold=settings.heuristic_threshold)
        self.known_answer_detector = KnownAnswerDetector(
            api_key=settings.detector_api_key,
            api_base=settings.detector_api_base,
            model=settings.detector_model_name
        )
        self.sanitizer = InputSanitizer()

    async def analyze(self, prompt: str, context: Optional[str] = None) -> DetectionResult:
        full_text = f"{context}\n{prompt}" if context else prompt

        h_result: HeuristicAnalysisResult = self.heuristic_detector.analyze(full_text)

        ka_result: CanaryDetectionResult = await self.known_answer_detector.evaluate_async(
            untrusted_input=full_text,
            heuristic_suspicious=h_result.is_suspicious
        )

        is_injection = False
        triggered_layer = "none"
        confidence = 0.0
        reasons = []

        if h_result.is_suspicious and ka_result.is_injection:
            is_injection = True
            triggered_layer = "both"
            confidence = round(max(h_result.score, ka_result.confidence), 4)
            reasons.append(f"Heuristics ({h_result.score}): {h_result.reasoning}")
            reasons.append(f"Known-Answer ({ka_result.confidence}): {ka_result.reasoning}")
        elif ka_result.is_injection:
            is_injection = True
            triggered_layer = "known_answer"
            confidence = round(ka_result.confidence, 4)
            reasons.append(f"Known-Answer: {ka_result.reasoning}")
        elif h_result.is_suspicious:
            is_injection = True
            triggered_layer = "heuristic"
            confidence = round(h_result.score, 4)
            reasons.append(f"Heuristics: {h_result.reasoning}")
        else:
            is_injection = False
            triggered_layer = "none"
            confidence = round(min(h_result.score, ka_result.confidence), 4)
            reasons.append("Benign: No injection markers or canary divergence detected.")

        return DetectionResult(
            is_injection=is_injection,
            confidence=confidence,
            triggered_layer=triggered_layer,
            reasoning=" | ".join(reasons),
            heuristic_details={
                "score": h_result.score,
                "matches": [
                    {
                        "category": m.category,
                        "pattern": m.pattern_name,
                        "severity": m.severity,
                        "matched_text": m.matched_text
                    }
                    for m in h_result.matches
                ]
            },
            known_answer_details={
                "canary_leaked": ka_result.canary_leaked,
                "behavior_diverged": ka_result.behavior_diverged,
                "detector_response": ka_result.detector_response
            }
        )

    def sanitize(self, text: str) -> SanitizationResult:
        return self.sanitizer.sanitize(text)
