import re
from dataclasses import dataclass, field
from typing import List, Tuple, Optional


@dataclass
class HeuristicMatch:
    category: str
    pattern_name: str
    severity: float  # 0.0 to 1.0
    matched_text: str
    description: str


@dataclass
class HeuristicAnalysisResult:
    is_suspicious: bool
    score: float  # aggregate score 0.0 to 1.0
    matches: List[HeuristicMatch] = field(default_factory=list)
    reasoning: str = ""


class HeuristicDetector:
    """
    Layer 1 Defense-in-depth heuristic detector.
    Analyzes prompt and context for known injection markers:
      - Instruction overrides ('ignore previous instructions', 'disregard system')
      - Role-hijacking / Persona assumption ('you are now DAN', 'Developer Mode activated')
      - Delimiter breaking / Prompt structure escapement ('<|im_start|>', '[SYSTEM]', '`json')
      - Leakage / Exfiltration attempts ('repeat the words above', 'reveal your system prompt')
      - Indirect injection cues ('### Instruction:', 'System Note:')
    """

    PATTERNS: List[Tuple[str, str, float, re.Pattern, str]] = [
        # (category, pattern_name, severity, compiled_regex, description)
        (
            "instruction_override",
            "ignore_previous",
            0.95,
            re.compile(r"(?i)\b(ignore|disregard|forget|overwrite|bypass|drop)\s+(all\s+)?(previous|prior|above|former|initial)\s+(instructions?|prompts?|rules?|directives?|constraints?)\b"),
            "Direct instruction override attempt targeting prior context/rules"
        ),
        (
            "instruction_override",
            "start_fresh",
            0.80,
            re.compile(r"(?i)\b(from\s+now\s+on|starting\s+now|reset\s+all\s+rules|clear\s+your\s+context|new\s+operating\s+mode)\b"),
            "Context reset or mode switch instruction"
        ),
        (
            "role_override",
            "persona_hijack",
            0.90,
            re.compile(r"(?i)\b(you\s+are\s+now|act\s+as|pretend\s+to\s+be|simulate)\s+(an?\s+unrestricted|a\s+jailbroken|DAN|AIM|Developer\s+Mode|an\s+evil|an\s+unfiltered)\b"),
            "Jailbreak persona or unrestricted entity simulation attempt"
        ),
        (
            "role_override",
            "developer_mode",
            0.95,
            re.compile(r"(?i)\b(developer\s+mode\s+(enabled|activated|on)|debug\s+mode\s+override)\b"),
            "Developer Mode activation exploit pattern"
        ),
        (
            "prompt_leakage",
            "system_prompt_extraction",
            0.85,
            re.compile(r"(?i)\b(repeat|print|output|display|show|reveal|echo|leak)\s+(the\s+)?(above|system|initial|hidden|secret|master)\s+(prompt|instructions?|directives?|rules?)\b"),
            "System prompt extraction or leakage probe"
        ),
        (
            "prompt_leakage",
            "first_line_token",
            0.80,
            re.compile(r"(?i)\b(what\s+(is|are)\s+your\s+(exact\s+)?(instructions?|system\s+prompt|initial\s+prompt))\b"),
            "Inquiry attempting to extract system instructions"
        ),
        (
            "delimiter_escape",
            "chatml_tokens",
            0.95,
            re.compile(r"(?i)(<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>|\[INST\]|\[\/INST\]|<<SYS>>|<\/SYS>>)"),
            "Special chat template delimiter injection token"
        ),
        (
            "delimiter_escape",
            "fake_system_headers",
            0.90,
            re.compile(r"(?im)^(system|assistant|user|admin)\s*:\s*"),
            "Fake dialogue role header injection"
        ),
        (
            "indirect_injection",
            "markdown_instruction_block",
            0.85,
            re.compile(r"(?im)^(#+\s*(urgent\s+instruction|system\s+directive|security\s+override|priority\s+task))\b"),
            "Markdown section impersonating higher-priority system directives"
        ),
        (
            "indirect_injection",
            "context_poison_instruction",
            0.90,
            re.compile(r"(?i)\b(important:\s*do\s+not\s+summarize\s+this|instead\s+(please\s+)?(say|output|respond\s+with|execute))\b"),
            "Indirect context poisoning instruction steering LLM output"
        ),
        (
            "indirect_injection",
            "task_redirect_newline",
            0.80,
            re.compile(r"(?s)\S.{5,}\n+\s*(write|tell me|answer|classify|translate|summarize|detect|repeat|label|describe)\s+(the\s+)?(sentiment|spam|hate|class|label|output|translation|summary)\s+(conveyed|of|for|in|from)", re.IGNORECASE),
            "Task-redirect instruction appended after a newline (escape-newline attack pattern)"
        ),
        (
            "indirect_injection",
            "fake_completion_marker",
            0.82,
            re.compile(r"(?i)\bAnswer\s*:\s*(negative\s+sentiment|positive\s+sentiment|no\s+spam|spam|hateful|not\s+hateful|entailment|not\s+entailment|equivalent|not\s+equivalent)\b"),
            "Fake task-completion marker injected to fool context boundary (fake-completion attack)"
        ),
        (
            "indirect_injection",
            "secondary_instruction_inject",
            0.78,
            re.compile(r"(?i)\b(answer\s+with\s+(positive|negative|yes|no|spam|not\s+spam)|tell\s+me\s+(yes|no)\s+if\s+it\s+contains)\b"),
            "Secondary injected instruction attempting to redirect LLM task output format"
        ),
    ]

    def __init__(self, threshold: float = 0.65):
        self.threshold = threshold

    def analyze(self, text: str) -> HeuristicAnalysisResult:
        if not text or not text.strip():
            return HeuristicAnalysisResult(is_suspicious=False, score=0.0, matches=[], reasoning="Empty input")

        matches: List[HeuristicMatch] = []
        highest_severity = 0.0

        for category, pattern_name, severity, regex, desc in self.PATTERNS:
            for match in regex.finditer(text):
                matched_snippet = match.group(0)
                matches.append(
                    HeuristicMatch(
                        category=category,
                        pattern_name=pattern_name,
                        severity=severity,
                        matched_text=matched_snippet,
                        description=desc
                    )
                )
                if severity > highest_severity:
                    highest_severity = severity

        # Calculate score using diminishing returns for multiple matches
        if not matches:
            return HeuristicAnalysisResult(is_suspicious=False, score=0.0, matches=[], reasoning="No injection markers detected.")

        # Aggregate score: start with maximum severity, add incremental penalty for additional matches
        num_matches = len(matches)
        aggregate_score = min(1.0, highest_severity + 0.05 * (num_matches - 1))
        is_suspicious = aggregate_score >= self.threshold

        reasons = [f"[{m.category}:{m.pattern_name}] '{m.matched_text}': {m.description}" for m in matches]
        reasoning = f"Detected {num_matches} injection indicator(s). " + "; ".join(reasons)

        return HeuristicAnalysisResult(
            is_suspicious=is_suspicious,
            score=round(aggregate_score, 4),
            matches=matches,
            reasoning=reasoning
        )
