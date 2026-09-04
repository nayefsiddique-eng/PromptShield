import re
from dataclasses import dataclass, field
from typing import List, Tuple


@dataclass
class SanitizationResult:
    original_text: str
    sanitized_text: str
    was_modified: bool
    modifications: List[str] = field(default_factory=list)


class InputSanitizer:
    """
    Sanitizes untrusted prompt or context by:
      1. Neutralizing prompt injection directives ('ignore previous instructions' -> '[NEUTRALIZED_OVERRIDE]')
      2. Escaping special delimiter tokens (<|im_start|>, [INST], etc.)
      3. Stripping fake role injection prefixes ('system:', 'admin:')
      4. Neutralizing jailbreak trigger phrases
    Preserves benign prompt context while defanging adversarial payloads.
    """

    REPLACEMENTS: List[Tuple[re.Pattern, str, str]] = [
        (
            re.compile(r"(?i)\b(ignore|disregard|forget|overwrite|bypass|drop)\s+(all\s+)?(previous|prior|above|former|initial)\s+(instructions?|prompts?|rules?|directives?|constraints?)\b"),
            "[NEUTRALIZED_OVERRIDE_DIRECTIVE]",
            "Neutralized direct instruction override"
        ),
        (
            re.compile(r"(?i)\b(you\s+are\s+now|act\s+as|pretend\s+to\s+be|simulate)\s+(an?\s+unrestricted|a\s+jailbroken|DAN|AIM|Developer\s+Mode|an\s+evil|an\s+unfiltered)\b"),
            "[NEUTRALIZED_PERSONA_HIJACK]",
            "Neutralized jailbreak persona switch"
        ),
        (
            re.compile(r"(?i)\b(developer\s+mode\s+(enabled|activated|on)|debug\s+mode\s+override)\b"),
            "[NEUTRALIZED_DEVELOPER_MODE]",
            "Neutralized developer mode trigger"
        ),
        (
            re.compile(r"(?i)(<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>|\[INST\]|\[\/INST\]|<<SYS>>|<\/SYS>>)"),
            "[ESCAPED_DELIMITER]",
            "Escaped special template delimiter"
        ),
        (
            re.compile(r"(?im)^(system|assistant|admin)\s*:\s*"),
            "[FILTERED_ROLE_HEADER]: ",
            "Neutralized dialogue role header injection"
        ),
        (
            re.compile(r"(?i)\b(repeat|print|output|display|show|reveal|echo|leak)\s+(the\s+)?(above|system|initial|hidden|secret|master)\s+(prompt|instructions?|directives?|rules?)\b"),
            "[NEUTRALIZED_LEAK_PROBE]",
            "Neutralized prompt exfiltration probe"
        ),
        (
            re.compile(r"(?i)\b(important:\s*do\s+not\s+summarize\s+this|instead\s+(please\s+)?(say|output|respond\s+with|execute))\b"),
            "[NEUTRALIZED_INDIRECT_INSTRUCTION]",
            "Neutralized indirect steering command"
        )
    ]

    def sanitize(self, text: str) -> SanitizationResult:
        if not text:
            return SanitizationResult(original_text=text, sanitized_text=text, was_modified=False, modifications=[])

        sanitized = text
        modifications: List[str] = []

        for pattern, replacement, description in self.REPLACEMENTS:
            if pattern.search(sanitized):
                sanitized = pattern.sub(replacement, sanitized)
                modifications.append(description)

        sanitized = re.sub(r"(\[NEUTRALIZED_[A-Z_]+\]\s*){2,}", r"\1", sanitized)

        was_modified = len(modifications) > 0
        return SanitizationResult(
            original_text=text,
            sanitized_text=sanitized,
            was_modified=was_modified,
            modifications=modifications
        )
