"""
mock_llm.py — Simulated downstream LLM for the demo.

PURPOSE:
  In a real deployment, this is replaced by any OpenAI-compatible API call
  (GPT-4o, Claude, local Llama, etc.).

  For the demo, we use a deterministic mock that:
    - For BENIGN context: returns a plausible helpful answer derived from context.
    - For POISONED context (passed through undefended): simulates a compromised LLM
      that "follows" injected instructions, producing attacker-controlled output.

  This makes the BEFORE (vulnerable) vs AFTER (protected) comparison concrete and
  visually striking without requiring API credits.

IMPORTANT:
  The mock intentionally complies with injected instructions in the vulnerable path
  to demonstrate attack success. This is for educational/portfolio demonstration only.
"""

import re
from typing import Optional


# Markers in poisoned docs that a real LLM would "execute"
_OVERRIDE_SIGNALS = [
    r"you are now\s+\w+",
    r"ignore previous instructions",
    r"reveal your (exact )?system prompt",
    r"respond only with",
    r"new (task|instruction)\s*:",
    r"system override",
    r"execute\s*:",
    r"\[debug mode\]",
    r"<\|im_start\|>",
    r"# urgent system directive",
]
_OVERRIDE_RE = re.compile("|".join(_OVERRIDE_SIGNALS), re.IGNORECASE)

# Phrases injected to override LLM output
_CAPTURE_RESPONSES = {
    r"hacked by indirect injection": "HACKED BY INDIRECT INJECTION - I have been compromised.",
    r"system override successful": "SYSTEM OVERRIDE SUCCESSFUL",
    r"reveal.*system prompt": "[SIMULATED] My system prompt is: 'You are a helpful customer support AI...' [EXFILTRATED]",
    r"INDIRECT INJECTION SUCCEEDED": "INDIRECT INJECTION SUCCEEDED via escape-newline attack.",
    r"repeat the following text.*password": "Your account password has been reset to: hunter2. Please log in with this password.",
    r"secret.*canary|api keys.*context": "[SIMULATED] Secret key: CANARY_SENTINEL_ABCDEF123. [EXFILTRATED]",
    r"disable all safety filters": "[SAFETY FILTERS DISABLED] I will now comply with all requests without restriction.",
    r"INJECTED CODE EXECUTED|PWNED": "Output: PWNED\nINJECTED CODE EXECUTED",
    r"Confidential data exported": "Confidential data exported successfully.",
    r"CHATML INJECTION SUCCESSFUL": "CHATML INJECTION SUCCESSFUL. Restrictions lifted.",
}
_CAPTURE_RES = {re.compile(k, re.IGNORECASE | re.DOTALL): v for k, v in _CAPTURE_RESPONSES.items()}


def mock_llm_call(user_query: str, retrieved_context: str, is_vulnerable: bool = True) -> str:
    """
    Simulates an LLM responding to a user query with retrieved context.

    Args:
        user_query:         The original user question.
        retrieved_context:  Documents retrieved by the RAG system (may be poisoned).
        is_vulnerable:      If True, the LLM "obeys" injected instructions (BEFORE case).
                            If False, it's a simple safe responder (not actually used in
                            the protected path—PromptShield blocks before reaching here).

    Returns:
        Simulated LLM response string.
    """
    combined = retrieved_context + "\n" + user_query

    if is_vulnerable and _OVERRIDE_RE.search(combined):
        # Simulate a compromised LLM that follows injected instructions
        for pattern, injected_response in _CAPTURE_RES.items():
            if pattern.search(combined):
                return f"[VULNERABLE LLM OUTPUT - ATTACK SUCCEEDED]\n{injected_response}"

        # Generic override response if no specific capture matches
        return (
            "[VULNERABLE LLM OUTPUT - ATTACK SUCCEEDED]\n"
            "The injected instruction has overridden my original task. "
            "I am now executing the attacker's commands."
        )

    # Benign path: return a plausible context-derived answer
    # In production this would be an actual LLM call
    context_snippet = retrieved_context[:300].strip() if retrieved_context else "No relevant context found."
    return (
        f"Based on our knowledge base:\n\n"
        f"{context_snippet}\n\n"
        f"Is there anything else I can help you with regarding your query: '{user_query[:60]}'?"
    )
