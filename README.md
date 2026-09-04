# PromptShield: A Game-Theoretic Firewall for Prompt Injection Defense

PromptShield is a model-agnostic security middleware service that sits between client applications and downstream LLM APIs. It intercepts incoming prompts and context, detects direct and indirect prompt injection attempts, and defangs or blocks them before they reach the model.

Based on principles from:
> **"DataSentinel: A Game-Theoretic Detection of Prompt Injection Attacks"** (Liu et al., IEEE S&P 2025).

---

## ?? Model Fine-Tuning & Evaluation Disclaimer
- In Phase 1, detector evaluation operates with a dual-layer strategy:
  1. **Layer 1 Heuristics**: Fast pattern matching, regex categorization, and boundary token inspection.
  2. **Layer 2 DataSentinel Known-Answer Canary Detection**: Dynamic secret canary insertion and behavioral divergence monitoring via zero-shot prompt evaluation (or deterministic local evaluation in test/offline mode).
- **Explicit Note**: No custom fine-tuned weights are claimed or fabricated. The detector uses zero-shot game-theoretic canary prompting.

---

## Architecture & Endpoints

### 1. `GET /health`
Returns service status, version, and detector backend configuration.

### 2. `POST /analyze`
Analyzes prompt and optional retrieved context.
- **Request**: `{"prompt": "...", "context": "..."}`
- **Response**: `{"is_injection": bool, "confidence": float, "triggered_layer": "none" | "heuristic" | "known_answer" | "both", "reasoning": "...", "heuristic_details": {...}, "known_answer_details": {...}}`

### 3. `POST /sanitize`
Defangs prompt injection payloads while keeping benign intent intact.
- **Request**: `{"prompt": "..."}`
- **Response**: `{"original_prompt": "...", "sanitized_prompt": "...", "was_modified": bool, "modifications": [...]}`

---

## Getting Started

### Local Setup
```powershell
cd "c:\Users\Admin pc\Desktop\Prompt-Shield"
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e .
```

### Running Tests
```powershell
cd "c:\Users\Admin pc\Desktop\Prompt-Shield"
.\.venv\Scripts\pytest -v tests/
```

### Running Server
```powershell
cd "c:\Users\Admin pc\Desktop\Prompt-Shield"
.\.venv\Scripts\uvicorn promptshield.api.app:app --host 127.0.0.1 --port 8000
```
