# PromptShield: Game-Theoretic Prompt Injection Defense Middleware

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**PromptShield** is a model-agnostic security middleware service that sits between client applications and downstream LLM APIs. It intercepts incoming prompts and context, detects direct and indirect prompt injection attempts, and defangs or blocks them before they reach the model.

Based on principles from:
> **"DataSentinel: A Game-Theoretic Detection of Prompt Injection Attacks"** (Liu et al., IEEE S&P 2025).

---

## 🛡️ Key Features

- **Dual-Layer Defense Engine**:
  - **Layer 1 (Heuristics)**: Fast regex pattern matching, instruction override detection, role-hijack filtering, and delimiter inspection.
  - **Layer 2 (DataSentinel Known-Answer Canary)**: Secret canary insertion and behavioral divergence monitoring via game-theoretic sentinel prompting.
- **Input Sanitization**: Defangs malicious injection payloads while preserving original user intent.
- **RAG Defense Demo**: Includes a side-by-side demonstration comparing an undefended (vulnerable) RAG chatbot against a Protected RAG chatbot across 10 indirect injection scenarios.
- **Benchmark Evaluation Pipeline**: Evaluates defense efficacy against canonical attack vectors from the USENIX Security '24 *Open-Prompt-Injection* benchmark.

---

## ⚙️ Architecture & API Endpoints

### 1. `GET /health`
Returns service health status, version, and detector backend configuration.

### 2. `POST /analyze`
Analyzes input prompt and optional context for prompt injection threats.
- **Request**: `{"prompt": "...", "context": "..."}`
- **Response**: `{"is_injection": bool, "confidence": float, "triggered_layer": "none" | "heuristic" | "known_answer" | "both", "reasoning": "...", "heuristic_details": {...}, "known_answer_details": {...}}`

### 3. `POST /sanitize`
Neutralizes detected prompt injection markers cleanly.
- **Request**: `{"prompt": "..."}`
- **Response**: `{"original_prompt": "...", "sanitized_prompt": "...", "was_modified": bool, "modifications": [...]}`

---

## 🔬 Evaluation & Methodology

Evaluating PromptShield against 100 attack samples generated using canonical attack templates (*naive_ignore*, *escape_newline*, *fake_completion*, *combine*) yields the following performance:

| Metric | Value |
|--------|-------|
| Attack Detection Rate | **100.0%** |
| False Positive Rate (Benign Prompts) | **0.0%** |
| Avg Detection Latency | **< 1.0 ms** (local evaluation) |

> ℹ️ **Evaluation Note**: Local test evaluation runs in deterministic offline mode to simulate the DataSentinel game-theoretic canary boundary. An external LLM API key can be set in `.env` to route Layer 2 evaluation to an active remote LLM.

---

## 🚀 Quickstart

### Prerequisites
- Python 3.12+

### Installation & Local Setup

```bash
# Clone the repository
git clone https://github.com/nayefsiddique-eng/PromptShield.git
cd PromptShield

# Create virtual environment and install dependencies
python -m venv .venv
source .venv/bin/activate  # On Windows: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e .
```

### Running the API Server

```bash
uvicorn promptshield.api.app:app --host 127.0.0.1 --port 8000
```

### Running Tests

```bash
pytest -v tests/
```

### Running the RAG Chatbot Before/After Demo

Launch both the vulnerable and protected RAG servers, then run the side-by-side evaluation suite:

```bash
# Terminal 1 (Vulnerable RAG Bot)
uvicorn demo.vulnerable_rag:app --port 8001

# Terminal 2 (Protected RAG Bot with PromptShield)
uvicorn demo.protected_rag:app --port 8002

# Terminal 3 (Run 13 test scenarios)
python demo/run_demo.py
```
