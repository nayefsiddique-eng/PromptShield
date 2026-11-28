# PromptShield: Game-Theoretic Prompt Injection Defense Middleware

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg)](https://fastapi.tiangolo.com/)

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

## Evaluation

Hosted CI runs deterministic unit and integration fixtures on Ubuntu
and Windows. These fixtures cover detection, sanitization, and request
bounds. They do not estimate accuracy, false-positive rates, or latency
for a representative workload or an external model.

Run the core API with `requirements.txt`. Keep the optional retrieval
demo and its separate dependencies on a local or disposable test
machine.

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

### API request limits

The `/analyze` and `/sanitize` endpoints accept up to 100,000 characters per
prompt or context field. For network-facing deployments, set a request-body
size limit at the reverse proxy as well.

### Optional retrieval demo

Install `requirements-demo.txt` to run the companion retrieval demo and its
full test suite. The API requirements omit ChromaDB. Keep the companion demo on
loopback while its dependency advisories are open.

The HTTP request envelope is capped at 3 MiB before JSON parsing. Field
limits still apply independently. The deterministic test suite demonstrates
specific handling of known patterns and benign multilingual text. These checks
do not establish false-positive or false-negative rates for untested data or
external models. PromptShield is one layer in a defense that also requires
privilege boundaries around model tools and sensitive data.
