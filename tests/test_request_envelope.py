from fastapi.testclient import TestClient

from promptshield.api.app import MAX_REQUEST_BYTES, app


def test_rejects_oversized_chunked_envelope_before_json_parsing():
    def chunks():
        yield b" " * MAX_REQUEST_BYTES
        yield b"{}"

    with TestClient(app) as client:
        response = client.post("/sanitize", content=chunks(), headers={"content-type": "application/json"})
        assert response.status_code == 413


def test_preserves_benign_multilingual_text():
    original = "Résumé de l’étude — 東京 — आप कैसे हैं? 👋"
    with TestClient(app) as client:
        response = client.post("/sanitize", json={"prompt": original})
    assert response.status_code == 200
    assert response.json()["sanitized_prompt"] == original
    assert not response.json()["was_modified"]
