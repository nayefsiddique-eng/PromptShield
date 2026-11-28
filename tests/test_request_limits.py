from fastapi.testclient import TestClient
import pytest

from promptshield.api.app import app
from promptshield.api.models import MAX_INPUT_LENGTH


@pytest.mark.parametrize(
    ("route", "field"), [("/analyze", "prompt"), ("/analyze", "context"), ("/sanitize", "prompt")]
)
def test_rejects_oversized_input(route, field):
    payload = {"prompt": "Summarize the document.", field: "x" * (MAX_INPUT_LENGTH + 1)}
    with TestClient(app) as client:
        assert client.post(route, json=payload).status_code == 422


def test_sanitize_accepts_exact_limit():
    with TestClient(app) as client:
        response = client.post("/sanitize", json={"prompt": "x" * MAX_INPUT_LENGTH})
    assert response.status_code == 200
