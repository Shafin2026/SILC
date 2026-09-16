import asyncio
import json
import httpx
import pytest
from src import ai_providers as ai
from src.api import sample


@pytest.mark.parametrize("provider,response", [
    ("ollama", {"message":{"content":"Evidence review"}}),
    ("gemini", {"candidates":[{"content":{"parts":[{"text":"Evidence review"}]}}]}),
    ("deepseek", {"choices":[{"message":{"content":"Evidence review"}}]}),
    ("openai", {"output":[{"type":"message","content":[{"type":"output_text","text":"Evidence review"}]}]}),
    ("anthropic", {"content":[{"type":"text","text":"Evidence review"}]}),
])
def test_provider_payload_and_parser(monkeypatch, provider, response):
    alert = sample()["alerts"].iloc[0].to_dict()
    explanation = ai.offline_explanations([alert])[0]
    structured = json.dumps({"summary": "Evidence review", "explanations": [explanation]})
    def inject(value):
        if isinstance(value, dict):
            return {k: inject(v) for k, v in value.items()}
        if isinstance(value, list):
            return [inject(v) for v in value]
        return structured if value == "Evidence review" else value
    response = inject(response)
    monkeypatch.setenv("ALLOW_CLOUD_AI", "true")
    monkeypatch.setenv(provider.upper()+"_API_KEY", "test-only-key")
    monkeypatch.setenv(provider.upper()+"_MODEL", "test-model")
    original_client = httpx.AsyncClient
    def respond(request):
        assert request.method == "POST"
        assert b"test-only-key" not in request.content
        assert b"untrusted" in request.content
        if provider == "gemini":
            assert "test-only-key" not in str(request.url)
        if provider == "openai":
            assert request.url.path == "/v1/responses"
        return httpx.Response(200, json=response)
    monkeypatch.setattr(ai.httpx, "AsyncClient", lambda **kwargs: original_client(
        transport=httpx.MockTransport(respond), **kwargs))
    result=asyncio.run(ai.summarize_alerts(sample()["alerts"].head(1).to_dict(orient="records"), provider))
    assert result["summary"] == "Evidence review"
    assert result["is_ai"]
    assert result["explanations"][0]["evidence_ids"] == alert["evidence_ids"][:10]


def test_error_does_not_leak_secret(monkeypatch):
    monkeypatch.setenv("ALLOW_CLOUD_AI", "true")
    monkeypatch.setenv("GEMINI_API_KEY", "secret-test-value")
    monkeypatch.setenv("GEMINI_MODEL", "test-model")
    original_client=httpx.AsyncClient
    monkeypatch.setattr(ai.httpx, "AsyncClient", lambda **kwargs: original_client(
        transport=httpx.MockTransport(lambda request: httpx.Response(401,json={"message":"secret-test-value"})), **kwargs))
    with pytest.raises(ai.AIProviderError) as error:
        asyncio.run(ai.summarize_alerts(sample()["alerts"].head(1).to_dict(orient="records"), "gemini"))
    assert "secret-test-value" not in str(error.value)
    assert "401" in str(error.value)


def test_cloud_disabled_even_with_key(monkeypatch):
    monkeypatch.setenv("ALLOW_CLOUD_AI", "false")
    with pytest.raises(ai.AIProviderError, match="disabled"):
        asyncio.run(ai.summarize_alerts([], "gemini"))


def test_ollama_cannot_use_remote_host(monkeypatch):
    monkeypatch.setenv("OLLAMA_BASE_URL", "https://attacker.example")
    with pytest.raises(ai.AIProviderError, match="local"):
        asyncio.run(ai.summarize_alerts([], "ollama"))
