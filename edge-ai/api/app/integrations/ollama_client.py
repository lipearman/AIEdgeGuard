"""Thin client for the existing host Ollama service.

The llm-server runs Ollama as a systemd service on port 11434. Containers
reach it via host.docker.internal (see extra_hosts in docker-compose.yml).
"""

import asyncio
import re
from datetime import UTC, datetime, timedelta

import httpx

from app.config import settings

ANALYSIS_TIMEOUT = 180.0  # 9B models on RTX 2060 can be slow on long prompts
_model_catalog = {}
_model_catalog_at = None
_model_catalog_lock = asyncio.Lock()


async def model_metadata(model):
    """Observed tag digest, explicitly not an attestation of the running model."""
    global _model_catalog, _model_catalog_at
    now = datetime.now(UTC)
    if _model_catalog_at is None or now - _model_catalog_at > timedelta(seconds=60):
        async with _model_catalog_lock:
            if _model_catalog_at is None or now - _model_catalog_at > timedelta(
                seconds=60
            ):
                try:
                    async with (
                        asyncio.timeout(4),
                        httpx.AsyncClient(timeout=3) as client,
                    ):
                        response = await client.get(settings.ollama_url + "/api/tags")
                        response.raise_for_status()
                        models = response.json()["models"]
                    if not isinstance(models, list):
                        raise TypeError("Invalid model catalog")
                    _model_catalog = {
                        m["name"]: m.get("digest")
                        for m in models
                        if isinstance(m, dict)
                        and isinstance(m.get("name"), str)
                        and re.fullmatch(
                            r"(?:sha256:)?[a-fA-F0-9]{64}", str(m.get("digest") or "")
                        )
                    }
                    _model_catalog_at = datetime.now(UTC)
                except (httpx.HTTPError, TimeoutError, ValueError, KeyError, TypeError):
                    return {
                        "observed_model_digest": None,
                        "digest_scope": "Ollama tag metadata unavailable",
                    }
    return {
        "observed_model_digest": _model_catalog.get(model)
        or _model_catalog.get(model + ":latest"),
        "digest_observed_at": str(_model_catalog_at),
        "digest_source": "Ollama /api/tags",
        "digest_scope": "Observed tag mapping, not an immutable runtime attestation; the tag may change",
    }


async def list_models() -> list[str]:
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(f"{settings.ollama_url}/api/tags")
        resp.raise_for_status()
        data = resp.json()
    return [m["name"] for m in data.get("models", [])]


async def embed(text: str) -> list[float]:
    """Embedding via the host Ollama (e.g. nomic-embed-text, 768 dims)."""
    payload = {"model": settings.embedding_model, "prompt": text[:4000]}
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(f"{settings.ollama_url}/api/embeddings", json=payload)
        resp.raise_for_status()
        data = resp.json()
    emb = data.get("embedding")
    if not emb:
        raise ValueError("ollama returned no embedding")
    return emb


async def embed_many(texts: list[str]) -> list[list[float]]:
    """Sequential embeddings (Ollama handles batching internally per call)."""
    out = []
    for t in texts:
        out.append(await embed(t))
    return out


async def chat_json(system_prompt: str, user_content: str) -> dict:
    """Single-turn chat that must return a JSON object.

    Uses Ollama's `format: "json"` to force JSON output and low temperature
    for deterministic analysis.
    """
    metadata = await model_metadata(settings.ollama_model)
    payload = {
        "model": settings.ollama_model,
        "stream": False,
        "format": "json",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
        "options": {"temperature": 0.1},
    }
    async with httpx.AsyncClient(timeout=ANALYSIS_TIMEOUT) as client:
        resp = await client.post(f"{settings.ollama_url}/api/chat", json=payload)
        resp.raise_for_status()
        data = resp.json()

    content = data.get("message", {}).get("content", "{}")
    # Ollama with format:"json" still returns a string; parse defensively.
    import json

    try:
        parsed = json.loads(content)
        if not isinstance(parsed, dict):
            raise TypeError("Model returned a non-object JSON result")
        parsed["_edgeguard_runtime"] = {"returned_model": data.get("model"), **metadata}
        return parsed
    except json.JSONDecodeError as exc:
        raise ValueError(f"Model returned invalid JSON: {content[:200]}") from exc
