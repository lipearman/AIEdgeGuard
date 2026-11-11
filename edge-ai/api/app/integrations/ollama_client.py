"""Thin client for the existing host Ollama service.

The llm-server runs Ollama as a systemd service on port 11434. Containers
reach it via host.docker.internal (see extra_hosts in docker-compose.yml).
"""

import httpx

from app.config import settings

ANALYSIS_TIMEOUT = 180.0  # 9B models on RTX 2060 can be slow on long prompts


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
        return json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Model returned invalid JSON: {content[:200]}") from exc
