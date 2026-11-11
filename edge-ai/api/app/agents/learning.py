"""Learning Agent — Phase 9.

Embeds analyzed incidents into pgvector so future events can be matched
against past ones ("AI เรียนรู้จากเหตุการณ์"). The worker also injects the
top-k similar past incidents into the Analysis Agent's evidence, closing
the feedback loop: every analyzed event makes the next analysis more informed.
"""

import asyncio
import sys

from app.config import settings
from app.integrations import db, ollama_client


def incident_text(row: dict) -> str:
    """Compact text used as the embedding source for one incident."""
    parts = [
        f"kind: {row.get('kind')}",
        f"reason: {row.get('reason')}",
        f"attack_type: {row.get('attack_type')}",
        f"source_ip: {row.get('source_ip')}",
        f"reasoning: {row.get('reasoning')}",
    ]
    return "\n".join(p for p in parts if p and not p.endswith(": "))


async def embed_once() -> int:
    rows = await db.list_unembedded(settings.learning_batch)
    done = 0
    for row in rows:
        text = incident_text(row)
        try:
            emb = await ollama_client.embed(text)
            if len(emb) != settings.embedding_dim:
                raise ValueError(
                    f"dim mismatch: got {len(emb)}, expected {settings.embedding_dim}"
                )
            await db.set_embedding(row["alert_id"], emb)
            done += 1
        except Exception as exc:  # noqa: BLE001 — skip and retry next tick
            sys.stderr.write(f"[learning] {row['alert_id']} embed failed: {exc}\n")
    return done


async def similar_context(text: str, exclude_alert_id: str | None = None,
                          k: int | None = None) -> list[dict]:
    """Top-k similar past incidents for a piece of text (RAG context)."""
    emb = await ollama_client.embed(text)
    return await db.search_similar(
        emb, k or settings.similar_top_k, exclude_alert_id
    )


async def run() -> None:
    interval = 60
    sys.stderr.write(
        f"[learning] started, embedding with {settings.embedding_model} "
        f"(batch {settings.learning_batch}/tick)\n"
    )
    while True:
        try:
            done = await embed_once()
            if done:
                stats = await db.embedding_stats()
                sys.stderr.write(
                    f"[learning] embedded {done} — total {stats['embedded']}"
                    f"/{stats['analyzed']}\n"
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"[learning] tick failed: {exc}\n")
        await asyncio.sleep(interval)
