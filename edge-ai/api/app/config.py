"""Application settings (12-factor style, loaded from environment)."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # --- AI runtime (existing host Ollama on the llm-server) ---
    ollama_url: str = "http://host.docker.internal:11434"
    ollama_model: str = "qwen3.5:9b"

    # --- CrowdSec LAPI ---
    crowdsec_lapi_url: str = "http://crowdsec:8080"
    crowdsec_machine_id: str = "edge-ai"
    crowdsec_machine_password: str = ""
    # Read-only bouncer key for /v1/decisions:
    #   cscli bouncers add edge-ai-readonly -o raw
    crowdsec_bouncer_key: str = ""

    # --- Data plane ---
    redis_url: str = "redis://redis:6379/0"
    database_url: str = "postgresql://edgeguard:secret@gateway-postgres:5432/edgeguard"

    # --- Auto-ingestion (Phase 4) ---
    ingest_enabled: bool = True       # watcher: poll LAPI for new alerts
    analyze_enabled: bool = True      # worker: run Analysis Agent per new alert
    poll_interval_seconds: int = 30

    # --- Safety switch: automated blocking stays OFF until the
    #     Policy Engine (deterministic gate) is implemented and tested.
    defense_enabled: bool = False


settings = Settings()
