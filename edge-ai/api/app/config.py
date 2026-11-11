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

    # --- Detection / Decision / Defense (Phases 5-7) ---
    detection_enabled: bool = True    # cluster incidents into campaigns
    decide_enabled: bool = True       # run Policy Engine on analyzed incidents
    defense_auto_execute: bool = False  # FALSE = dry-run (human approval required)
                                        # TRUE = policy-approved L1 actions auto-execute

    # --- Attack Lab (Phase 8) — kill switch OFF by default ---
    attack_enabled: bool = False      # master kill switch for the Attack Simulator
    attack_target_allowlist: str = "juicelab.lab.local"  # comma-separated hosts
    attacker_url: str = "http://edge-attacker:8000"

    # --- Learning loop (Phase 9) ---
    learning_enabled: bool = True     # embed incidents into pgvector
    embedding_model: str = "nomic-embed-text:latest"  # 768 dims, 0.3GB
    embedding_dim: int = 768
    learning_batch: int = 10          # incidents embedded per loop tick
    similar_top_k: int = 3            # similar past incidents fed to Analysis

    # --- Safety switch (legacy stub, superseded by decisions workflow) ---
    defense_enabled: bool = False


settings = Settings()
