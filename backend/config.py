"""
config.py
=========
Central settings loader for the Noctra AI backend.

Everything that might change between dev / prod (API keys, TTLs, upload size,
CORS origin) is read here from environment variables / .env so the rest of the
app never has to touch os.getenv directly.

Storageless principle: this module loads constants ONCE at startup. It does not
persist anything to disk.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

# Load .env from the backend folder (silently no-op if missing in production).
# override=True so the project's .env is authoritative even when a stale
# same-named variable exists in the OS environment (common on dev machines).
load_dotenv(override=True)


@dataclass(frozen=True)
class Settings:
    """Immutable runtime settings for the backend."""

    # --- External API keys (filled in by the user after Phase 1) ---
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")
    abuseipdb_api_key: str = os.getenv("ABUSEIPDB_API_KEY", "")
    virustotal_api_key: str = os.getenv("VIRUSTOTAL_API_KEY", "")

    # --- Session lifecycle ---
    session_ttl_minutes: int = int(os.getenv("SESSION_TTL_MINUTES", "30"))
    session_sweep_interval_seconds: int = int(
        os.getenv("SESSION_SWEEP_INTERVAL_SECONDS", "60")
    )

    # --- Uploads ---
    max_upload_mb: int = int(os.getenv("MAX_UPLOAD_MB", "25"))

    # --- CORS ---
    cors_origin: str = os.getenv("CORS_ORIGIN", "http://localhost:5173")

    @property
    def cors_origins(self) -> list[str]:
        origins = [self.cors_origin]
        extra = os.getenv("CORS_ORIGINS_EXTRA", "")
        if extra:
            origins += [o.strip() for o in extra.split(",") if o.strip()]
        origins += ["https://noctra-ai-autonomous-soc-platform.vercel.app"]
        return list(dict.fromkeys(origins))

    # --- Convenience flags ---
    @property
    def gemini_ready(self) -> bool:
        return bool(self.gemini_api_key)

    @property
    def abuseipdb_ready(self) -> bool:
        return bool(self.abuseipdb_api_key)

    @property
    def virustotal_ready(self) -> bool:
        return bool(self.virustotal_api_key)


# A single shared instance — import this everywhere.
settings = Settings()
