"""
engine/gemini.py
================
Shared async Gemini client.

One small wrapper so every AI feature (classifier, investigation agent,
chain narrative, NL hunt) talks to Gemini the same way and degrades the
same way when the key is missing or the call fails.

`generate_json` always returns either parsed JSON or None — callers are
expected to have a deterministic fallback. AI is a quality layer here,
never a hard dependency (storageless, offline-friendly by design).
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any, Optional

import httpx

from config import settings

log = logging.getLogger("noctra.gemini")

# Pinned to a STABLE GA model on purpose. "gemini-flash-latest" is a moving
# alias that currently resolves to a preview model (gemini-3-flash-preview)
# which is a thinking model and frequently returns 503 "high demand" — that
# instability silently degraded every AI feature to the offline heuristic.
_GEMINI_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    "gemini-2.5-flash:generateContent"
)
_TIMEOUT = 30


def available() -> bool:
    return settings.gemini_ready


def _strip_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.MULTILINE)
    return text.strip()


async def generate_json(
    system_prompt: str,
    user_text: str,
    temperature: float = 0.2,
) -> Optional[Any]:
    """
    Ask Gemini for a JSON response. Returns the parsed object, or None on
    any failure (no key, HTTP error, malformed JSON). Never raises.
    """
    if not settings.gemini_ready:
        return None

    payload = {
        "system_instruction": {"parts": [{"text": system_prompt}]},
        "contents": [{"role": "user", "parts": [{"text": user_text}]}],
        "generationConfig": {
            "temperature": temperature,
            "responseMimeType": "application/json",
            # gemini-flash-latest now resolves to a "thinking" model. Without
            # this, every call silently burns a large hidden thinking-token
            # budget — slow, quota-hungry, and on big prompts it exhausts
            # MAX_TOKENS and returns NO text part, forcing a heuristic
            # fallback. Disabling thinking makes calls cheap and reliable.
            "thinkingConfig": {"thinkingBudget": 0},
        },
    }

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                _GEMINI_URL,
                params={"key": settings.gemini_api_key},
                json=payload,
            )
            # One short retry on transient overload / rate limit before we
            # give up and degrade to the heuristic fallback.
            if resp.status_code in (429, 503):
                await asyncio.sleep(2)
                resp = await client.post(
                    _GEMINI_URL,
                    params={"key": settings.gemini_api_key},
                    json=payload,
                )
            if resp.status_code != 200:
                log.warning(
                    "Gemini HTTP %s — caller will use fallback. Body: %s",
                    resp.status_code,
                    resp.text[:500],
                )
                return None
            body = resp.json()
        text = body["candidates"][0]["content"]["parts"][0]["text"]
    except (httpx.HTTPError, KeyError, IndexError, TypeError) as exc:
        log.warning("Gemini call failed (%s) — caller will use fallback", exc)
        return None

    try:
        return json.loads(_strip_fences(text))
    except json.JSONDecodeError:
        log.warning("Gemini returned unparseable JSON — caller will use fallback")
        return None
