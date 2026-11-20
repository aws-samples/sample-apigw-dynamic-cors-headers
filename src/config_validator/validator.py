"""AWS AppConfig Lambda validator.

AppConfig invokes this function with each new configuration version BEFORE it can
be deployed. Raising an exception fails validation and blocks the rollout. This
enforces semantic rules that a JSON Schema cannot fully express, layering on top
of the schema validator:

  * No wildcard origins ('*').
  * All origins must be https:// (localhost permitted for local dev only).
  * Credentialed CORS is never combined with a wildcard.
  * Baseline security headers must be present.

The event delivers the candidate configuration as base64-encoded content.
"""
from __future__ import annotations

import base64
import json
from typing import Any, Dict

_REQUIRED_SECURITY_HEADERS = {
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
}


def _decode(event: Dict[str, Any]) -> Dict[str, Any]:
    content = event.get("content")
    if content is None:
        raise ValueError("Validator event missing 'content'.")
    return json.loads(base64.b64decode(content).decode("utf-8"))


def handler(event: Dict[str, Any], context: Any) -> None:
    config = _decode(event)

    origins = config.get("allowedOrigins", [])
    if not isinstance(origins, list) or not origins:
        raise ValueError("allowedOrigins must be a non-empty list.")

    for origin in origins:
        if origin == "*":
            raise ValueError("Wildcard origin '*' is not permitted.")
        if not (
            origin.startswith("https://")
            or origin.startswith("http://localhost")
            or origin.startswith("http://127.0.0.1")
        ):
            raise ValueError(f"Origin must use https (or localhost): {origin!r}")

    if config.get("allowCredentials") and "*" in origins:
        raise ValueError("allowCredentials cannot be combined with wildcard origin.")

    headers = config.get("securityHeaders", {})
    missing = _REQUIRED_SECURITY_HEADERS - set(headers)
    if missing:
        raise ValueError(f"Missing required security headers: {sorted(missing)}")

    # Returning normally signals a valid configuration to AppConfig.
