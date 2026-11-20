"""Reusable CORS validation + security-headers middleware.

This is the reusable asset of the pattern. It is built with Powertools'
``@lambda_handler_decorator`` factory so any handler can opt in with a single
decorator, and the enforcement logic lives in exactly one place.

Enforcement rules (all driven by the AppConfig configuration):
  1. The incoming ``Origin`` is matched EXACTLY against the allowlist.
  2. Preflight ``OPTIONS`` requests short-circuit to ``204`` with CORS headers.
  3. ``Access-Control-Allow-Origin`` is echoed back ONLY on an exact match --
     the wildcard ``*`` is never emitted, and an unvalidated origin is never
     reflected.
  4. ``Access-Control-Allow-Credentials: true`` is emitted only alongside a
     specific origin (never with ``*``), avoiding the well-known credentialed-
     wildcard vulnerability.
  5. Security headers are injected on EVERY response -- success, error, and
     preflight alike.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from aws_lambda_powertools import Logger
from aws_lambda_powertools.middleware_factory import lambda_handler_decorator

from config_loader import get_config

logger = Logger(child=True)


def _get_origin(event: Dict[str, Any]) -> Optional[str]:
    """Case-insensitively extract the Origin header from a REST API event."""
    headers = event.get("headers") or {}
    for key, value in headers.items():
        if key.lower() == "origin":
            return value
    return None


def _http_method(event: Dict[str, Any]) -> str:
    return (
        event.get("httpMethod")
        or event.get("requestContext", {}).get("http", {}).get("method")
        or ""
    ).upper()


def _cors_headers(origin: Optional[str], config: Dict[str, Any]) -> Dict[str, str]:
    """Build CORS response headers for an allowed origin.

    Returns an empty dict when the origin is missing or not allowlisted, so the
    browser receives no ``Access-Control-Allow-Origin`` and blocks the response.
    """
    allowed = config.get("allowedOrigins", [])
    if not origin or origin not in allowed:
        if origin:
            logger.info("Origin rejected by allowlist.", extra={"origin": origin})
        return {}

    headers = {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Methods": ", ".join(config.get("allowedMethods", [])),
        "Access-Control-Allow-Headers": ", ".join(config.get("allowedHeaders", [])),
        "Vary": "Origin",
    }
    if config.get("allowCredentials"):
        # Only ever paired with a specific origin, never with '*'.
        headers["Access-Control-Allow-Credentials"] = "true"
    if "maxAgeSeconds" in config:
        headers["Access-Control-Max-Age"] = str(config["maxAgeSeconds"])
    return headers


def _merge_headers(response: Dict[str, Any], extra: Dict[str, str]) -> None:
    existing = response.get("headers") or {}
    existing.update(extra)
    response["headers"] = existing


@lambda_handler_decorator
def cors_and_security_headers(handler, event, context) -> Dict[str, Any]:
    """Wrap a REST handler with dynamic CORS + security-header enforcement."""
    config = get_config()
    origin = _get_origin(event)
    security_headers: Dict[str, str] = config.get("securityHeaders", {})
    cors = _cors_headers(origin, config)

    # 1. Preflight short-circuit -- never invokes the wrapped handler.
    if _http_method(event) == "OPTIONS":
        response = {"statusCode": 204, "headers": {}, "body": ""}
        _merge_headers(response, security_headers)
        _merge_headers(response, cors)
        return response

    # 2. Run the actual handler, injecting headers on success AND on error.
    try:
        response = handler(event, context)
    except Exception:
        error_response = {
            "statusCode": 500,
            "headers": {},
            "body": '{"message": "Internal server error"}',
        }
        _merge_headers(error_response, security_headers)
        _merge_headers(error_response, cors)
        logger.exception("Handler raised; returning 500 with enforced headers.")
        return error_response

    if not isinstance(response, dict):
        response = {"statusCode": 200, "body": response}
    _merge_headers(response, security_headers)
    _merge_headers(response, cors)
    return response
