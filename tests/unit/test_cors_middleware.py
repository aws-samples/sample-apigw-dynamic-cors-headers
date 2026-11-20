"""Unit tests for the reusable CORS + security-headers middleware."""
import importlib
import os
import sys

import pytest

# Make the handler source importable and provide required env vars before import.
SRC = os.path.join(os.path.dirname(__file__), "..", "..", "src", "api_handler")
sys.path.insert(0, os.path.abspath(SRC))
os.environ.setdefault("APPCONFIG_APPLICATION", "app")
os.environ.setdefault("APPCONFIG_ENVIRONMENT", "env")
os.environ.setdefault("APPCONFIG_PROFILE", "profile")

CONFIG = {
    "allowedOrigins": ["https://app.example.com"],
    "allowedMethods": ["GET", "POST", "OPTIONS"],
    "allowedHeaders": ["Content-Type", "Authorization"],
    "allowCredentials": True,
    "maxAgeSeconds": 600,
    "securityHeaders": {
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
        "Referrer-Policy": "no-referrer",
    },
}


@pytest.fixture
def middleware(monkeypatch):
    import cors_middleware

    importlib.reload(cors_middleware)
    monkeypatch.setattr(cors_middleware, "get_config", lambda: CONFIG)
    return cors_middleware


def _event(method="GET", origin=None):
    headers = {}
    if origin is not None:
        headers["Origin"] = origin
    return {"httpMethod": method, "headers": headers, "path": "/hello"}


def test_allowed_origin_is_echoed(middleware):
    @middleware.cors_and_security_headers
    def handler(event, context):
        return {"statusCode": 200, "body": "ok"}

    resp = handler(_event(origin="https://app.example.com"), None)
    assert resp["headers"]["Access-Control-Allow-Origin"] == "https://app.example.com"
    assert resp["headers"]["Access-Control-Allow-Credentials"] == "true"
    assert resp["headers"]["Vary"] == "Origin"


def test_disallowed_origin_gets_no_cors_header(middleware):
    @middleware.cors_and_security_headers
    def handler(event, context):
        return {"statusCode": 200, "body": "ok"}

    resp = handler(_event(origin="https://evil.example.com"), None)
    assert "Access-Control-Allow-Origin" not in resp["headers"]
    # Security headers are still enforced even when CORS is denied.
    assert resp["headers"]["X-Content-Type-Options"] == "nosniff"


def test_wildcard_is_never_emitted(middleware):
    @middleware.cors_and_security_headers
    def handler(event, context):
        return {"statusCode": 200, "body": "ok"}

    resp = handler(_event(origin="https://app.example.com"), None)
    assert resp["headers"]["Access-Control-Allow-Origin"] != "*"


def test_preflight_short_circuits_with_204(middleware):
    called = {"handler": False}

    @middleware.cors_and_security_headers
    def handler(event, context):
        called["handler"] = True
        return {"statusCode": 200, "body": "ok"}

    resp = handler(_event(method="OPTIONS", origin="https://app.example.com"), None)
    assert resp["statusCode"] == 204
    assert called["handler"] is False
    assert resp["headers"]["Access-Control-Allow-Methods"] == "GET, POST, OPTIONS"
    assert resp["headers"]["Access-Control-Max-Age"] == "600"


def test_security_headers_present_on_success(middleware):
    @middleware.cors_and_security_headers
    def handler(event, context):
        return {"statusCode": 200, "body": "ok"}

    resp = handler(_event(origin="https://app.example.com"), None)
    for key in CONFIG["securityHeaders"]:
        assert resp["headers"][key] == CONFIG["securityHeaders"][key]


def test_security_headers_present_on_handler_error(middleware):
    @middleware.cors_and_security_headers
    def handler(event, context):
        raise RuntimeError("boom")

    resp = handler(_event(origin="https://app.example.com"), None)
    assert resp["statusCode"] == 500
    assert resp["headers"]["X-Frame-Options"] == "DENY"
    # CORS still applied to the error response for the allowed origin.
    assert resp["headers"]["Access-Control-Allow-Origin"] == "https://app.example.com"


def test_missing_origin_omits_cors(middleware):
    @middleware.cors_and_security_headers
    def handler(event, context):
        return {"statusCode": 200, "body": "ok"}

    resp = handler(_event(origin=None), None)
    assert "Access-Control-Allow-Origin" not in resp["headers"]
    assert resp["headers"]["X-Content-Type-Options"] == "nosniff"
