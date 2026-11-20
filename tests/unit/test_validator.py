"""Unit tests for the AppConfig Lambda validator."""
import base64
import json
import os
import sys

import pytest

SRC = os.path.join(os.path.dirname(__file__), "..", "..", "src", "config_validator")
sys.path.insert(0, os.path.abspath(SRC))

import validator  # noqa: E402

VALID = {
    "allowedOrigins": ["https://app.example.com"],
    "allowedMethods": ["GET", "POST", "OPTIONS"],
    "allowedHeaders": ["Content-Type"],
    "allowCredentials": True,
    "securityHeaders": {
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'none'",
    },
}


def _event(config):
    return {"content": base64.b64encode(json.dumps(config).encode()).decode()}


def test_valid_config_passes():
    validator.handler(_event(VALID), None)  # should not raise


def test_wildcard_origin_rejected():
    bad = {**VALID, "allowedOrigins": ["*"]}
    with pytest.raises(ValueError, match="Wildcard"):
        validator.handler(_event(bad), None)


def test_non_https_origin_rejected():
    bad = {**VALID, "allowedOrigins": ["http://app.example.com"]}
    with pytest.raises(ValueError, match="https"):
        validator.handler(_event(bad), None)


def test_localhost_allowed():
    ok = {**VALID, "allowedOrigins": ["http://localhost:3000"]}
    validator.handler(_event(ok), None)  # should not raise


def test_empty_origins_rejected():
    bad = {**VALID, "allowedOrigins": []}
    with pytest.raises(ValueError, match="non-empty"):
        validator.handler(_event(bad), None)


def test_missing_security_header_rejected():
    bad = {**VALID, "securityHeaders": {"X-Content-Type-Options": "nosniff"}}
    with pytest.raises(ValueError, match="Missing required"):
        validator.handler(_event(bad), None)
