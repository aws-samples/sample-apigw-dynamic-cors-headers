"""Loads dynamic CORS/security-headers configuration from AWS AppConfig.

Reads through the AppConfig Lambda extension (a local HTTP cache running in the
execution environment) via Powertools' ``AppConfigProvider``. The provider keeps
an in-process cache for ``max_age`` seconds, so the vast majority of invocations
incur no network call and no per-invoke AppConfig API cost. Configuration changes
made in AppConfig propagate automatically once the cache entry expires and the
extension polls for the new deployed version -- no Lambda redeploy required.
"""
from __future__ import annotations

import os
from typing import Any, Dict

from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.parameters import AppConfigProvider
from aws_lambda_powertools.utilities.parameters.exceptions import GetParameterError

logger = Logger(child=True)

# Environment variables are used ONLY for non-sensitive AppConfig coordinates
# (which application/environment/profile to read). The CORS allowlist and header
# policy themselves live in AppConfig, never in environment variables.
_APP = os.environ["APPCONFIG_APPLICATION"]
_ENV = os.environ["APPCONFIG_ENVIRONMENT"]
_PROFILE = os.environ["APPCONFIG_PROFILE"]
_CACHE_SECONDS = int(os.environ.get("APPCONFIG_CACHE_SECONDS", "45"))

# One provider per execution environment, reused across warm invocations.
_provider = AppConfigProvider(environment=_ENV, application=_APP)

# Last-known-good configuration. If AppConfig is briefly unreachable AND the
# cache has expired, we fall back to this rather than failing open on CORS.
_last_good: Dict[str, Any] | None = None

# Conservative built-in default used only if the very first load fails before we
# ever obtained a real configuration. Denies all cross-origin access.
_SAFE_DEFAULT: Dict[str, Any] = {
    "allowedOrigins": [],
    "allowedMethods": ["GET", "POST", "OPTIONS"],
    "allowedHeaders": ["Content-Type", "Authorization"],
    "allowCredentials": False,
    "maxAgeSeconds": 0,
    "securityHeaders": {
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
        "Referrer-Policy": "no-referrer",
        "Cache-Control": "no-store",
    },
}


def get_config() -> Dict[str, Any]:
    """Return the current CORS/security-headers configuration.

    Never raises: on a load failure it returns the last-known-good config, or the
    deny-by-default configuration if none was ever loaded. This guarantees a
    transient AppConfig issue can never cause the function to start reflecting
    arbitrary origins.
    """
    global _last_good
    try:
        config: Dict[str, Any] = _provider.get(
            _PROFILE,
            max_age=_CACHE_SECONDS,
            transform="json",
        )
        _last_good = config
        return config
    except (GetParameterError, ValueError, KeyError) as exc:
        if _last_good is not None:
            logger.warning(
                "AppConfig fetch failed; using last-known-good config.",
                extra={"error": str(exc)},
            )
            return _last_good
        logger.error(
            "AppConfig fetch failed with no cached config; denying all origins.",
            extra={"error": str(exc)},
        )
        return _SAFE_DEFAULT
