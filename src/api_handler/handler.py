"""Example business handler protected by the reusable CORS middleware.

The handler itself contains no CORS or security-header logic -- that concern is
entirely owned by the ``cors_and_security_headers`` decorator, which reads its
policy dynamically from AWS AppConfig.
"""
from __future__ import annotations

import json
from typing import Any, Dict

from aws_lambda_powertools import Logger, Tracer

from cors_middleware import cors_and_security_headers

logger = Logger(service="cors-pattern")
tracer = Tracer(service="cors-pattern")


@cors_and_security_headers
@logger.inject_lambda_context
@tracer.capture_lambda_handler
def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Return a simple JSON payload; headers are applied by the middleware."""
    logger.info("Handling request.", extra={"path": event.get("path")})
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(
            {
                "message": "Hello from the dynamic CORS pattern.",
                "note": "CORS and security headers were applied by shared middleware "
                "using configuration served from AWS AppConfig.",
            }
        ),
    }
