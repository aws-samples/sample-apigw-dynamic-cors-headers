#!/usr/bin/env bash
#
# Deterministic CORS + security-headers validation against a deployed stage.
#
# Proves, in order:
#   1. An allowlisted Origin receives Access-Control-Allow-Origin echoed back.
#   2. A non-allowlisted Origin receives NO Access-Control-Allow-Origin.
#   3. Security headers are present on responses.
#   4. Preflight OPTIONS returns 204 with CORS headers.
#
# Because the API uses AWS_IAM authorization, GET/POST are signed with SigV4 via
# `curl --aws-sigv4`. Preflight OPTIONS is unauthenticated by design.
#
# Usage:
#   ./validate_cors.sh <API_URL> <ALLOWED_ORIGIN> <REGION>
# Example:
#   ./validate_cors.sh https://abc123.execute-api.us-east-1.amazonaws.com/prod \
#       https://app.example.com us-east-1
set -euo pipefail

API_URL="${1:?Usage: validate_cors.sh <API_URL> <ALLOWED_ORIGIN> <REGION>}"
ALLOWED_ORIGIN="${2:?Provide an allowlisted origin, e.g. https://app.example.com}"
REGION="${3:?Provide the AWS region, e.g. us-east-1}"
BAD_ORIGIN="https://evil.example.com"
ENDPOINT="${API_URL%/}/hello"

pass() { printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
fail() { printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; exit 1; }

sigv4() {
  # Signed GET; requires AWS credentials in the environment/instance profile.
  curl -s -D - -o /dev/null \
    --aws-sigv4 "aws:amz:${REGION}:execute-api" \
    --user "${AWS_ACCESS_KEY_ID}:${AWS_SECRET_ACCESS_KEY}" \
    ${AWS_SESSION_TOKEN:+-H "x-amz-security-token: ${AWS_SESSION_TOKEN}"} \
    -H "Origin: $1" \
    "${ENDPOINT}"
}

echo "== 1. Allowed origin is echoed back =="
HEADERS="$(sigv4 "${ALLOWED_ORIGIN}")"
if grep -iq "^access-control-allow-origin: ${ALLOWED_ORIGIN}" <<<"${HEADERS}"; then
  pass "Access-Control-Allow-Origin: ${ALLOWED_ORIGIN}"
else
  fail "Expected Access-Control-Allow-Origin: ${ALLOWED_ORIGIN}"
fi

echo "== 2. Disallowed origin gets NO CORS header =="
HEADERS="$(sigv4 "${BAD_ORIGIN}")"
if grep -iq "^access-control-allow-origin:" <<<"${HEADERS}"; then
  fail "Disallowed origin unexpectedly received a CORS header"
else
  pass "No Access-Control-Allow-Origin for ${BAD_ORIGIN}"
fi

echo "== 3. Security headers present =="
for h in "strict-transport-security" "x-content-type-options" "x-frame-options" "content-security-policy"; do
  if grep -iq "^${h}:" <<<"${HEADERS}"; then
    pass "${h} present"
  else
    fail "${h} missing"
  fi
done

echo "== 4. Preflight OPTIONS returns 204 with CORS headers =="
PREFLIGHT="$(curl -s -D - -o /dev/null -X OPTIONS \
  -H "Origin: ${ALLOWED_ORIGIN}" \
  -H "Access-Control-Request-Method: GET" \
  "${ENDPOINT}")"
if head -n1 <<<"${PREFLIGHT}" | grep -q "204"; then
  pass "Preflight returned 204"
else
  fail "Preflight did not return 204"
fi
if grep -iq "^access-control-allow-methods:" <<<"${PREFLIGHT}"; then
  pass "Preflight includes Access-Control-Allow-Methods"
else
  fail "Preflight missing Access-Control-Allow-Methods"
fi

echo ""
echo "All CORS validation checks passed."
echo ""
echo "NEXT: prove it is DYNAMIC -- edit the allowlist in AWS AppConfig (add or"
echo "remove an origin), deploy the new version, wait for propagation (~cache TTL),"
echo "then re-run this script. Behavior changes with NO Lambda redeploy."
