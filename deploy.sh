#!/usr/bin/env bash
#
# Convenience wrapper to deploy the pattern. Assumes AWS credentials are already
# configured in the environment and the CDK CLI is installed.
#
# Usage: ./deploy.sh [region]
set -euo pipefail

REGION="${1:-${CDK_DEFAULT_REGION:-us-east-1}}"
export CDK_DEFAULT_REGION="${REGION}"
# Assign and export separately (ShellCheck SC2155) so a failing `aws` call
# aborts the script under `set -e` instead of being masked by `export`.
CDK_DEFAULT_ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
export CDK_DEFAULT_ACCOUNT

echo "Deploying CorsLambdaStack to account ${CDK_DEFAULT_ACCOUNT} / ${REGION}"
cdk deploy --require-approval any-change
echo ""
echo "Deployed. Validate with:"
echo "  ./tests/validate_cors.sh <ApiUrl> <allowed-origin> ${REGION}"
