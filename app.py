#!/usr/bin/env python3
"""CDK application entry point.

Deploys the dynamic CORS validation and security-headers enforcement pattern:
API Gateway (IAM-authorized) -> Lambda (Powertools middleware) -> AWS AppConfig.
"""
import os

import aws_cdk as cdk
from cdk_nag import AwsSolutionsChecks

from stacks.cors_lambda_stack import CorsLambdaStack
from stacks.ui_demo_stack import UiDemoStack

app = cdk.App()

# Baseline tags on every resource in both stacks: ownership/cost attribution,
# tag-based access control, and easy discovery of sample resources at clean-up.
cdk.Tags.of(app).add("Project", "dynamic-cors-security-headers-apigw-lambda")
cdk.Tags.of(app).add("Environment", "sample-non-production")

# Run the AWS Solutions security/best-practice rule pack against the whole app
# at synth time. Any unaddressed finding fails synth, so the pattern cannot ship
# with an unreviewed security gap.
cdk.Aspects.of(app).add(AwsSolutionsChecks(verbose=True))

# Deploy to the account/region resolved from the standard AWS environment.
env = cdk.Environment(
    account=os.environ.get("CDK_DEFAULT_ACCOUNT"),
    region=os.environ.get("CDK_DEFAULT_REGION"),
)

CorsLambdaStack(
    app,
    "CorsLambdaStack",
    env=env,
    description="Dynamic CORS validation and security headers enforcement "
    "for API Gateway and Lambda (APG pattern).",
)

# Optional: S3 + CloudFront hosting for the browser demo page.
UiDemoStack(
    app,
    "UiDemoStack",
    env=env,
    description="Optional S3 + CloudFront hosting for the dynamic CORS browser demo.",
)

app.synth()
