"""Optional S3 + CloudFront hosting for the browser demo page.

Serves ui-demo/index.html from a private S3 bucket via CloudFront using Origin
Access Control (OAC), over HTTPS only, with security headers added at the edge.
This gives the demo a real, shareable ``https://<id>.cloudfront.net`` origin that
you add to the AppConfig allowlist to see the CORS decision flip in a browser.

Kept as a separate stack so the core pattern stack's cdk-nag report stays clean;
the demo-grade suppressions here are documented inline.
"""
from __future__ import annotations

import os

from aws_cdk import (
    Aws,
    CfnOutput,
    Duration,
    RemovalPolicy,
    Stack,
)
from aws_cdk import aws_cloudfront as cloudfront
from aws_cdk import aws_cloudfront_origins as origins
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_s3_deployment as s3deploy
from cdk_nag import NagSuppressions
from constructs import Construct

_UI_DIR = os.path.join(os.path.dirname(__file__), "..", "ui-demo")


class UiDemoStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Destination bucket for S3 server access logs and CloudFront logs.
        logs_bucket = s3.Bucket(
            self,
            "UiLogsBucket",
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
            object_ownership=s3.ObjectOwnership.BUCKET_OWNER_PREFERRED,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
            lifecycle_rules=[s3.LifecycleRule(expiration=Duration.days(90))],
        )

        # Private bucket holding the static demo page. No public access; served
        # only through CloudFront via OAC.
        site_bucket = s3.Bucket(
            self,
            "UiSiteBucket",
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
            server_access_logs_bucket=logs_bucket,
            server_access_logs_prefix="s3-access/",
        )

        # Security headers enforced at the edge (defense in depth alongside the
        # Lambda). The CSP allows only same-origin script/style (no inline code)
        # and restricts fetch() to API Gateway endpoints in this Region.
        response_headers = cloudfront.ResponseHeadersPolicy(
            self,
            "UiSecurityHeaders",
            security_headers_behavior=cloudfront.ResponseSecurityHeadersBehavior(
                strict_transport_security=cloudfront.ResponseHeadersStrictTransportSecurity(
                    access_control_max_age=Duration.days(730),
                    include_subdomains=True,
                    preload=True,
                    override=True,
                ),
                content_type_options=cloudfront.ResponseHeadersContentTypeOptions(
                    override=True
                ),
                frame_options=cloudfront.ResponseHeadersFrameOptions(
                    frame_option=cloudfront.HeadersFrameOption.DENY, override=True
                ),
                referrer_policy=cloudfront.ResponseHeadersReferrerPolicy(
                    referrer_policy=cloudfront.HeadersReferrerPolicy.NO_REFERRER,
                    override=True,
                ),
                content_security_policy=cloudfront.ResponseHeadersContentSecurityPolicy(
                    content_security_policy=(
                        "default-src 'self'; script-src 'self'; "
                        "style-src 'self'; "
                        f"connect-src https://*.execute-api.{Aws.REGION}.amazonaws.com; "
                        "img-src 'self' data:; frame-ancestors 'none'"
                    ),
                    override=True,
                ),
            ),
        )

        self.distribution = cloudfront.Distribution(
            self,
            "UiDistribution",
            comment="Dynamic CORS pattern - browser demo hosting",
            default_root_object="index.html",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3BucketOrigin.with_origin_access_control(site_bucket),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                response_headers_policy=response_headers,
                cache_policy=cloudfront.CachePolicy.CACHING_OPTIMIZED,
            ),
            minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
            enable_logging=True,
            log_bucket=logs_bucket,
            log_file_prefix="cloudfront-access/",
        )

        # Second distribution serving the SAME page from a DIFFERENT origin. Its
        # origin is intentionally NOT added to the allowlist, so it demonstrates
        # the "denied" side of CORS side-by-side with the allowed distribution.
        self.denied_distribution = cloudfront.Distribution(
            self,
            "UiDistributionDenied",
            comment="Dynamic CORS pattern - browser demo (NOT allowlisted / denied)",
            default_root_object="index.html",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3BucketOrigin.with_origin_access_control(site_bucket),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                response_headers_policy=response_headers,
                cache_policy=cloudfront.CachePolicy.CACHING_OPTIMIZED,
            ),
            minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
            enable_logging=True,
            log_bucket=logs_bucket,
            log_file_prefix="cloudfront-access-denied/",
        )

        s3deploy.BucketDeployment(
            self,
            "DeployUi",
            sources=[s3deploy.Source.asset(_UI_DIR)],
            destination_bucket=site_bucket,
            distribution=self.distribution,
            distribution_paths=["/*"],
            # Explicit, modest memory for the CDK upload helper Lambda. Newer
            # aws-cdk-lib defaults to 1024 MB, which fails in accounts with a
            # reduced Lambda memory quota; 512 MB is ample for three static files.
            memory_limit=512,
        )

        CfnOutput(
            self,
            "AllowedDemoUrl",
            value=f"https://{self.distribution.distribution_domain_name}",
            description="ALLOWED demo: this origin IS on the AppConfig allowlist "
            "(shows CORS ALLOWED).",
        )
        CfnOutput(
            self,
            "DeniedDemoUrl",
            value=f"https://{self.denied_distribution.distribution_domain_name}",
            description="DENIED demo: this origin is NOT on the allowlist "
            "(shows CORS BLOCKED).",
        )
        CfnOutput(
            self,
            "AllowedOrigin",
            value=f"https://{self.distribution.distribution_domain_name}",
            description="The exact origin string that must be in allowedOrigins.",
        )

        self._apply_nag_suppressions()

    def _apply_nag_suppressions(self) -> None:
        """Documented, demo-appropriate suppressions for the UI hosting stack."""
        # The log-destination bucket cannot log to itself.
        NagSuppressions.add_resource_suppressions(
            self.node.find_child("UiLogsBucket"),
            [
                {
                    "id": "AwsSolutions-S1",
                    "reason": "This bucket is the access-log destination; it cannot "
                    "log to itself.",
                }
            ],
        )
        # CloudFront demo distributions (allowed + denied): geo restriction and
        # WAF are out of scope for a static public demo page (the protected API
        # has its own WAF), and the default *.cloudfront.net certificate governs
        # the TLS policy.
        for dist in (self.distribution, self.denied_distribution):
            NagSuppressions.add_resource_suppressions(
                dist,
                [
                    {
                        "id": "AwsSolutions-CFR1",
                        "reason": "Public demo page; no geographic restriction intended.",
                    },
                    {
                        "id": "AwsSolutions-CFR2",
                        "reason": "Static public demo asset; the protected API (separate "
                        "stack) is fronted by AWS WAF. Add WAF here for production.",
                    },
                    {
                        "id": "AwsSolutions-CFR4",
                        "reason": "Demo uses the default *.cloudfront.net certificate; "
                        "TLS 1.2_2021 min protocol is set. Use a custom domain/cert in "
                        "production.",
                    },
                ],
            )
        # The AWS-managed BucketDeployment custom resource creates its own role and
        # runtime that we do not control.
        # CDK names the helper by a fixed UUID plus the memory size (memory_limit=512).
        bd = "/UiDemoStack/Custom::CDKBucketDeployment8693BB64968944B69AAFB0CC9EB8756C512MiB"
        for path, rules in {
            f"{bd}/ServiceRole/Resource": [
                "AwsSolutions-IAM4"
            ],
            f"{bd}/ServiceRole/DefaultPolicy/Resource": [
                "AwsSolutions-IAM5"
            ],
            f"{bd}/Resource": [
                "AwsSolutions-L1"
            ],
        }.items():
            NagSuppressions.add_resource_suppressions_by_path(
                self,
                path,
                [
                    {
                        "id": rid,
                        "reason": "AWS-managed CDK BucketDeployment custom resource; "
                        "its role/runtime are controlled by the CDK library.",
                    }
                    for rid in rules
                ],
            )
