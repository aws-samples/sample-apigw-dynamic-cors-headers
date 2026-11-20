"""CDK stack for the dynamic CORS + security-headers enforcement pattern.

Provisions, secure-by-default:
  * AWS AppConfig application/environment/profile holding the CORS + header
    policy, guarded by a JSON Schema validator AND a Lambda validator, and
    released with a gradual deployment strategy.
  * A Python API handler Lambda that reads the config through the AppConfig
    Lambda extension and enforces CORS/headers via shared middleware.
  * A REST API with AWS_IAM authorization on every method (no open endpoints).
  * An AWS WAF web ACL (AWS managed rules + rate limiting) associated to the stage.
  * A customer-managed AWS KMS key (automatic rotation enabled) that encrypts
    all CloudWatch log groups and the API handler's environment variables.
  * CloudWatch log groups with retention, API access logging, TLS enforcement,
    and least-privilege IAM.
"""
from __future__ import annotations

import os
import shutil
import subprocess

from aws_cdk import (
    Aws,
    BundlingOptions,
    CfnOutput,
    DockerImage,
    Duration,
    ILocalBundling,
    RemovalPolicy,
    Stack,
)
from aws_cdk import aws_apigateway as apigw
from aws_cdk import aws_appconfig as appconfig
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from aws_cdk import aws_wafv2 as wafv2
from cdk_nag import NagSuppressions
import jsii
from constructs import Construct


@jsii.implements(ILocalBundling)
class LocalPipBundling:
    """Bundle the Lambda locally with pip when available, else fall back to Docker.

    Lets the pattern synthesize/deploy on machines without Docker. CDK calls
    ``try_bundle`` first; returning False makes it use the Docker image instead.
    """

    def __init__(self, source_dir: str) -> None:
        self._source_dir = source_dir

    def try_bundle(self, output_dir: str, *, image=None, **_kwargs) -> bool:
        if not _which("pip3") and not _which("pip"):
            return False
        pip = _which("pip3") or _which("pip")
        req = os.path.join(self._source_dir, "requirements.txt")
        try:
            subprocess.run(
                [pip, "install", "-r", req, "-t", output_dir],
                check=True,
            )
        except subprocess.CalledProcessError:
            return False
        # Copy the handler source alongside the installed dependencies. Uses
        # shutil (no shell) to avoid any shell-injection surface.
        shutil.copytree(self._source_dir, output_dir, dirs_exist_ok=True)
        return True


def _which(cmd: str) -> str | None:
    from shutil import which

    return which(cmd)

# AWS-managed AppConfig Lambda extension layer ARNs vary by region/arch. This
# map covers common regions for x86_64; extend as needed for your target region.
# See: https://docs.aws.amazon.com/appconfig/latest/userguide/appconfig-integration-lambda-extensions-versions.html
APPCONFIG_EXTENSION_LAYER_ARNS = {
    "us-east-1": "arn:aws:lambda:us-east-1:027255383542:layer:AWS-AppConfig-Extension:207",
    "us-west-2": "arn:aws:lambda:us-west-2:359756378197:layer:AWS-AppConfig-Extension:208",
    "eu-west-1": "arn:aws:lambda:eu-west-1:434848589818:layer:AWS-AppConfig-Extension:200",
    "ap-south-1": "arn:aws:lambda:ap-south-1:554480029851:layer:AWS-AppConfig-Extension:200",
}

_APPCONFIG_DIR = os.path.join(os.path.dirname(__file__), "..", "appconfig")


class CorsLambdaStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self._build_data_key()
        self._build_appconfig()
        self._build_api_handler()
        self._build_rest_api()
        self._build_waf()
        self._emit_outputs()
        self._apply_nag_suppressions()

    # ---------------------------------------------------------------- KMS key
    def _build_data_key(self) -> None:
        """Customer-managed key for CloudWatch Logs and Lambda env vars.

        Gives adopters per-key access control, rotation governance, and a
        crypto-shred option for log data (API access logs contain caller IPs,
        user agents, and origins).

        NOTE: CDK's default key policy grants the account root principal key
        administration. In production, scope key administration to a specific
        deployment/admin role.
        """
        self.data_key = kms.Key(
            self,
            "CorsPatternDataKey",
            description="Encrypts CloudWatch Logs and Lambda env vars for the CORS pattern.",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.DESTROY,  # sample tear-down; RETAIN in production
            pending_window=Duration.days(7),
        )
        # CloudWatch Logs must be allowed to use the key, scoped by encryption
        # context to log groups in this account and Region only.
        self.data_key.add_to_resource_policy(
            iam.PolicyStatement(
                principals=[iam.ServicePrincipal(f"logs.{Aws.REGION}.amazonaws.com")],
                actions=[
                    "kms:Encrypt*",
                    "kms:Decrypt*",
                    "kms:ReEncrypt*",
                    "kms:GenerateDataKey*",
                    "kms:Describe*",
                ],
                resources=["*"],  # in a key policy, "*" refers to this key only
                conditions={
                    "ArnLike": {
                        "kms:EncryptionContext:aws:logs:arn": (
                            f"arn:{Aws.PARTITION}:logs:{Aws.REGION}:"
                            f"{Aws.ACCOUNT_ID}:log-group:*"
                        )
                    }
                },
            )
        )

    # ------------------------------------------------------------------ AppConfig
    def _build_appconfig(self) -> None:
        with open(os.path.join(_APPCONFIG_DIR, "cors-config.json")) as fh:
            config_content = fh.read()
        with open(os.path.join(_APPCONFIG_DIR, "cors-config.schema.json")) as fh:
            schema_content = fh.read()

        self.app = appconfig.CfnApplication(
            self, "CorsApplication", name="cors-security-headers"
        )
        self.cors_environment = appconfig.CfnEnvironment(
            self,
            "CorsEnvironment",
            application_id=self.app.ref,
            name="production",
        )

        # Lambda validator (semantic checks beyond JSON Schema).
        self.validator_fn = self._build_validator_fn()

        self.profile = appconfig.CfnConfigurationProfile(
            self,
            "CorsProfile",
            application_id=self.app.ref,
            name="cors-config",
            location_uri="hosted",
            validators=[
                appconfig.CfnConfigurationProfile.ValidatorsProperty(
                    type="JSON_SCHEMA", content=schema_content
                ),
                appconfig.CfnConfigurationProfile.ValidatorsProperty(
                    type="LAMBDA", content=self.validator_fn.function_arn
                ),
            ],
        )

        self.hosted_version = appconfig.CfnHostedConfigurationVersion(
            self,
            "CorsHostedVersion",
            application_id=self.app.ref,
            configuration_profile_id=self.profile.ref,
            content=config_content,
            content_type="application/json",
        )

        # Gradual rollout: bake time + growth so a bad config is caught mid-deploy.
        self.deploy_strategy = appconfig.CfnDeploymentStrategy(
            self,
            "CorsDeployStrategy",
            name="cors-gradual-rollout",
            deployment_duration_in_minutes=5,
            final_bake_time_in_minutes=2,
            growth_factor=25,
            growth_type="LINEAR",
            replicate_to="NONE",
        )

        # AppConfig must be allowed to invoke the Lambda validator.
        self.validator_fn.add_permission(
            "AllowAppConfigInvoke",
            principal=iam.ServicePrincipal("appconfig.amazonaws.com"),
            action="lambda:InvokeFunction",
        )

        # Actually deploy the hosted config version to the environment, so the
        # extension can serve it. Without this the profile has no active
        # deployment and GetLatestConfiguration returns empty (deny-all).
        self.deployment = appconfig.CfnDeployment(
            self,
            "CorsDeployment",
            application_id=self.app.ref,
            environment_id=self.cors_environment.ref,
            configuration_profile_id=self.profile.ref,
            configuration_version=self.hosted_version.ref,
            deployment_strategy_id=self.deploy_strategy.ref,
        )
        # The deployment runs the Lambda validator; ensure invoke permission and
        # the config version exist first.
        self.deployment.node.add_dependency(self.hosted_version)

    def _build_validator_fn(self) -> lambda_.Function:
        log_group = logs.LogGroup(
            self,
            "ValidatorLogGroup",
            retention=logs.RetentionDays.ONE_MONTH,
            encryption_key=self.data_key,
            removal_policy=RemovalPolicy.DESTROY,
        )
        return lambda_.Function(
            self,
            "ConfigValidator",
            runtime=lambda_.Runtime.PYTHON_3_14,
            handler="validator.handler",
            code=lambda_.Code.from_asset(
                os.path.join(os.path.dirname(__file__), "..", "src", "config_validator")
            ),
            timeout=Duration.seconds(10),
            memory_size=128,
            log_group=log_group,
            description="AppConfig Lambda validator: rejects unsafe CORS configs.",
        )

    # ------------------------------------------------------------- API handler fn
    def _build_api_handler(self) -> None:
        region = Stack.of(self).region
        extension_arn = APPCONFIG_EXTENSION_LAYER_ARNS.get(region)
        if extension_arn is None:
            raise ValueError(
                f"No AppConfig extension layer ARN configured for region {region!r}. "
                "Add it to APPCONFIG_EXTENSION_LAYER_ARNS."
            )
        extension_layer = lambda_.LayerVersion.from_layer_version_arn(
            self, "AppConfigExtensionLayer", extension_arn
        )

        self.handler_log_group = logs.LogGroup(
            self,
            "ApiHandlerLogGroup",
            retention=logs.RetentionDays.ONE_MONTH,
            encryption_key=self.data_key,
            removal_policy=RemovalPolicy.DESTROY,
        )

        handler_src = os.path.join(
            os.path.dirname(__file__), "..", "src", "api_handler"
        )
        self.api_fn = lambda_.Function(
            self,
            "ApiHandler",
            runtime=lambda_.Runtime.PYTHON_3_14,
            handler="handler.lambda_handler",
            code=lambda_.Code.from_asset(
                handler_src,
                bundling=BundlingOptions(
                    image=lambda_.Runtime.PYTHON_3_14.bundling_image,
                    local=LocalPipBundling(os.path.abspath(handler_src)),
                    command=[
                        "bash",
                        "-c",
                        "pip install -r requirements.txt -t /asset-output "
                        "&& cp -au . /asset-output",
                    ],
                ),
            ),
            timeout=Duration.seconds(10),
            memory_size=256,
            layers=[extension_layer],
            log_group=self.handler_log_group,
            tracing=lambda_.Tracing.ACTIVE,
            environment={
                # Only non-sensitive AppConfig coordinates live here -- never the
                # allowlist or header policy themselves.
                "APPCONFIG_APPLICATION": self.app.ref,
                "APPCONFIG_ENVIRONMENT": self.cors_environment.ref,
                "APPCONFIG_PROFILE": self.profile.ref,
                "APPCONFIG_CACHE_SECONDS": "45",
                "POWERTOOLS_SERVICE_NAME": "cors-pattern",
                "POWERTOOLS_LOG_LEVEL": "INFO",
            },
            environment_encryption=self.data_key,
            description="API handler enforcing dynamic CORS + security headers.",
        )
        self.data_key.grant_decrypt(self.api_fn)

        # Least-privilege: only read THIS profile's configuration, nothing else.
        self.api_fn.add_to_role_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "appconfig:StartConfigurationSession",
                    "appconfig:GetLatestConfiguration",
                ],
                resources=[
                    f"arn:{Aws.PARTITION}:appconfig:{Aws.REGION}:{Aws.ACCOUNT_ID}:"
                    f"application/{self.app.ref}/environment/{self.cors_environment.ref}/"
                    f"configuration/{self.profile.ref}"
                ],
            )
        )

    # ----------------------------------------------------------------- REST API
    def _build_rest_api(self) -> None:
        access_log_group = logs.LogGroup(
            self,
            "ApiAccessLogs",
            retention=logs.RetentionDays.ONE_MONTH,
            encryption_key=self.data_key,
            removal_policy=RemovalPolicy.DESTROY,
        )

        self.api = apigw.RestApi(
            self,
            "CorsPatternApi",
            rest_api_name="dynamic-cors-pattern",
            description="REST API demonstrating dynamic CORS + security headers.",
            # CORS is intentionally handled in the Lambda (dynamic), NOT here.
            deploy_options=apigw.StageOptions(
                stage_name="prod",
                access_log_destination=apigw.LogGroupLogDestination(access_log_group),
                access_log_format=apigw.AccessLogFormat.json_with_standard_fields(
                    caller=True,
                    http_method=True,
                    ip=True,
                    protocol=True,
                    request_time=True,
                    resource_path=True,
                    response_length=True,
                    status=True,
                    user=True,
                ),
                logging_level=apigw.MethodLoggingLevel.INFO,
                metrics_enabled=True,
                tracing_enabled=True,
            ),
            endpoint_configuration=apigw.EndpointConfiguration(
                types=[apigw.EndpointType.REGIONAL]
            ),
            # Enforce TLS via a resource policy denying non-secure transport.
            policy=iam.PolicyDocument(
                statements=[
                    iam.PolicyStatement(
                        effect=iam.Effect.ALLOW,
                        principals=[iam.AnyPrincipal()],
                        actions=["execute-api:Invoke"],
                        resources=["execute-api:/*"],
                    ),
                    iam.PolicyStatement(
                        effect=iam.Effect.DENY,
                        principals=[iam.AnyPrincipal()],
                        actions=["execute-api:Invoke"],
                        resources=["execute-api:/*"],
                        conditions={"Bool": {"aws:SecureTransport": "false"}},
                    ),
                ]
            ),
        )

        integration = apigw.LambdaIntegration(self.api_fn, proxy=True)

        # Basic request validation at the edge (validates params + body) before
        # any request reaches the Lambda.
        validator = self.api.add_request_validator(
            "BasicRequestValidator",
            validate_request_body=True,
            validate_request_parameters=True,
        )

        # Every data method requires AWS_IAM authorization -- the API is never open.
        resource = self.api.root.add_resource("hello")
        self.data_methods = []
        for method in ("GET", "POST"):
            self.data_methods.append(
                resource.add_method(
                    method,
                    integration,
                    authorization_type=apigw.AuthorizationType.IAM,
                    request_validator=validator,
                )
            )
        # Preflight OPTIONS is unauthenticated (browsers cannot sign it) and is
        # answered by the Lambda middleware with a 204 + CORS headers.
        self.options_method = resource.add_method(
            "OPTIONS",
            integration,
            authorization_type=apigw.AuthorizationType.NONE,
            request_validator=validator,
        )

    # --------------------------------------------------------------------- WAF
    def _build_waf(self) -> None:
        self.web_acl = wafv2.CfnWebACL(
            self,
            "CorsPatternWebAcl",
            scope="REGIONAL",
            default_action=wafv2.CfnWebACL.DefaultActionProperty(allow={}),
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name="corsPatternWebAcl",
                sampled_requests_enabled=True,
            ),
            rules=[
                wafv2.CfnWebACL.RuleProperty(
                    name="AWSManagedCommonRules",
                    priority=0,
                    override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
                    statement=wafv2.CfnWebACL.StatementProperty(
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            vendor_name="AWS",
                            name="AWSManagedRulesCommonRuleSet",
                        )
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name="commonRules",
                        sampled_requests_enabled=True,
                    ),
                ),
                wafv2.CfnWebACL.RuleProperty(
                    name="RateLimit",
                    priority=1,
                    action=wafv2.CfnWebACL.RuleActionProperty(block={}),
                    statement=wafv2.CfnWebACL.StatementProperty(
                        rate_based_statement=wafv2.CfnWebACL.RateBasedStatementProperty(
                            limit=2000, aggregate_key_type="IP"
                        )
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name="rateLimit",
                        sampled_requests_enabled=True,
                    ),
                ),
            ],
        )

        stage_arn = (
            f"arn:{Aws.PARTITION}:apigateway:{Aws.REGION}::/restapis/"
            f"{self.api.rest_api_id}/stages/{self.api.deployment_stage.stage_name}"
        )
        self.waf_association = wafv2.CfnWebACLAssociation(
            self,
            "WebAclAssociation",
            resource_arn=stage_arn,
            web_acl_arn=self.web_acl.attr_arn,
        )
        self.waf_association.node.add_dependency(self.api)

    # ----------------------------------------------------------------- Outputs
    def _emit_outputs(self) -> None:
        CfnOutput(self, "ApiUrl", value=self.api.url)
        CfnOutput(self, "AppConfigApplicationId", value=self.app.ref)
        CfnOutput(self, "AppConfigEnvironmentId", value=self.cors_environment.ref)
        CfnOutput(self, "AppConfigProfileId", value=self.profile.ref)
        CfnOutput(self, "DeploymentStrategyId", value=self.deploy_strategy.ref)

    # ------------------------------------------------------ cdk-nag suppressions
    def _apply_nag_suppressions(self) -> None:
        """Justified suppressions for intentional design choices.

        Every entry documents *why* the finding is acceptable, which is the
        transparent way cdk-nag is meant to be used: fix what is fixable, and
        record evidence for what is deliberate.
        """
        # python3.14 is the newest GA Lambda Python runtime; python3.15 is public
        # preview only, so cdk-nag's "latest runtime" check is intentionally
        # suppressed. Move to the newer runtime once it is GA.
        for fn in (self.validator_fn, self.api_fn):
            NagSuppressions.add_resource_suppressions(
                fn,
                [
                    {
                        "id": "AwsSolutions-L1",
                        "reason": "python3.14 is the latest GA Lambda Python runtime "
                        "(deprecation Jun 30, 2029); python3.15 is public preview only.",
                    }
                ],
            )

        # Lambda execution roles use the AWS-managed basic-execution policy,
        # which grants only CloudWatch Logs write access -- the AWS-recommended
        # minimal logging baseline for Lambda.
        for path in (
            f"/{self.stack_name}/ConfigValidator/ServiceRole/Resource",
            f"/{self.stack_name}/ApiHandler/ServiceRole/Resource",
        ):
            NagSuppressions.add_resource_suppressions_by_path(
                self,
                path,
                [
                    {
                        "id": "AwsSolutions-IAM4",
                        "reason": "AWSLambdaBasicExecutionRole grants only CloudWatch "
                        "Logs write access, the AWS-recommended minimal logging "
                        "baseline for Lambda.",
                        "appliesTo": [
                            "Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                        ],
                    }
                ],
            )

        # API Gateway's account-level CloudWatch role uses the AWS-managed
        # push-to-CloudWatch policy required to publish access/execution logs.
        NagSuppressions.add_resource_suppressions_by_path(
            self,
            f"/{self.stack_name}/CorsPatternApi/CloudWatchRole/Resource",
            [
                {
                    "id": "AwsSolutions-IAM4",
                    "reason": "AWS-managed policy required for API Gateway to publish "
                    "logs to CloudWatch; grants only logging actions.",
                    "appliesTo": [
                        "Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
                    ],
                }
            ],
        )

        # The only wildcard resource in the handler role comes from AWS X-Ray
        # tracing actions, which do not support resource-level permissions.
        NagSuppressions.add_resource_suppressions_by_path(
            self,
            f"/{self.stack_name}/ApiHandler/ServiceRole/DefaultPolicy/Resource",
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "X-Ray actions (PutTraceSegments, PutTelemetryRecords, "
                    "GetSampling*) do not support resource-level permissions and "
                    "require Resource:'*' per AWS documentation.",
                    "appliesTo": ["Resource::*"],
                }
            ],
        )

        # Data methods intentionally use AWS_IAM authorization (a Well-Architected
        # option), not Cognito. Cognito is offered as an optional variant.
        for m in self.data_methods:
            NagSuppressions.add_resource_suppressions(
                m,
                [
                    {
                        "id": "AwsSolutions-COG4",
                        "reason": "This pattern authorizes with AWS_IAM (SigV4), a "
                        "valid Well-Architected choice; Cognito is an optional variant.",
                    }
                ],
            )

        # The preflight OPTIONS method is intentionally unauthenticated: browsers
        # cannot sign a CORS preflight, and it returns no data (204 + headers).
        NagSuppressions.add_resource_suppressions(
            self.options_method,
            [
                {
                    "id": "AwsSolutions-APIG4",
                    "reason": "CORS preflight (OPTIONS) must be unauthenticated per the "
                    "Fetch/CORS spec and returns no data; all data methods require "
                    "AWS_IAM.",
                },
                {
                    "id": "AwsSolutions-COG4",
                    "reason": "Preflight OPTIONS cannot use a Cognito authorizer; it is "
                    "unauthenticated by CORS design and returns no data.",
                },
            ],
        )
