# Security Policy

## Reporting a vulnerability

If you discover a potential security issue in this project, please notify
AWS/Amazon Security via the
[vulnerability reporting page](https://aws.amazon.com/security/vulnerability-reporting/)
or by email to **aws-security@amazon.com**. Please do **not** create a public
issue, pull request, or discussion.

## Non-production sample

This is sample code for **non-production** usage. Work with your security and
legal teams to meet your organization's security, regulatory, and compliance
requirements before deploying it. Test, secure, and optimize it as appropriate
for production-grade use based on your own quality-control practices.

## Security posture

The pattern is secure by default:

- **AWS_IAM authorization** on all data methods (no open API); preflight `OPTIONS`
  is unauthenticated by design and returns no data.
- **AWS WAF** (AWS managed common rule set + rate-based rule) on the API stage.
- **TLS enforced** (API Gateway resource policy denies non-TLS; CloudFront HTTPS-only, TLS 1.2+).
- **Least-privilege IAM** — the handler role can read only its one AppConfig profile ARN.
- **Deny-safe CORS** — on a cold-cache AppConfig failure the middleware denies all
  origins (never fails open); it never emits `*` and never pairs
  `Access-Control-Allow-Credentials: true` with a wildcard.
- **Validated configuration** — JSON Schema + Lambda validators reject unsafe
  config (wildcards, non-HTTPS) before deployment; gradual rollout with bake
  time. For production, attach a CloudWatch alarm as an AppConfig environment
  monitor so a bad rollout is reverted automatically.
- **cdk-nag** (AWS Solutions) runs at synth and fails the build on unaddressed
  findings; intentional deviations are suppressed with documented evidence.

## Accepted trade-offs and production hardening

These are intentional simplifications for a **sample**. Harden them before
production use:

### Encryption at rest (customer-managed KMS key)

The stack creates a **customer-managed AWS KMS key** (`CorsPatternDataKey`,
automatic rotation enabled) that encrypts:

- all three CloudWatch log groups (validator, API handler, API access logs), and
- the API handler Lambda's environment variables.

The key policy allows `logs.<region>.amazonaws.com` to use the key only for log
groups in the same account and Region (encryption-context condition), and the
API handler's execution role is granted `kms:Decrypt`.

For production:

- **Scope key administration.** CDK's default key policy grants the account root
  principal key administration. Restrict key admin to a specific deployment or
  security role.
- **Retain the key.** The sample uses `RemovalPolicy.DESTROY` (7-day pending
  window) so `cdk destroy` cleans up. Use `RemovalPolicy.RETAIN` in production so
  encrypted logs remain readable.

### Dependency vulnerability scanning

Pinned dependency versions do not self-remediate. Run a dependency-CVE scan
regularly, e.g.:

```bash
pip-audit -r requirements.txt -r src/api_handler/requirements.txt
```

and/or rely on your pipeline's dependency scanner.

### Other production hardening

- **CloudFront demo:** uses the default `*.cloudfront.net` certificate; use a
  custom domain with a TLS 1.2_2021 security policy, and add AWS WAF to the
  CloudFront distribution.
- **DDoS:** consider AWS Shield Advanced for internet-facing production APIs.
- **Authorization:** IAM auth is the default; adopt Cognito or a custom authorizer
  as your identity model requires.
- **Lambda runtime:** both functions use `python3.14`, the newest GA Lambda Python
  runtime. cdk-nag `AwsSolutions-L1` is suppressed because `python3.15` is public
  preview only; move to the newer runtime once it is GA.
