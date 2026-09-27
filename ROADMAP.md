# Roadmap

## v0.1: Local static credential tracing

- Read environment credentials and shared `config` / `credentials` files
- Resolve `--profile`, `AWS_PROFILE`, `AWS_DEFAULT_PROFILE`, and `default`
- Explain `selected`, `shadowed`, and `ignored` candidates
- Confirm the provider resolved by AWS SDK for Go v2
- Verify the effective identity with `sts:GetCallerIdentity`
- Support Windows, macOS, and Linux with consistent CLI behavior
- Test that credential secrets never appear in output
- Add CI validation for `windows-latest`, `macos-latest`, and `ubuntu-latest`

## v0.2.0: IAM Identity Center / SSO

- Trace modern `sso_session` and legacy inline SSO profile selection
- Delegate cached-token refresh and role credential retrieval to AWS SDK for Go v2
- Report missing or expired sessions without exposing token or credential material
- Guarantee that `--no-sts` performs no credential retrieval or network authentication

## v0.3.0: Direct AssumeRole

- Trace one `role_arn` hop through a direct `source_profile`
- Support static, modern SSO, and legacy SSO source profiles
- Reject nested or cyclic role chains and unsupported providers safely
- Preserve the strict offline guarantees of `--no-sts`

## Later provider expansion

- Evaluate bounded nested AssumeRole chains
- Diagnose `credential_process` safely
- Add Web Identity, ECS, and EC2 Instance Metadata analysis

## Later candidates

- JSON output
- More granular machine-readable exit codes

Priorities may change after v0.1 behavior and security guarantees are validated.
