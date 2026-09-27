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

## After v0.1: Provider expansion

- Trace AWS IAM Identity Center / SSO selection and session state
- Trace AssumeRole and `source_profile` chains
- Diagnose `credential_process` safely
- Add Web Identity, ECS, and EC2 Instance Metadata analysis

## Later candidates

- JSON output
- More granular machine-readable exit codes

Priorities may change after v0.1 behavior and security guarantees are validated.
