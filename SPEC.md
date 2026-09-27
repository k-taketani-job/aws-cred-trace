# Specification

## Inputs

The planned command is:

```console
aws-cred-trace inspect [--profile NAME] [--no-sts]
```

v0.1 reads only:

- `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and optional `AWS_SESSION_TOKEN`
- `AWS_PROFILE`, `AWS_DEFAULT_PROFILE`, `AWS_CONFIG_FILE`, and `AWS_SHARED_CREDENTIALS_FILE`
- `AWS_REGION` and `AWS_DEFAULT_REGION`, only for SDK region resolution required by STS
- The shared config file, defaulting to `~/.aws/config`
- The shared credentials file, defaulting to `~/.aws/credentials`
- `--profile` and `--no-sts`

Shared files are read-only. Credential values must not enter user-facing output.

## Supported platforms and paths

v0.1 officially supports Windows, macOS, and Linux.

- Use the AWS SDK for Go v2 default shared-file path functions so path resolution matches the SDK: `$HOME/.aws/...` on macOS/Linux and `%USERPROFILE%\.aws\...` on Windows.
- Honor `AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE` with host-native path semantics.
- Do not require Bash, PowerShell, Command Prompt, or another specific shell.
- Keep commands, state names, reasons, output fields, and exit codes consistent across supported platforms. Filesystem paths may use native separators.

## Profile and credential precedence

These rules describe the default AWS SDK for Go v2 behavior within the v0.1 scope:

1. `--profile` is an explicit programmatic profile selection. It takes precedence over environment credentials because it is supplied to the SDK as an explicit configuration option.
2. Without `--profile`, a complete environment credential takes precedence. It requires `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`; `AWS_SESSION_TOKEN` is optional. A partial environment pair is ignored by AWS SDK for Go v2.
3. The profile inspected for shared-file settings is `--profile`, otherwise `AWS_PROFILE`, otherwise `AWS_DEFAULT_PROFILE`, otherwise `default`. If both profile environment variables are set, `AWS_PROFILE` wins. The `default` profile does not provide inherited values to a named profile.
4. When shared-file credentials are eligible, values from the credentials file take precedence over conflicting values from the config file for the same profile. Each file must contain a complete access-key and secret-key pair; pairs are not assembled across files.
5. Use AWS SDK for Go v2 path resolution and shared-file parsing as confirmation. Normalize the result into stable tool-defined source labels; do not expose SDK-internal type names as a stable CLI contract.

With `--profile`, complete environment credentials are `ignored` because the explicit SDK profile option takes precedence. Without `--profile`, complete environment credentials are `selected` before credentials from the profile named by `AWS_PROFILE` or `AWS_DEFAULT_PROFILE`.

Each discovered candidate receives one state:

- `selected`: a supported candidate determined as effective after SDK parsing validates the static credential pair
- `shadowed`: a complete supported candidate that cannot win because a known higher-precedence candidate was selected
- `ignored`: a discovered value that is ineligible, such as a partial environment pair or a candidate from a non-selected profile

Do not label a candidate `selected` or `shadowed` merely because it is configured; validity may require retrieval. A partial static credential pair in either shared file is a configuration error, not an `ignored` candidate.

SSO, AssumeRole, `credential_process`, Web Identity, ECS, and EC2 Instance Metadata providers are reported separately as unsupported in v0.1. If an unsupported provider would be required to obtain effective credentials, stop before SDK credential retrieval or STS; in particular, v0.1 must not execute `credential_process` or trigger metadata requests. If a supported higher-precedence candidate is selected, report the unsupported setting as not evaluated rather than claiming it is invalid.

Authoritative references:

- [AWS SDK for Go v2 credential configuration](https://docs.aws.amazon.com/sdk-for-go/v2/developer-guide/configure-gosdk.html)
- [AWS SDK for Go v2 config package precedence](https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/config)
- [Shared file profile format and precedence](https://docs.aws.amazon.com/sdkref/latest/guide/file-format.html)

## Output

Text output contains the profile selection source, candidate state/source/type/reason, and identity verification result.

```text
CREDENTIAL_SOURCE_ANALYSIS
PROFILE_SOURCE  AWS_PROFILE
STATUS    SOURCE              TYPE                 REASON
ignored   environment         static               credential variables are not set
selected  shared-credentials  static               complete static credential pair
ignored   shared-config       static               no supported static credentials

IDENTITY_VERIFICATION
STATUS   skipped
REASON   STS verification disabled
```

Documentation and test examples must use placeholders, never real credentials, Account IDs, ARNs, user IDs, usernames, or tokens.

## Identity verification

By default, the command calls `sts:GetCallerIdentity` with supported credentials resolved by the analyzer. The STS client uses the region resolved from `AWS_REGION` or `AWS_DEFAULT_REGION`; the tool does not invent a fallback region. The client makes at most two attempts. On success, runtime output shows only the returned `Account` and `Arn`. With `--no-sts`, no STS request is made and identity status is `skipped`.

## Error behavior

- A missing default shared file is treated as absent, matching the SDK. An explicitly configured path that cannot be read, or an existing file that cannot be parsed, produces a sanitized error without exposing filesystem paths; exit `1`.
- Explicit `--profile` not found, or a shared profile required for credential resolution not found: report the condition without printing the profile name; exit `1`. A missing `AWS_PROFILE` or `AWS_DEFAULT_PROFILE` target does not override otherwise selected environment credentials.
- Unsupported provider required for resolution: identify its kind without executing it; exit `1`.
- Credentials cannot be resolved: print candidate states and reasons; exit `1`.
- STS request or its SDK configuration fails: retain provider analysis, report identity as `unverified`, print a sanitized cause to standard error; exit `1`.
- Invalid CLI usage: print Cobra usage; exit `2`.

Errors, debug output, and termination messages must not contain credential values or tokens.

## Security considerations

- Never print access keys, secret keys, session tokens, or raw credential objects.
- Do not modify shared AWS files or environment variables.
- Sanitize SDK and parser errors before presenting them.
- Keep STS optional because it performs a network request and exposes caller identity in runtime output.
- Keep all repository examples fictitious and redacted.

## Non-goals

- SSO login, token refresh, or complete SSO resolution tracing
- Recursive resolution of complex AssumeRole / `source_profile` chains
- Full `credential_process` execution and tracing
- Detailed Web Identity, ECS, or EC2 Instance Metadata analysis
- Creating, updating, storing, or repairing credentials
- Exact behavioral emulation of every AWS CLI and AWS SDK version

## v0.2.0 IAM Identity Center / SSO

v0.2.0 adds analysis and credential construction for both `sso_session` profiles and legacy inline SSO profiles. The AWS SDK for Go v2 owns cached-token loading, supported token refresh, and role credential retrieval. The tool never prints cached token contents or credential values and never initiates `aws sso login`, opens a browser, or starts a login subprocess.

The existing profile and credential precedence remains unchanged. A selected profile's complete static credentials take precedence over SSO configuration. Missing or expired SSO sessions do not change the selected provider; credential retrieval and identity verification fail with a sanitized error that requires the user to run login explicitly.

For v0.2.0, `--no-sts` is a strict offline mode after local configuration analysis. It guarantees no credential retrieval, SSO token refresh, SSO role credential request, STS request, browser or subprocess login, or ECS/EC2 metadata endpoint access. SSO session validity is not checked in this mode.

## Direct AssumeRole with source_profile

The next milestone supports one AssumeRole hop when the selected profile contains both `role_arn` and `source_profile`. The direct source profile must resolve to complete static credentials in a shared file or to a supported modern or legacy SSO profile. Analysis emits a selected `assume-role` finding and a separate selected `source-profile` finding without printing either profile name, the role ARN, external IDs, MFA values, or credential material.

The existing profile selection and environment precedence rules remain unchanged. A supported higher-precedence environment or shared-credentials candidate shadows the role profile. With explicit `--profile`, environment credentials remain ignored. Actual source credential retrieval and `sts:AssumeRole` are delegated to AWS SDK for Go v2 only when identity verification is enabled; EC2 IMDS is explicitly disabled and SDK errors are sanitized.

Only a direct source profile is supported. Nested and cyclic role chains, `credential_source`, MFA prompting, Web Identity, `credential_process`, ECS credentials, and EC2 Instance Metadata credentials are rejected without executing an external provider. With `--no-sts`, analysis remains local: it does not retrieve source credentials, refresh SSO, request SSO role credentials, call AssumeRole or GetCallerIdentity, start a browser or subprocess, or access metadata endpoints.

Example local analysis:

```text
CREDENTIAL_SOURCE_ANALYSIS
PROFILE_SOURCE  --profile
STATUS    SOURCE              TYPE                 REASON
ignored   environment         static               credential variables are not set
ignored   shared-credentials  static               selected profile not found
selected  shared-config       assume-role          role_arn with direct source_profile selected
selected  source-profile      sso                  modern SSO source_profile selected

IDENTITY_VERIFICATION
STATUS   skipped
REASON   STS verification disabled
```
