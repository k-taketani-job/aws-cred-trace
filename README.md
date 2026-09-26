# aws-cred-trace

`aws-cred-trace` is a CLI that explains which AWS credentials are selected, which alternatives are not selected, and why. It reports credential sources and decisions without printing credential material.

## Who it is for

- Developers who switch between multiple AWS profiles
- Operators diagnosing conflicts between environment variables and shared AWS files
- Anyone verifying that the effective AWS identity matches their intent

## Project status

The local-analysis and optional STS identity-verification slices are implemented but not released.

The planned v0.1 scope covers environment credentials, `~/.aws/config`, `~/.aws/credentials`, profile resolution through `--profile`, `AWS_PROFILE`, `AWS_DEFAULT_PROFILE`, or `default`, `selected` / `shadowed` / `ignored` reasoning, and effective identity verification with `sts:GetCallerIdentity`. Full SSO, complex AssumeRole chains, and full `credential_process` support are deferred.

## Supported platforms

`aws-cred-trace` officially supports Windows, macOS, and Linux. CLI commands, status names, reasons, exit codes, and output structure are intended to remain consistent across all three platforms. Platform-specific shell behavior is not required.

## Expected installation

The first release is expected to provide GitHub release binaries and Go installation after the module path and version are published:

```console
go install github.com/k-taketani-job/aws-cred-trace@v0.1.0
```

## Usage

```console
aws-cred-trace inspect
aws-cred-trace inspect --profile example-profile
aws-cred-trace inspect --no-sts
```

Example output with `--no-sts`:

```text
CREDENTIAL_SOURCE_ANALYSIS
PROFILE_SOURCE  AWS_PROFILE
STATUS    SOURCE              TYPE                 REASON
selected  environment         static               complete static credential pair
shadowed  shared-credentials  static               environment credentials take precedence
ignored   shared-config       static               no supported static credentials

IDENTITY_VERIFICATION
STATUS   skipped
REASON   STS verification disabled
```

Credential values, profile names, and secret material are never printed. When STS verification is enabled, only the effective Account ID and ARN are added to the output. See [SPEC.md](SPEC.md).

## References

- [Configure the AWS SDK for Go v2](https://docs.aws.amazon.com/sdk-for-go/v2/developer-guide/configure-gosdk.html)
- [AWS shared config and credentials files](https://docs.aws.amazon.com/sdkref/latest/guide/file-format.html)
- [STS GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html)

## Development

See [DEVELOPMENT.md](DEVELOPMENT.md) for local setup, validation commands, and contribution requirements.

## License

MIT
