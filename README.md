# aws-cred-trace

`aws-cred-trace` is a CLI that explains which AWS credentials are selected, which alternatives are not selected, and why. It reports credential sources and decisions without printing credential material.

## Who it is for

- Developers who switch between multiple AWS profiles
- Operators diagnosing conflicts between environment variables and shared AWS files
- Anyone verifying that the effective AWS identity matches their intent

## Project status

Version 0.2.0 is available from [GitHub Releases](https://github.com/k-taketani-job/aws-cred-trace/releases).

Version 0.2.0 adds modern `sso_session` and legacy inline IAM Identity Center / SSO profiles to the existing environment, shared-file, profile-selection, reasoning, and optional STS verification support. Complex AssumeRole chains and full `credential_process` support remain deferred.

## Supported platforms

`aws-cred-trace` officially supports Windows, macOS, and Linux. CLI commands, status names, reasons, exit codes, and output structure are intended to remain consistent across all three platforms. Platform-specific shell behavior is not required.

## Installation

Download the binary for your platform from [GitHub Releases](https://github.com/k-taketani-job/aws-cred-trace/releases), then run it directly:

```powershell
.\aws-cred-trace_windows_amd64.exe inspect --no-sts
```

```console
chmod +x aws-cred-trace_darwin_arm64
./aws-cred-trace_darwin_arm64 inspect --no-sts
```

```console
chmod +x aws-cred-trace_linux_amd64
./aws-cred-trace_linux_amd64 inspect --no-sts
```

Alternatively, install with Go:

```console
go install github.com/k-taketani-job/aws-cred-trace@latest
```

Each release includes `checksums.txt`. Verify the downloaded binary with `Get-FileHash` on Windows, `shasum -a 256 -c checksums.txt` on macOS, or `sha256sum -c checksums.txt` on Linux.

Release binaries also include GitHub Artifact Attestations. Verify provenance with GitHub CLI:

```console
gh attestation verify <artifact> --repo k-taketani-job/aws-cred-trace
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
