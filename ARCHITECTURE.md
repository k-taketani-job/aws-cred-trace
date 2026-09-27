# Architecture

v0.1 is a single Go CLI binary. Components should remain small and concrete until more than one implementation is required.

```text
Cobra command
  -> analyzer (environment + shared files + profile + candidate states)
  -> supported credential provider construction
  -> identity verifier (optional STS call + safe error classification)
  -> package-level text formatters
```

- **Command:** validates arguments, invokes the flow, and maps failures to exit codes.
- **Analyzer:** reads environment settings and shared files, applies the limited rules in [SPEC.md](SPEC.md), and produces `selected`, `shadowed`, or `ignored` reasons. It recognizes modern and legacy SSO configuration and one-hop `role_arn` / `source_profile` chains without retrieving credentials or reading cached token contents.
- **Credential construction:** reloads only the selected static, SSO, or supported AssumeRole profile for STS use. SSO and AssumeRole credential handling is delegated to AWS SDK for Go v2, SDK errors are sanitized, and EC2 metadata access is explicitly disabled.
- **Identity verifier:** optionally calls `GetCallerIdentity` and reduces failures to safe categories.
- **Formatters:** analysis and identity packages render stable English output without credential material.

Keep local analysis separate from network calls so precedence and chain tests require no AWS access. The analyzer rejects nested or cyclic role chains before credential construction; a direct source profile is represented as a separate finding rather than flattened into the role result. With `--no-sts`, stop after local analysis and do not construct or retrieve credentials. Keep platform differences inside path resolution; analysis and rendering remain platform-neutral. Do not introduce general-purpose frameworks or speculative interfaces.
