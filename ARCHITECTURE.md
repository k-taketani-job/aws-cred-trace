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
- **Analyzer:** reads environment settings and shared files, applies the limited rules in [SPEC.md](SPEC.md), and produces `selected`, `shadowed`, or `ignored` reasons. It uses the AWS SDK's default shared-file path functions and native path handling.
- **Credential construction:** reloads only the selected supported static source for STS use. It does not invoke unsupported providers or metadata endpoints.
- **Identity verifier:** optionally calls `GetCallerIdentity` and reduces failures to safe categories.
- **Formatters:** analysis and identity packages render stable English output without credential material.

Keep local analysis separate from network calls so precedence tests require no AWS access. Keep platform differences inside path resolution; analysis and rendering remain platform-neutral. Do not introduce general-purpose frameworks or speculative interfaces in v0.1.
