# Architecture

v0.1 is a single Go CLI binary. Components should remain small and concrete until more than one implementation is required.

```text
Cobra command
  -> input loader (environment + shared AWS files)
  -> analyzer (profile + candidate states and reasons)
  -> AWS SDK for Go v2 (effective provider + STS)
  -> text renderer (sanitization + output)
```

- **Command:** validates arguments, invokes the flow, and maps failures to exit codes.
- **Input loader:** reads environment settings and shared files without exposing secret values to presentation code. It uses the AWS SDK's default shared-file path functions and native path handling so Windows, macOS, and Linux match SDK behavior.
- **Analyzer:** applies the limited rules in [SPEC.md](SPEC.md) and produces `selected`, `shadowed`, or `ignored` reasons.
- **AWS adapter:** retrieves credentials only after analysis identifies a supported source, normalizes SDK credential-source evidence into stable labels, and optionally calls `GetCallerIdentity`. It does not invoke unsupported providers or metadata endpoints.
- **Renderer:** produces stable English output and prevents credential material from being printed.

Keep local analysis separate from network calls so precedence tests require no AWS access. Keep platform differences inside path resolution; analysis and rendering remain platform-neutral. Do not introduce general-purpose frameworks or speculative interfaces in v0.1.
