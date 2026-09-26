# Development

## Prerequisites

- Go 1.25.13 or later
- Git

Install the pinned quality tools:

```console
go install honnef.co/go/tools/cmd/staticcheck@v0.7.0
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0
go install golang.org/x/vuln/cmd/govulncheck@v1.8.0
```

Ensure the Go binary installation directory reported by `go env GOBIN` or `go env GOPATH` is available on `PATH`.

## Local validation

Run these commands from the repository root:

```console
go fmt ./...
go build ./...
go vet ./...
go test ./...
staticcheck ./...
golangci-lint run ./...
govulncheck ./...
```

`go fmt ./...` updates formatting. Before committing, `gofmt -l` must produce no file names for changed Go files. `govulncheck` queries the Go vulnerability database and therefore requires network access.

## Code quality and security

- Write idiomatic, focused Go and prefer simple code over abstractions.
- Remove dead code and unused dependencies.
- Add GoDoc comments to exported APIs when they are appropriate.
- Use comments for intent, constraints, or non-obvious behavior, not to restate code.
- Handle errors explicitly.
- Do not suppress lint findings without documenting the reason next to the suppression.
- Never log, print, or expose AWS credentials, tokens, secrets, or sensitive configuration values.

## Contribution workflow

1. Keep each change limited to the requested behavior.
2. Add or update focused tests.
3. Run the local validation commands.
4. Review `git diff` and the staged file list for secrets, local AWS files, build outputs, and unrelated changes.
5. Commit only after all checks pass.

CI builds and tests on Windows, macOS, and Linux. Formatting, vet, lint, and vulnerability checks run once on Linux to avoid duplicating expensive work.
