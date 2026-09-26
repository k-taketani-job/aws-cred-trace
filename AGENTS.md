# aws-cred-trace Development Rules

## Purpose and v0.1

`aws-cred-trace` is a Go CLI that explains which AWS credentials are selected and why. It uses Cobra and AWS SDK for Go v2.

v0.1 covers environment credentials, `~/.aws/config`, `~/.aws/credentials`, profile resolution, `selected` / `shadowed` / `ignored` reasons, and effective identity verification with `sts:GetCallerIdentity`. Full SSO, complex AssumeRole, and full `credential_process` support are deferred.

## Working rules

- Read only files and settings directly required by the task. Do not explore the entire repository without cause.
- Prefer existing code and patterns, and keep changes to the minimum requested scope.
- Do not perform unrelated refactoring, premature abstraction, or unnecessary dependency additions.
- Run only relevant tests unless wider validation is justified.
- Do not create unnecessary documentation; keep explanations concise.
- Do not make unsolicited improvements after completing the task.
- Limit repeated reads, output, and investigation to conserve tokens and context.
- Keep Go code idiomatic, focused, and simple; remove dead code and unused dependencies.
- Document exported APIs where appropriate. Comments should explain intent or constraints, not restate code.
- Handle errors explicitly and do not suppress lint findings without a documented reason.
- Never log or expose AWS credentials, tokens, secrets, or sensitive configuration values.
