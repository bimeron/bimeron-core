# PR draft: feat(control): guard daemon mutations by instance and session

Status: local draft; no pull request created or pushed.

A stale GUI command could affect a restarted daemon or a replacement session.
Advertise `daemon_session_guards` in daemon hello/version responses and check
start/stop instance/session preconditions under the existing command admission
mutex. Rejections include authoritative instance/status and never mutate the
engine. Reject ambiguous JSON to prevent guards from being erased during decode.

Legacy CLI requests remain unguarded and legacy stop remains idempotent. Guarded
shutdown is rejected; existing administrative shutdown cleanup is preserved.
Windows foreground control is unchanged. See [contract.md](contract.md) for exact
JSON casing, errors, retry rules, and remaining compatibility/security limits.

Tests use fake engines and in-memory RPC connections; they never open a tunnel.
Existing Go CI already runs internal/control unit tests and core/control race
checks. Local validation results are recorded below before committing.

## Local validation

Using the cached Go 1.26.9 binary directly with `GOTOOLCHAIN=local`,
`GOPROXY=off`, and `GOSUMDB=off` (no downloads):

- `go test ./internal/control -count=1` passed.
- `CGO_ENABLED=1 go test -race ./internal/control -count=1` passed.
- `go test ./internal/control -run '^TestDaemon(SessionGuards|ConcurrentGuardAdmission|GuardWireContract)$' -count=50` passed.
- `go vet ./internal/control ./cmd/bimeron` passed.
- `go test ./cmd/bimeron -run '^$'` passed (compile only).
- Linux amd64 and Windows amd64 `CGO_ENABLED=0 go test -c ./internal/control` passed (compile only; temporary binaries removed).
- `git diff --check` passed.

The initial ordinary Go launcher attempt could not verify its toolchain with
checksum lookup disabled; using the already installed pinned binary resolved it.
Full repository/live interoperability suites, privileged integration, and remote
CI were intentionally not run. No dependencies or CI configuration changed.
