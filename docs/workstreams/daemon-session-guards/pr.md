# feat(control): guard daemon mutations by instance and session

Closes #82

Issue: https://github.com/bimeron/bimeron-core/issues/82.
Branch: `feat/daemon-session-guards-publication`.
Publication is authorized; the parent handles push and pull request creation.
Merge, release, and live acceptance require separate approval.

A stale GUI command could affect a restarted daemon or a replacement session.
Advertise `daemon_session_guards` in daemon hello/version responses and check
start/stop instance/session preconditions under the existing command admission
mutex. Rejections include authoritative instance/status and never mutate the
engine. Capture semantic rejection snapshots under admission, including early
validation failures. Reject ambiguous JSON and Unicode field aliases to prevent
guards from being erased during decode.

Legacy CLI requests remain unguarded and legacy stop remains idempotent. Guarded
shutdown is rejected; existing administrative shutdown cleanup is preserved.
Windows foreground control is unchanged. See [contract.md](contract.md) for exact
JSON casing, errors, retry rules, and remaining compatibility/security limits.

Tests use fake engines and in-memory RPC connections; they never open a tunnel.
Existing Go CI already runs internal/control unit tests and core/control race
checks. Local validation results are recorded below before committing.

## Local validation

Review used the cached Go 1.26.9 binary directly with `GOTOOLCHAIN=local`,
`GOPROXY=off`, and `GOSUMDB=off`; no downloads or remote operations.
All final commands below exited 0:

- `go test ./internal/control -skip '^TestStopKeepsDaemonAndShutdownExits$' -count=1`: passed (`0.675s`).
- `CGO_ENABLED=1 go test -race ./internal/control -skip '^TestStopKeepsDaemonAndShutdownExits$' -count=1`: passed (`1.748s`).
- `go test ./internal/control -run '^TestDaemon(SessionGuards|ConcurrentGuardAdmission|GuardWireContract|GuardRejectionSnapshotAdmission)$' -count=50`: passed (`0.949s`).
- `go vet ./internal/control ./cmd/bimeron`: passed.
- `go test ./cmd/bimeron -run '^Test(Doctor.*|ConfigFlagsRejectAmbiguousOverrides|ModeIsCheckedBeforeNetwork)$' -count=1`: passed (`1.147s`).
- `go test ./cmd/bimeron -run '^$'`: passed (`0.686s`, compile only).
- `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o /tmp/bimeron-guards-review-linux.test ./internal/control`: passed (compile only).
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go test -c -o /tmp/bimeron-guards-review-windows.test.exe ./internal/control`: passed (compile only).
- `git diff --check`: passed.

Both added regression cases failed before their fixes: early rejection snapshots
escaped admission, and Unicode `inſtance: null` was accepted as an unguarded stop.
Temporary cross-compile binaries were removed.

The TCP control lifecycle test was excluded to honor the no-networking constraint;
control tests still exercised in-memory RPC and local Unix IPC. CLI execution was
limited to the listed network-free tests. Full repository/core race suites, live
interoperability, privileged acceptance, and remote CI were not run. No dependencies
or CI configuration changed.
