Runtime sources and the BSD-3-Clause license were copied from github.com/tailscale/wf at commit 6fbb0a674ee6 (v0.0.0-20240214030419-6fbb0a674ee6).

Bimeron adds only `transaction.go`, exposing upstream native WFP transaction calls. This allows atomic replacement and removal of the persistent kill switch. Upstream tools, CLI, generators, and tests are not included. Other runtime sources are unchanged. The module lists only runtime dependencies.
