# known_hosts parser source attribution

`internal/sshtunnel/knownhosts/knownhosts.go` and its test are adapted from
`ssh/knownhosts` in golang.org/x/crypto v0.58.0.

Bimeron replaces `New`, which opens files by name, with `Parse`, which takes
file contents that the caller has already read through the bounded local file
reader. Other code and the upstream tests are unchanged. The adapted files
remain under the BSD-3-Clause license; see [LICENSE](LICENSE). Other Bimeron
files remain under the repository MIT license unless otherwise stated.
