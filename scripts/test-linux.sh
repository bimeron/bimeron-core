#!/bin/sh
# These privileged integration tests run only in fresh network namespaces.
set -eu
cd "$(dirname "$0")/.."
go test ./...
nft_binary=$(command -v nft)
test_directory=$(mktemp -d)
trap 'rm -f "$test_directory/network.test" "$test_directory/core.test" "$test_directory/control.test" "$test_directory/bimeron"; rmdir "$test_directory"' EXIT HUP INT TERM
go test -c -o "$test_directory/network.test" ./internal/linuxnet
go test -c -o "$test_directory/core.test" ./core
go test -c -o "$test_directory/control.test" ./internal/control
go build -o "$test_directory/bimeron" ./cmd/bimeron
sudo unshare -n env BIMERON_NETNS_TEST=1 BIMERON_NFT_BIN="$nft_binary" "$test_directory/network.test" -test.run=TestNativeNetwork -test.v
sudo unshare -n env BIMERON_NETNS_TEST=1 "$test_directory/core.test" -test.run=TestLinuxTUNHTTP -test.v
sudo unshare -m -n sh -c 'mount --make-rprivate / && mount -t tmpfs tmpfs /run && exec env BIMERON_CLI_TEST="$1/bimeron" "$1/control.test" -test.run=TestLinuxDaemonBinary -test.v' sh "$test_directory"
