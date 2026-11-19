#!/bin/sh
# With no arguments, only check the effective Go release settings.
set -eu
settings=$(go env GOFLAGS GOEXPERIMENT) || { echo 'could not read Go release settings' >&2; exit 1; }
if [ -n "$settings" ]; then
    echo 'unset GOFLAGS and GOEXPERIMENT (also in go env -w)' >&2
    exit 1
fi
if [ "$#" -gt 0 ]; then
    exec go "$@"
fi
