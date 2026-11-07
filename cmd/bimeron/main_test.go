package main

import (
	"errors"
	"flag"
	"runtime"
	"strings"
	"testing"
)

func TestHelpRequestsAreNotErrors(t *testing.T) {
	for _, args := range [][]string{{"help"}, {"-h"}, {"--help"}} {
		if err := run(args); err != nil {
			t.Fatalf("%v failed: %v", args, err)
		}
	}
	if err := run([]string{"check", "-h"}); !errors.Is(err, flag.ErrHelp) {
		t.Fatal("subcommand help did not report flag.ErrHelp:", err)
	}
}

func TestUsageListsPlatformRecoverFlags(t *testing.T) {
	var out strings.Builder
	printUsage(&out)
	hasFlag := strings.Contains(out.String(), "bimeron recover [--keep-current-dns]\n")
	if want := runtime.GOOS == "linux" || runtime.GOOS == "darwin"; hasFlag != want {
		t.Fatalf("recover usage on %s lists --keep-current-dns: %t", runtime.GOOS, hasFlag)
	}
}
