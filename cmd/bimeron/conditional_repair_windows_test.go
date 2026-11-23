package main

import (
	"bimeron/internal/control"
	"context"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"path/filepath"
	"strings"
	"testing"
)

func TestConditionalRepairAlternateAdministrator(t *testing.T) {
	root, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		t.Fatal(err)
	}
	const guiSID = "S-1-5-21-11-22-33-1001"
	const adminSID = "S-1-5-21-11-22-33-1002"
	config := mgr.Config{BinaryPathName: windows.ComposeCommandLine([]string{filepath.Join(root, "Bimeron Core", "bimeron.exe"), "service", "run", guiSID}), ServiceStartName: "LocalSystem"}
	state := svc.Status{State: svc.Running, ProcessId: 1337}
	identity := control.RecoveryIdentity{Owner: "system", Instance: strings.Repeat("e", 32), Generation: strings.Repeat("f", 64)}
	for _, tc := range []struct {
		caller string
		cap    int
		want   string
		calls  int
	}{{guiSID, 1, "recovered", 2}, {adminSID, 1, "unknown", 0}, {guiSID, 0, "unsupported", 1}} {
		calls := 0
		// Simulate only the privileged transport available to the alternate admin.
		readiness := func(_ context.Context, pid uint32, r control.Request) (control.Response, error) {
			calls++
			if pid != state.ProcessId {
				t.Fatal("wrong service PID", pid)
			}
			if calls == 1 && r.Command == "hello" {
				return control.Response{Instance: identity.Instance, ConditionalRecoveryContract: tc.cap}, nil
			}
			if calls == 2 && r.Command == "conditional_recovery" && r.RecoveryIdentity != nil && *r.RecoveryIdentity == identity {
				return control.Response{Instance: identity.Instance, Disposition: "recovered"}, nil
			}
			t.Fatal("unexpected readiness request", r)
			return control.Response{}, nil
		}
		if got := requestConditionalRecovery(tc.caller, config, state, identity, readiness); got != tc.want || calls != tc.calls {
			t.Fatal(got, calls)
		}
	}
}
