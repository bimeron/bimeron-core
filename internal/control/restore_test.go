package control

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"bimeron/core"
)

func TestGuardedRestoreChannelsAndInstance(t *testing.T) {
	s := NewServer(core.New(core.Options{}))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	queries, finalizes, closed := 0, 0, 0
	s.QueryRestore = func(_ net.Conn, r Request) RestoreProof {
		queries++
		return RestoreProof{Version: 2, Operation: r.Operation}
	}
	s.FinalizeRestore = func(_ context.Context, r Request, _ ProcessWatch) RestoreProof {
		finalizes++
		return RestoreProof{Version: 2, Operation: r.Operation}
	}
	s.PeerProcess = func(net.Conn) ProcessWatch { return &fakeWatch{true, &closed} }
	query := Request{ID: "q", Instance: s.instance, Operation: strings.Repeat("a", 32), Command: "query_restore"}
	finalize := query
	finalize.Command = "finalize_restore"
	finalize.ResidualProfile = strings.Repeat("b", 64)
	finalize.ResidualGeneration = strings.Repeat("c", 64)
	finalize.TargetSHA = strings.Repeat("d", 64)
	stale := query
	stale.Instance = "old"
	for _, tc := range []struct {
		priv bool
		r    Request
		ok   bool
	}{{false, query, true}, {false, stale, false}, {true, query, false}, {false, finalize, false}, {true, finalize, true}} {
		server, client := net.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			if tc.priv {
				s.readinessConnection(ctx, server)
			} else {
				s.handle(ctx, server)
			}
		}()
		ans, err := exchange(ctx, client, tc.r)
		client.Close()
		<-done
		if (err == nil && ans.Restore != nil) != tc.ok {
			t.Fatalf("%s privileged=%t: %+v %v", tc.r.Command, tc.priv, ans, err)
		}
	}
	if queries != 1 || finalizes != 1 || closed != 1 {
		t.Fatal(queries, finalizes, closed)
	}
}
