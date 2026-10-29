package control

import (
	"bimeron/core"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestForegroundInstallationPolicyIsStrictAndBounded(t *testing.T) {
	valid := foregroundInstallation{Schema: 1, Installation: strings.Repeat("a", 32), GUIHash: strings.Repeat("b", 64)}
	encoded, _ := json.Marshal(valid)
	if _, err := parseForegroundInstallation(encoded); err != nil {
		t.Fatal("valid installation rejected")
	}
	for _, data := range [][]byte{[]byte(`{"schema":1,"schema":1}`), []byte(strings.Repeat("x", 4097)), []byte(`{"schema":1,"installation":"x","gui_sha256":"x"}`), append(append([]byte(nil), encoded...), []byte(" {}")...)} {
		if _, err := parseForegroundInstallation(data); err == nil {
			t.Fatal("untrusted installation policy accepted")
		}
	}
}

func TestForegroundCrossInstallationCannotActivate(t *testing.T) {
	e := &countedForegroundEngine{}
	s := NewServer(e)
	s.installation = strings.Repeat("a", 32)
	s.build = func() core.BuildDetails { return core.BuildDetails{Revision: strings.Repeat("c", 40)} }
	s.bindForegroundSession(context.Background(), core.SessionConfig{})
	a := s.foregroundDispatch(context.Background(), Request{Version: 1, ID: "activate", Command: "hello", Instance: s.instance, Installation: strings.Repeat("b", 32), AcceptRevision: strings.Repeat("c", 40)})
	if a.Error != "installation_mismatch" || e.starts.Load() != 0 {
		t.Fatal("wrong installation changed networking")
	}
}
