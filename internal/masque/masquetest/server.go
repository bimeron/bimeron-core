// Package masquetest starts the separately built, pinned interoperability server.
package masquetest

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"bimeron/internal/accesskey"
)

func Start(t testing.TB) map[string]string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	t.Cleanup(cancel)
	binary := os.Getenv("BIMERON_MASQUE_REFERENCE_BIN")
	if binary == "" {
		binary = filepath.Join(t.TempDir(), "masque-reference.exe")
		_, file, _, _ := runtime.Caller(0)
		cmd := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-o", binary, ".")
		cmd.Dir = filepath.Join(filepath.Dir(file), "..", "testdata", "reference-server")
		for _, v := range os.Environ() {
			if !strings.HasPrefix(v, "GOWORK=") {
				cmd.Env = append(cmd.Env, v)
			}
		}
		cmd.Env = append(cmd.Env, "GOWORK=off")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build MASQUE reference: %v\n%s", err, output)
		}
	}
	cmd := exec.CommandContext(ctx, binary)
	cmd.Stderr = os.Stderr
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	var endpoints map[string]string
	if err := json.NewDecoder(output).Decode(&endpoints); err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, []byte(endpoints["certificate"]), 0600); err != nil {
		t.Fatal(err)
	}
	endpoints["ca"] = ca
	return endpoints
}

func Profile(t testing.TB, endpoints map[string]string) accesskey.Profile {
	t.Helper()
	p, err := accesskey.ParseMASQUE("masque://user:fixture-pass@" + endpoints["server"] + "?sni=localhost&ca=" + url.QueryEscape(endpoints["ca"]))
	if err != nil {
		t.Fatal(err)
	}
	return p
}
