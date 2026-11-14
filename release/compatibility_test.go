package release

import (
	"encoding/json"
	"os"
	"testing"
)

func TestEmbeddedCompatibilityMatchesSource(t *testing.T) {
	data, err := os.ReadFile("compatibility.json")
	if err != nil {
		t.Fatal(err)
	}
	var source Compatibility
	if err := json.Unmarshal(data, &source); err != nil {
		t.Fatal(err)
	}
	got, err := ReviewedCompatibility()
	if err != nil || got != source {
		t.Fatalf("embedded=%+v source=%+v error=%v", got, source, err)
	}
}

func TestEmbeddedCompatibilityFailsClosed(t *testing.T) {
	original := compatibilityJSON
	t.Cleanup(func() { compatibilityJSON = original })
	for _, data := range []string{
		`{`,
		`{}`,
		`{"schema":1,"gui_reviewed":false,"gui_min":"0.3.0","gui_max_exclusive":"0.3.1","ipc_min":1,"ipc_max":1,"profile_format":1}`,
		`{"schema":1,"gui_reviewed":true,"gui_min":null,"gui_max_exclusive":null,"ipc_min":1,"ipc_max":1,"profile_format":1}`,
	} {
		compatibilityJSON = data
		if _, err := ReviewedCompatibility(); err == nil {
			t.Fatalf("accepted invalid or unreviewed metadata: %s", data)
		}
	}
}
