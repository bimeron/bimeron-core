package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"bimeron/internal/config"
	"bimeron/internal/problem"
)

func bridgeKey(b byte) string {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b + byte(i)
	}
	return base64.StdEncoding.EncodeToString(k)
}

func bridgeWG() string {
	return "[Interface]\nPrivateKey = " + bridgeKey(1) + "\nAddress = 10.8.0.2/32\nJc = 4\nS3 = 10\n\n[Peer]\nPublicKey = " + bridgeKey(2) + "\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0\n"
}

func callWireGuard(t *testing.T, request any) (wireguardResponse, string) {
	t.Helper()
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := wireguardBridge(bytes.NewReader(data), &out); err != nil {
		t.Fatal(err)
	}
	var r wireguardResponse
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	return r, out.String()
}

func problemCode(r wireguardResponse) string {
	if r.Problems == nil || len(*r.Problems) == 0 {
		return ""
	}
	return (*r.Problems)[0].Code
}

func TestWireGuardBridgeInspectAndEdit(t *testing.T) {
	r, raw := callWireGuard(t, map[string]any{"version": 1, "op": "inspect", "text": bridgeWG()})
	if r.Error != "" || r.Protocol != "amneziawg" || *r.AWGVersion != "2.0" || r.Fields["Peer/Endpoint"] != "192.0.2.1:51820" || r.AllowedIPs.Coverage != "ipv4_only" || r.AllowedIPs.IPv6 != "none" {
		t.Fatalf("inspect %s", raw)
	}
	if r.Text != nil || r.Problems == nil || len(*r.Problems) != 0 || len(r.SecretFields) != 3 {
		t.Fatalf("inspect members %s", raw)
	}
	r, raw = callWireGuard(t, map[string]any{"version": 1, "op": "edit", "text": bridgeWG(), "operations": []any{
		map[string]any{"op": "set_field", "section": "Peer", "key": "AllowedIPs", "value": "0.0.0.0/0, ::/0"},
		map[string]any{"op": "set_field", "section": "Interface", "key": "S3", "value": ""},
	}})
	if r.Error != "" || r.AllowedIPs.Coverage != "full" || *r.AWGVersion != "1.0" || strings.Contains(*r.Text, "S3") {
		t.Fatalf("edit %s", raw)
	}
	r, _ = callWireGuard(t, map[string]any{"version": 1, "op": "edit", "text": bridgeWG(), "operations": []any{
		map[string]any{"op": "set_field", "section": "Peer", "key": "AllowedIPs", "value": "::/0"},
		map[string]any{"op": "set_field", "section": "Peer", "key": "PostUp", "value": "x"},
	}})
	if r.Error == "" || *r.Text != bridgeWG() || problemCode(r) != "option_unknown" {
		t.Fatal("failed edit must return the original text")
	}
	r, _ = callWireGuard(t, map[string]any{"version": 1, "op": "inspect", "text": bridgeWG() + "PostUp = x\n"})
	if r.Error != "" || problemCode(r) != "wireguard_hook_unsupported" || r.Fields == nil {
		t.Fatal("validation problems keep fields")
	}
	if p := (*r.Problems)[0]; p.Document != "wireguard" || p.Line != 11 {
		t.Fatalf("location %+v", p)
	}
}

func TestWireGuardBridgeDetectImportCapabilities(t *testing.T) {
	r, _ := callWireGuard(t, map[string]any{"version": 1, "op": "detect", "text": bridgeWG()})
	if r.Format != "wireguard" || r.Error != "" {
		t.Fatalf("detect %+v", r)
	}
	r, _ = callWireGuard(t, map[string]any{"version": 1, "op": "detect", "text": "[Routing]\nDefault = proxy\n"})
	if r.Format != "bimeron" {
		t.Fatal("detect bimeron")
	}
	r, _ = callWireGuard(t, map[string]any{"version": 1, "op": "detect", "text": "\xff"})
	if problemCode(r) != "file_not_utf8" && r.Error == "" {
		t.Fatal("detect non-UTF-8")
	}
	r, _ = callWireGuard(t, map[string]any{"version": 1, "op": "inspect", "text": strings.Repeat("#", 70000)})
	if problemCode(r) != "file_too_large" {
		t.Fatal("size limit")
	}
	link := "wireguard://" + url.QueryEscape(bridgeKey(1)) + "@vpn.example.test:51820?publickey=" + url.QueryEscape(bridgeKey(2)) + "&address=10.0.0.2/32#Home"
	r, raw := callWireGuard(t, map[string]any{"version": 1, "op": "import_uri", "uri": link})
	if r.Error != "" || *r.Name != "Home" || r.Text == nil || r.Protocol != "wireguard" || len(*r.Problems) != 0 {
		t.Fatalf("import %s", raw)
	}
	r, raw = callWireGuard(t, map[string]any{"version": 1, "op": "import_uri", "uri": strings.Replace(link, "#Home", "&reserved=1,2,3", 1)})
	if r.Text == nil || r.Error != "" || problemCode(r) != "" || r.Fields["Peer/Reserved"] != "1, 2, 3" {
		t.Fatalf("reserved %s", raw)
	}
	hyphen := strings.Replace(strings.Replace(link, "wireguard://", "wg://", 1), "#Home", "&reserved=0-12-255#Home", 1)
	r, raw = callWireGuard(t, map[string]any{"version": 1, "op": "import_uri", "uri": hyphen})
	if r.Text == nil || problemCode(r) != "" || r.Fields["Peer/Reserved"] != "0, 12, 255" {
		t.Fatalf("reserved %s", raw)
	}
	b64 := strings.Replace(hyphen, "0-12-255", url.QueryEscape(base64.StdEncoding.EncodeToString([]byte{255, 255, 254})), 1)
	r, raw = callWireGuard(t, map[string]any{"version": 1, "op": "import_uri", "uri": b64})
	if r.Text == nil || problemCode(r) != "" || r.Fields["Peer/Reserved"] != "255, 255, 254" {
		t.Fatalf("base64 reserved %s", raw)
	}
	r, raw = callWireGuard(t, map[string]any{"version": 1, "op": "import_uri", "uri": strings.Replace(hyphen, "#Home", "&enable_amnezia=true#Home", 1)})
	if r.Text != nil || problemCode(r) != "wireguard_reserved_unsupported" || strings.Contains(raw, bridgeKey(1)) {
		t.Fatalf("combined reserved and AWG %s", raw)
	}
	r, _ = callWireGuard(t, map[string]any{"version": 1, "op": "capabilities"})
	if r.Capabilities == nil || !r.Capabilities.Supported || !r.Capabilities.Reserved || r.Capabilities.DocumentAPI != 1 {
		t.Fatal("capabilities")
	}
	for _, bad := range []any{
		map[string]any{"version": 2, "op": "capabilities"},
		map[string]any{"version": 1, "op": "inspect"},
		map[string]any{"version": 1, "op": "detect", "text": "", "uri": ""},
		map[string]any{"version": 1, "op": "nope"},
		map[string]any{"version": 1, "op": "edit", "text": "", "operations": []any{map[string]any{"op": "move"}}},
		map[string]any{"version": 1, "op": "capabilities", "extra": true},
	} {
		r, _ := callWireGuard(t, bad)
		if r.Error == "" {
			t.Fatalf("accepted %v", bad)
		}
	}
}

func TestWireGuardBridgeReservedRoundTrip(t *testing.T) {
	original := strings.Replace(bridgeWG(), "Jc = 4\nS3 = 10\n", "", 1)
	edit := func(text, section, key, value string) wireguardResponse {
		t.Helper()
		r, _ := callWireGuard(t, map[string]any{"version": 1, "op": "edit", "text": text, "operations": []any{
			map[string]string{"op": "set_field", "section": section, "key": key, "value": value},
		}})
		if r.Error != "" || r.Text == nil || problemCode(r) != "" {
			t.Fatalf("edit %s failed: %s", key, problemCode(r))
		}
		return r
	}
	r := edit(original, "Peer", "Reserved", "0, 12, 255")
	if r.Fields["Peer/Reserved"] != "0, 12, 255" {
		t.Fatal("missing reserved field")
	}
	saved := *r.Text
	r, _ = callWireGuard(t, map[string]any{"version": 1, "op": "inspect", "text": saved})
	if problemCode(r) != "" || r.Fields["Peer/Reserved"] != "0, 12, 255" {
		t.Fatal("reopen lost reserved field")
	}
	r = edit(saved, "Interface", "MTU", "1280")
	if !strings.Contains(*r.Text, "Reserved = 0, 12, 255") {
		t.Fatal("unrelated edit lost reserved field")
	}
	r = edit(*r.Text, "Peer", "Reserved", "")
	if _, exists := r.Fields["Peer/Reserved"]; exists || strings.Contains(*r.Text, "Reserved") {
		t.Fatal("clear retained reserved field")
	}
	for _, value := range []string{"1,2", "1,,2,3", "-1,2,3", "1,2,256", "1,2,pasted-secret"} {
		r, _ := callWireGuard(t, map[string]any{"version": 1, "op": "inspect", "text": original + "Reserved = " + value + "\n"})
		if problemCode(r) != "number_invalid" || (*r.Problems)[0].Field != "Reserved" || strings.Contains((*r.Problems)[0].Error(), "pasted-secret") {
			t.Fatal("invalid reserved diagnostic")
		}
	}
	path := filepath.Join(t.TempDir(), "reserved.conf")
	if err := os.WriteFile(path, []byte(saved), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.LoadAny(path); err != nil {
		t.Fatalf("runtime load: %v", err)
	}
}

func TestValidateProfileWithWireGuardFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, text string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	write("home.wg.conf", bridgeWG())
	profile := write("home.conf", "[Profile]\nVersion = 1\nName = Home\n\n[AccessKey]\nFile = home.wg.conf\n\n[Routing]\nDefault = proxy\nAllowedIPsMode = block\n")
	c, err := config.Load(profile)
	if err != nil || !c.IsWireGuard() {
		t.Fatalf("load: %v", err)
	}
	write("home.wg.conf", bridgeWG()+"PostDown = x\n")
	var out bytes.Buffer
	if err := validateJSONBridge(profile, &out); err != nil {
		t.Fatal(err)
	}
	var r struct{ Problems []problem.Error }
	if err := json.Unmarshal(out.Bytes(), &r); err != nil || len(r.Problems) != 1 {
		t.Fatalf("validate %s", out.String())
	}
	if p := r.Problems[0]; p.Code != "wireguard_hook_unsupported" || p.Document != "wireguard" || p.Source != "File" || p.Line != 11 || p.Section != "Peer" {
		t.Fatalf("problem %+v", p)
	}
	os.Remove(filepath.Join(dir, "home.wg.conf"))
	out.Reset()
	_ = validateJSONBridge(profile, &out)
	r.Problems = nil
	if err := json.Unmarshal(out.Bytes(), &r); err != nil || r.Problems[0].Code != "file_unreadable" || r.Problems[0].Field != "File" || r.Problems[0].Document != "" {
		t.Fatalf("missing file %s", out.String())
	}
}

func TestWireGuardBridgeKeyOperations(t *testing.T) {
	r, raw := callWireGuard(t, map[string]any{"version": 1, "op": "generate_keypair"})
	if r.Error != "" || len(r.PrivateKey) != 44 || len(r.PublicKey) != 44 {
		t.Fatalf("keypair %s", raw)
	}
	private, public := r.PrivateKey, r.PublicKey
	r, _ = callWireGuard(t, map[string]any{"version": 1, "op": "public_key", "private_key": private})
	if r.Error != "" || r.PublicKey != public {
		t.Fatal("derived public key differs")
	}
	r, raw = callWireGuard(t, map[string]any{"version": 1, "op": "public_key", "private_key": "not-a-key"})
	if problemCode(r) != "wireguard_key_invalid" || strings.Contains(raw, "not-a-key") || r.PublicKey != "" {
		t.Fatalf("invalid key %s", raw)
	}
	r, _ = callWireGuard(t, map[string]any{"version": 1, "op": "generate_preshared_key"})
	if r.Error != "" || len(r.PresharedKey) != 44 {
		t.Fatal("preshared key")
	}
	r, _ = callWireGuard(t, map[string]any{"version": 1, "op": "capabilities"})
	if strings.Join(r.Capabilities.KeyOperations, ",") != "generate_keypair,public_key,generate_preshared_key" {
		t.Fatalf("key operations %v", r.Capabilities.KeyOperations)
	}
	for _, bad := range []any{
		map[string]any{"version": 1, "op": "public_key"},
		map[string]any{"version": 1, "op": "generate_keypair", "private_key": private},
	} {
		if r, _ := callWireGuard(t, bad); r.Error == "" {
			t.Fatalf("accepted %v", bad)
		}
	}
}
