package accesskey

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

func TestXHTTPExtraDownloadAndDuplicates(t *testing.T) {
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	raw := `{"downloadSettings":{"address":"download.example","port":443,"network":"xhttp","security":"reality","realitySettings":{"serverName":"front.example","publicKey":"` + key + `","shortId":"ab","fingerprint":"chrome"},"xhttpSettings":{"host":"front.example","path":"/down"}},"xmux":{"maxConnections":2}}`
	options, err := ParseXHTTPExtra(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := options.Validate("packet-up", "tls", "h2"); err != nil {
		t.Fatal(err)
	}
	if options.DownloadSettings.Path != "/down" || options.DownloadSettings.ServerName != "front.example" {
		t.Fatalf("download settings: %+v", options.DownloadSettings)
	}
	for _, bad := range []string{`{"headers":{"A":"a","A":"b"}}`, `{"xmux":{},"xmux":{}}`, `{"downloadSettings":{"address":"a","address":"b"}}`} {
		if _, err := ParseXHTTPExtra(bad); err == nil {
			t.Fatalf("duplicate accepted: %s", bad)
		}
	}
	if err := options.SetXHTTPConfField("XHTTP", ""); err == nil {
		t.Fatal("empty field accepted")
	}
	if _, err := ParseXHTTPExtra(strings.Repeat("x", 16*1024+1)); err == nil {
		t.Fatal("oversize extra accepted")
	}
}

func TestXHTTPExtraLink(t *testing.T) {
	extra := `{"headers":{"User-Agent":"Example"},"sessionPlacement":"query","xmux":{"maxConnections":2}}`
	link := "vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?encryption=none&security=tls&type=xhttp&mode=packet-up&extra=" + url.QueryEscape(extra)
	profile, err := ParseVLESS(link)
	if err != nil {
		t.Fatal(err)
	}
	if profile.VLESS.XHTTPOptions == nil || profile.VLESS.XHTTPOptions.SessionPlacement != "query" {
		t.Fatal("extra lost")
	}
	if _, err := ParseVLESS(link + "&extra=" + url.QueryEscape(extra)); err == nil {
		t.Fatal("duplicate extra accepted")
	}
}
