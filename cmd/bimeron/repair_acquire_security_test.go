package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"testing"
)

func TestRepairAcquisitionSignedPolicyNegatives(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	pub := priv.Public().(ed25519.PublicKey)
	kh := sha256.Sum256(pub)
	base := repairManifest{Schema: 1, KeyID: hex.EncodeToString(kh[:8]), Tag: "v0.2.0", Version: "0.2.0", Channel: "stable"}
	base.Compatibility = repairCompatibilityFromSource(t)
	for _, p := range []string{"windows", "linux"} {
		for _, a := range []string{"amd64", "arm64"} {
			base.Archives = append(base.Archives, repairArchive{p, a, "bimeron-v0.2.0-" + p + "-" + a + ".zip", 1, hex.EncodeToString(make([]byte, 32))})
		}
	}
	verify := func(m repairManifest, key []byte) error {
		b, e := json.Marshal(m)
		if e != nil {
			t.Fatal(e)
		}
		b = append(b, '\n')
		s := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, b)) + "\n")
		_, e = verifyRepairManifest(b, s, key, "0.2.0", "windows", "amd64")
		return e
	}
	if e := verify(base, pub); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		name, min, max string
		accept         bool
	}{
		{"current release", "0.3.0", "0.3.1", true},
		{"previous release", "0.2.0", "0.2.1", false},
		{"wider upper", "0.3.0", "0.4.0", false},
		{"wider lower", "0.2.0", "0.3.1", false},
		{"narrower upper", "0.3.0", "0.3.1-beta.1", false},
		{"narrower lower", "0.3.1-beta.1", "0.3.1", false},
		{"other window", "0.4.0", "0.4.1", false},
		{"empty window", "0.3.0", "0.3.0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := base
			m.Compatibility.Min, m.Compatibility.Max = tc.min, tc.max
			if err := verify(m, pub); (err == nil) != tc.accept {
				t.Fatalf("window [%s, %s): error=%v, want acceptance=%v", tc.min, tc.max, err, tc.accept)
			}
		})
	}
	cases := map[string]func(*repairManifest){
		"manifest schema":   func(m *repairManifest) { m.Schema = 2 },
		"key ID":            func(m *repairManifest) { m.KeyID = "0000000000000000" },
		"version":           func(m *repairManifest) { m.Version = "0.2.1" },
		"tag":               func(m *repairManifest) { m.Tag = "v0.2.1" },
		"channel":           func(m *repairManifest) { m.Channel = "beta" },
		"compat schema":     func(m *repairManifest) { m.Compatibility.Schema = 2 },
		"unreviewed":        func(m *repairManifest) { m.Compatibility.Reviewed = false },
		"GUI minimum":       func(m *repairManifest) { m.Compatibility.Min = "0.1.0" },
		"GUI maximum":       func(m *repairManifest) { m.Compatibility.Max = "0.3.0" },
		"IPC minimum":       func(m *repairManifest) { m.Compatibility.IPCMin = 2 },
		"IPC maximum":       func(m *repairManifest) { m.Compatibility.IPCMax = 0 },
		"wider IPC maximum": func(m *repairManifest) { m.Compatibility.IPCMax++ },
		"profile":           func(m *repairManifest) { m.Compatibility.Profile = 2 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := base
			mutate(&m)
			if verify(m, pub) == nil {
				t.Fatal("accepted signed incompatible manifest")
			}
		})
	}
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)).Public().(ed25519.PublicKey)
	if verify(base, other) == nil {
		t.Fatal("accepted wrong signing key")
	}
}

func TestRepairAcquisitionMaliciousZIP(t *testing.T) {
	for _, name := range []string{"../escape", "windows-amd64/../../escape", "/absolute", "C:/escape", `windows-amd64\escape`, "symlink", "duplicate", "oversized", "forged-size"} {
		t.Run(name, func(t *testing.T) {
			var b bytes.Buffer
			z := zip.NewWriter(&b)
			add := func(n string, mode os.FileMode, size int64) {
				h := &zip.FileHeader{Name: n, Method: zip.Deflate}
				h.SetMode(mode)
				w, e := z.CreateHeader(h)
				if e != nil {
					t.Fatal(e)
				}
				if size == 0 {
					_, e = w.Write([]byte("fixture"))
				} else {
					_, e = io.CopyN(w, zeroAcquisitionReader{}, size)
				}
				if e != nil {
					t.Fatal(e)
				}
			}
			wanted := "windows-amd64/wintun.dll"
			if name == "oversized" || name == "forged-size" {
				add(wanted, 0600, 64*1024*1024+1)
			} else {
				add(wanted, 0600, 0)
				switch name {
				case "duplicate":
					add(wanted, 0600, 0)
				case "symlink":
					add("unrelated-link", os.ModeSymlink|0777, 0)
				default:
					add(name, 0600, 0)
				}
			}
			if e := z.Close(); e != nil {
				t.Fatal(e)
			}
			data := b.Bytes()
			if name == "forged-size" {
				i := bytes.Index(data, []byte{'P', 'K', 1, 2})
				if i < 0 {
					t.Fatal("missing central directory")
				}
				copy(data[i+24:i+28], []byte{1, 0, 0, 0})
			}
			h := sha256.Sum256(data)
			a := repairArchive{OS: "windows", Arch: "amd64", Size: int64(len(data)), SHA256: hex.EncodeToString(h[:])}
			if out, e := extractRepairMember(data, a, "wintun.dll"); e == nil || out != nil {
				t.Fatal("accepted malicious authenticated ZIP")
			}
		})
	}
}

type zeroAcquisitionReader struct{}

func (zeroAcquisitionReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

type cancelAcquisitionBody struct {
	ctx    context.Context
	cancel context.CancelFunc
	reads  int
	closed bool
}

func (b *cancelAcquisitionBody) Read(p []byte) (int, error) {
	b.reads++
	if b.reads == 1 {
		copy(p, "part")
		b.cancel()
		return 4, nil
	}
	return 0, b.ctx.Err()
}
func (b *cancelAcquisitionBody) Close() error { b.closed = true; return nil }
func TestRepairAcquisitionCancellationInFlight(t *testing.T) {
	t.Run("waiting response", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		calls := 0
		c := newRepairHTTPClient(acquisitionTransport(func(r *http.Request) (*http.Response, error) {
			calls++
			if r.Context().Err() != nil {
				t.Fatal("already canceled")
			}
			cancel()
			return nil, r.Context().Err()
		}))
		out, e := fetchRepairBytes(ctx, c, "https://github.com/test", 100)
		if !errors.Is(e, context.Canceled) || out != nil || calls != 1 {
			t.Fatalf("out=%v err=%v calls=%d", out, e, calls)
		}
	})
	t.Run("partial download", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		b := &cancelAcquisitionBody{ctx: ctx, cancel: cancel}
		c := newRepairHTTPClient(acquisitionTransport(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: b, ContentLength: -1, Header: make(http.Header), Request: r}, nil
		}))
		out, e := fetchRepairBytes(ctx, c, "https://github.com/test", 100)
		if !errors.Is(e, context.Canceled) || out != nil || !b.closed || b.reads != 2 {
			t.Fatalf("out=%v err=%v body=%+v", out, e, b)
		}
	})
}
