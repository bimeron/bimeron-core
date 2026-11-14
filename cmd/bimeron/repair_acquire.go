package main

// Signed repair acquisition deliberately reuses Desktop's published update key
// and manifest envelope. The authenticated broker chooses the exact build tag;
// no caller can select a URL, key, digest, version, or archive member.
import (
	"archive/zip"
	"bimeron/core"
	"bimeron/release"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

//lint:ignore U1000 used by the Windows repair path.
const repairUpdateKey = "bk6SfABmDG88uhUupYT+ia6dtSrpHbnGaBCfYvihJF0="
const repairDownloadLimit = 100 * 1024 * 1024

var repairReleaseVersion = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-beta\.(0|[1-9][0-9]*))?$`)

type repairArchive struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type repairManifest struct {
	Schema        int                   `json:"schema"`
	KeyID         string                `json:"key_id"`
	Tag           string                `json:"tag"`
	Version       string                `json:"core_version"`
	Channel       string                `json:"channel"`
	Compatibility release.Compatibility `json:"compatibility"`
	Archives      []repairArchive       `json:"archives"`
}

func verifyRepairManifest(data, signature, key []byte, version, platform, arch string) (repairArchive, error) {
	fail := func() (repairArchive, error) { return repairArchive{}, fmt.Errorf("signed repair manifest rejected") }
	if len(data) == 0 || len(data) > 65536 || data[len(data)-1] != '\n' || len(signature) != 89 || signature[88] != '\n' || len(key) != ed25519.PublicKeySize {
		return fail()
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(string(signature[:88]))
	if err != nil || base64.StdEncoding.EncodeToString(sig) != string(signature[:88]) || !ed25519.Verify(key, data, sig) {
		return fail()
	}
	var m repairManifest
	if !repairJSONUnique(data) || json.Unmarshal(data, &m) != nil {
		return fail()
	}
	digest := sha256.Sum256(key)
	// Repair acquires this broker's exact release, so its entire compatibility
	// policy must match the reviewed metadata embedded from the same source.
	expected, err := release.ReviewedCompatibility()
	if err != nil || m.Schema != 1 || m.KeyID != hex.EncodeToString(digest[:8]) || !repairReleaseVersion.MatchString(version) || m.Version != version || m.Tag != "v"+version || m.Compatibility != expected || len(m.Archives) != 4 {
		return fail()
	}
	channel := "stable"
	if strings.Contains(version, "-") {
		channel = "beta"
	}
	if m.Channel != channel {
		return fail()
	}
	seen := map[string]bool{}
	var selected repairArchive
	for _, a := range m.Archives {
		target := a.OS + "-" + a.Arch
		h, e := hex.DecodeString(a.SHA256)
		if (a.OS != "windows" && a.OS != "linux") || (a.Arch != "amd64" && a.Arch != "arm64") || seen[target] || a.Name != "bimeron-v"+version+"-"+target+".zip" || a.Size < 1 || a.Size > repairDownloadLimit || e != nil || len(h) != 32 || hex.EncodeToString(h) != a.SHA256 {
			return fail()
		}
		seen[target] = true
		if a.OS == platform && a.Arch == arch {
			selected = a
		}
	}
	if selected.Name == "" {
		return fail()
	}
	return selected, nil
}

func repairDownloadURL(u *url.URL) bool {
	return u.Scheme == "https" && u.User == nil && u.Port() == "" && (u.Host == "github.com" || u.Host == "objects.githubusercontent.com" || u.Host == "release-assets.githubusercontent.com")
}
func fetchRepairBytes(ctx context.Context, client *http.Client, address string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	if !repairDownloadURL(req.URL) {
		return nil, fmt.Errorf("repair source URL rejected")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ContentLength > limit {
		return nil, fmt.Errorf("repair source unavailable or oversized")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("repair source oversized")
	}
	return data, nil
}
func extractRepairMember(data []byte, a repairArchive, member string) ([]byte, error) {
	digest := sha256.Sum256(data)
	if int64(len(data)) != a.Size || hex.EncodeToString(digest[:]) != a.SHA256 {
		return nil, fmt.Errorf("repair archive authentication failed")
	}
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	wanted := a.OS + "-" + a.Arch + "/" + member
	var selected *zip.File
	for _, f := range z.File {
		if f.Mode()&os.ModeSymlink != 0 || f.Name == "" || strings.HasPrefix(f.Name, "/") || strings.ContainsAny(f.Name, "\\:") {
			return nil, fmt.Errorf("unsafe repair archive")
		}
		for _, p := range strings.Split(f.Name, "/") {
			if p == ".." {
				return nil, fmt.Errorf("unsafe repair archive")
			}
		}
		if f.Name == wanted {
			if selected != nil || !f.Mode().IsRegular() || f.UncompressedSize64 == 0 || f.UncompressedSize64 > 64*1024*1024 {
				return nil, fmt.Errorf("invalid repair member")
			}
			selected = f
		}
	}
	if selected == nil {
		return nil, fmt.Errorf("signed repair member absent")
	}
	r, err := selected.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	result, err := io.ReadAll(io.LimitReader(r, 64*1024*1024+1))
	if err != nil {
		return nil, err
	}
	if len(result) > 64*1024*1024 {
		return nil, fmt.Errorf("repair member oversized")
	}
	return result, nil
}

//lint:ignore U1000 used by the Windows repair path.
func acquireRepairMember(ctx context.Context, member string) ([]byte, error) {
	version := core.GetBuildInfo().Version
	if !repairReleaseVersion.MatchString(version) {
		return nil, fmt.Errorf("signed repair source requires a published broker build version")
	}
	client := newRepairHTTPClient(&http.Transport{Proxy: nil})
	defer client.CloseIdleConnections()
	base := "https://github.com/bimeron/bimeron-core/releases/download/v" + version + "/"
	data, err := fetchRepairBytes(ctx, client, base+"update-manifest.json", 65536)
	if err != nil {
		return nil, err
	}
	sig, err := fetchRepairBytes(ctx, client, base+"update-manifest.json.sig", 1024)
	if err != nil {
		return nil, err
	}
	key, _ := base64.StdEncoding.DecodeString(repairUpdateKey)
	a, err := verifyRepairManifest(data, sig, key, version, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return nil, err
	}
	archive, err := fetchRepairBytes(ctx, client, base+a.Name, a.Size)
	if err != nil {
		return nil, err
	}
	return extractRepairMember(archive, a, member)
}

// Exclusive creation under an already protected service directory. Callers must
// retain their platform directory protection and revalidate the completed image.
func writeRepairDownload(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(path)
	}
	return err
}

// Reject duplicate object keys rather than depending on parser last-key wins.
func repairJSONUnique(data []byte) bool {
	d := json.NewDecoder(bytes.NewReader(data))
	var value func() bool
	value = func() bool {
		token, err := d.Token()
		if err != nil {
			return false
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return true
		}
		switch delimiter {
		case '{':
			keys := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return false
				}
				name, ok := k.(string)
				if !ok || keys[name] {
					return false
				}
				keys[name] = true
				if !value() {
					return false
				}
			}
			end, e := d.Token()
			return e == nil && end == json.Delim('}')
		case '[':
			for d.More() {
				if !value() {
					return false
				}
			}
			end, e := d.Token()
			return e == nil && end == json.Delim(']')
		}
		return false
	}
	if !value() {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}

func newRepairHTTPClient(transport http.RoundTripper) *http.Client {
	return &http.Client{Timeout: 45 * time.Second, Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 4 || !repairDownloadURL(req.URL) {
			return fmt.Errorf("repair redirect rejected")
		}
		return nil
	}}
}

func stageRepairDownload(target string, data []byte) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(target), filepath.Base(target)+".repair-download-*")
	if err != nil {
		return "", err
	}
	path := f.Name()
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}
