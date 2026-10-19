//go:build linux

package core

import (
	"context"
	stack "github.com/xjasonlyu/tun2socks/v2/core"
	"golang.getoutline.org/sdk/transport"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"bimeron/internal/linuxnet"
	"bimeron/internal/vpn"
	"strings"
	"testing"
	"time"
)

type loopbackStream struct{ address string }

func (d loopbackStream) DialStream(ctx context.Context, _ string) (transport.StreamConn, error) {
	return (&transport.TCPDialer{}).DialStream(ctx, d.address)
}

func TestLinuxTUNHTTP(t *testing.T) {
	if os.Getenv("BIMERON_NETNS_TEST") != "1" {
		t.Skip("requires unshare -n")
	}
	current, _ := os.Readlink("/proc/self/ns/net")
	host, _ := os.Readlink("/proc/1/ns/net")
	if os.Geteuid() != 0 || current == "" || current == host {
		t.Fatal("refusing to change host network namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	runner := func(ctx context.Context, name, input string, args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Stdin = strings.NewReader(input)
		return cmd.Output()
	}
	if _, err := runner(ctx, "ip", "", "link", "set", "lo", "up"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/conf/all/rp_filter", []byte("1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "through-linux-tun") }))
	defer server.Close()
	h := vpn.NewHandler(ctx)
	h.TCP = loopbackStream{address: server.Listener.Addr().String()}
	router := &flowRouter{}
	router.replace(h)
	defer router.Close()
	d, err := linuxnet.OpenTUN("Bimeron", 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	s, err := stack.CreateStack(&stack.Config{LinkEndpoint: d, TransportHandler: router})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	dir := t.TempDir()
	resolver := filepath.Join(dir, "resolv.conf")
	os.WriteFile(resolver, []byte("nameserver 192.0.2.53\n"), 0644)
	manager := &linuxnet.Manager{Dir: dir, Resolver: resolver, Run: runner}
	if err := manager.Configure(ctx, "Bimeron", 1420, nil, false, false); err != nil {
		t.Fatal(err)
	}
	defer manager.Recover(context.Background(), false)
	tr := &http.Transport{DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	for _, url := range []string{"http://203.0.113.9/", "http://[2001:db8::9]/"} {
		response, err := client.Get(url)
		if err != nil {
			t.Fatal("TUN flow failed", url, err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || string(body) != "through-linux-tun" {
			t.Fatal("invalid TUN response", string(body), err)
		}
	}
}
