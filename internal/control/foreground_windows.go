//go:build windows

package control

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"bimeron/core"
	"bimeron/internal/windowsnet"
	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// ForegroundOptions contains public launch bindings only. No credentials are
// accepted by this API. The requester is the GUI process that requested UAC.
type ForegroundOptions struct {
	Config           string
	SHA256           string
	RequesterPID     uint32
	RequesterCreated uint64
}

// RunForeground runs exactly one native session, beginning only after an
// authenticated hello. GUI/pipe closure does not cancel the owner context.
func RunForeground(ctx context.Context, opts ForegroundOptions) error {
	if !filepath.IsAbs(opts.Config) || opts.RequesterPID == 0 || opts.RequesterCreated == 0 {
		return errors.New("invalid_foreground_arguments")
	}
	server, l, release, err := newForegroundOwner(opts)
	if err != nil {
		return err
	}
	defer release()
	file, releaseConfig, err := lockForegroundConfig(opts.Config)
	if err != nil {
		return errors.New("foreground_configuration_rejected")
	}
	defer releaseConfig()
	data, err := io.ReadAll(io.LimitReader(file, 64*1024+1))
	if err != nil {
		return errors.New("foreground_configuration_rejected")
	}
	cfg, err := foregroundConfig(opts.Config, opts.SHA256, data)
	if err != nil {
		return err
	}
	server.bindForegroundSession(ctx, cfg)
	return server.Serve(ctx, l)
}

// CallForeground never dials a daemon. ExpectedImage is the selected Core
// executable's reviewed digest, not a revision claimed by an untrusted peer.
// ForegroundClient pins verified process/image handles between polls. Calls on
// one client are serialized; use asynchronous calls and Close after owner exit.
type ForegroundClient struct {
	mu            sync.Mutex
	expectedImage string
	peer          *ProcessIdentity
	release       func()
	closed        bool
}

func NewForegroundClient(expectedImage string) *ForegroundClient {
	return &ForegroundClient{expectedImage: expectedImage}
}
func (client *ForegroundClient) Close() {
	client.mu.Lock()
	defer client.mu.Unlock()
	if !client.closed {
		client.closed = true
		if client.release != nil {
			client.release()
		}
	}
}

func CallForeground(ctx context.Context, expectedImage string, r Request) (Response, error) {
	client := NewForegroundClient(expectedImage)
	defer client.Close()
	return client.Call(ctx, r)
}

func (client *ForegroundClient) Call(ctx context.Context, r Request) (Response, error) {
	bounded, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()
	ctx = bounded
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed {
		return Response{}, errors.New("foreground_client_closed")
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return Response{}, errForegroundIdentity
	}
	var session uint32
	if windows.ProcessIdToSessionId(uint32(os.Getpid()), &session) != nil || session == 0 {
		return Response{}, errForegroundIdentity
	}
	c, err := winio.DialPipeAccessImpLevel(ctx, foregroundPipe(u.User.Sid.String(), session), windows.GENERIC_READ|windows.GENERIC_WRITE, winio.PipeImpLevelIdentification)
	if err != nil {
		return Response{}, errors.New("foreground_owner_unavailable")
	}
	defer c.Close()
	peer, release, err := expectedPipePeer(c, false, client.peer)
	if err != nil {
		return Response{}, err
	}
	defer func() { release() }()
	if !peer.Elevated || peer.SID != u.User.Sid.String() || peer.Session != session || peer.ImageSHA256 != client.expectedImage {
		return Response{}, errForegroundIdentity
	}
	if client.peer != nil && *client.peer != peer {
		return Response{}, errors.New("stale_instance")
	}
	if client.peer == nil {
		client.peer = &peer
		client.release = release
		release = func() {}
	}
	a, callErr := exchange(ctx, c, r)
	if a.Owner == nil || *a.Owner != peer || a.Instance == "" || (a.Endpoint != "ikev2_foreground" && a.Endpoint != "ikev2_profile") {
		return Response{}, errForegroundIdentity
	}
	return a, callErr
}

func newForegroundOwner(opts ForegroundOptions) (*Server, net.Listener, func(), error) {
	self, releaseSelf, err := inspectProcess(uint32(os.Getpid()))
	if err != nil {
		return nil, nil, nil, err
	}

	if !self.Elevated {
		releaseSelf()
		return nil, nil, nil, errors.New("administrator_required")
	}
	requester, releaseRequester, err := inspectProcess(opts.RequesterPID)
	if err != nil {
		releaseSelf()
		return nil, nil, nil, err
	}

	if requester.Created != opts.RequesterCreated || requester.SID != self.SID || requester.Session != self.Session {
		releaseRequester()
		releaseSelf()
		return nil, nil, nil, errForegroundIdentity
	}
	markerRelease, err := windowsnet.BeginForegroundOwnership()
	if err != nil {
		releaseRequester()
		releaseSelf()
		return nil, nil, nil, errors.New("foreground_owner_unavailable")
	}
	l, err := winio.ListenPipe(foregroundPipe(self.SID, self.Session), &winio.PipeConfig{SecurityDescriptor: "D:P(A;;GA;;;SY)(A;;GA;;;" + self.SID + ")S:(ML;;NW;;;ME)", InputBufferSize: 16 * 1024, OutputBufferSize: 16 * 1024})
	if err != nil {
		markerRelease()
		releaseRequester()
		releaseSelf()
		return nil, nil, nil, errors.New("foreground_owner_unavailable")
	}
	engine := core.New(core.Options{})
	server := NewServer(engine)
	server.foreground = true
	server.owner = &self
	server.endpoint = "ikev2_foreground"
	server.authorize = func(c net.Conn) (func(), error) {
		peer, release, err := expectedPipePeer(c, true, &requester)
		if err != nil {
			return nil, err
		}
		if !matchingForegroundPeer(self, requester, peer) {
			release()
			return nil, errForegroundIdentity
		}
		return release, nil
	}

	return server, l, func() { l.Close(); markerRelease(); releaseRequester(); releaseSelf() }, nil
}
