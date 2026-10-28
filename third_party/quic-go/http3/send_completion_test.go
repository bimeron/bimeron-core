package http3

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

func TestGoAwayPreservesWritesAfterResponseEOFAndFINAck(t *testing.T) {
	client, peer := newConnPair(t)
	cc := (&Transport{GoAwayCloseDelay: time.Second}).NewClientConn(client)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, err := cc.OpenRequestStream(ctx)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodConnect, "https://localhost:443", nil)
	require.NoError(t, err)
	require.NoError(t, request.SendRequestHeader(req))
	response, err := peer.AcceptStream(ctx)
	require.NoError(t, err)
	decodeHeader(t, response)
	_, err = response.Write(encodeResponse(t, http.StatusOK))
	require.NoError(t, err)
	require.NoError(t, response.Close())
	_, err = request.ReadResponse()
	require.NoError(t, err)
	_, err = io.ReadAll(request)
	require.NoError(t, err)
	control, err := peer.OpenUniStream()
	require.NoError(t, err)
	frames := quicvarint.Append(nil, streamTypeControlStream)
	frames = (&settingsFrame{}).Append(frames)
	frames = (&goAwayFrame{StreamID: 4}).Append(frames)
	_, err = control.Write(frames)
	require.NoError(t, err)
	select {
	case <-cc.goAwayCtx.Done():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	payload := []byte("final tunnel payload")
	_, err = request.Write(payload)
	require.NoError(t, err)
	require.NoError(t, request.Close())
	_, err = request.Write([]byte("late"))
	require.Error(t, err)
	select {
	case <-request.SendCompletionContext().Done():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// ACK precedes application consumption. Closing QUIC now would discard
	// these already received bytes in an unmodified peer's receive stream.
	require.NoError(t, peer.Context().Err())
	require.NoError(t, response.SetReadDeadline(time.Now().Add(time.Second)))
	data, err := io.ReadAll(response)
	require.NoError(t, err)
	expected := (&dataFrame{Length: uint64(len(payload))}).Append(nil)
	require.Equal(t, append(expected, payload...), data)
}

func TestGoAwayCloseGraceExpires(t *testing.T) {
	client, peer := newConnPair(t)
	cc := (&Transport{GoAwayCloseDelay: 50 * time.Millisecond}).NewClientConn(client)
	control, err := peer.OpenUniStream()
	require.NoError(t, err)
	frames := quicvarint.Append(nil, streamTypeControlStream)
	frames = (&settingsFrame{}).Append(frames)
	frames = (&goAwayFrame{StreamID: 0}).Append(frames)
	_, err = control.Write(frames)
	require.NoError(t, err)
	select {
	case <-cc.goAwayCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("GOAWAY not received")
	}
	select {
	case <-peer.Context().Done():
	case <-time.After(2 * time.Second):
		t.Fatal("GOAWAY grace did not close the connection")
	}
}
