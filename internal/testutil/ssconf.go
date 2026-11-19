package testutil

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing/iotest"
)

// SSConfFailureTransport waits for the HTTP client timeout, or returns HTTP 200
// with a body that fails during the read.
type SSConfFailureTransport struct{ AfterHeaders bool }

func (f SSConfFailureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !f.AfterHeaders {
		<-req.Context().Done()
		return nil, req.Context().Err()
	}
	err := &url.Error{Op: "read", URL: req.URL.String(), Err: &net.OpError{Op: "read", Net: "tcp", Err: errors.New("connection reset")}}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(iotest.ErrReader(err))}, nil
}
