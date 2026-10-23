package vless

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"

	"bimeron/internal/accesskey"
)

func xhttpRangeValue(value accesskey.XHTTPRange, fallback int) int {
	if value.To == 0 {
		return fallback
	}
	if value.From == value.To {
		return value.From
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(value.To-value.From+1)))
	if err != nil {
		return value.From
	}
	return value.From + int(n.Int64())
}

func xhttpRequest(ctx context.Context, method string, u url.URL, body io.Reader, session, seq, mode string, options *accesskey.XHTTPOptions) (*http.Request, error) {
	if options == nil {
		options = &accesskey.XHTTPOptions{}
	}
	setQuery := func(key, value string) { q := u.Query(); q.Set(key, value); u.RawQuery = q.Encode() }
	metadata := []struct{ placement, key, value string }{
		{options.SessionPlacement, options.SessionKey, session},
		{options.SeqPlacement, options.SeqKey, seq},
	}
	for i := range metadata {
		item := &metadata[i]
		if item.key == "" {
			if i == 0 {
				if item.placement == "header" {
					item.key = "X-Session"
				} else {
					item.key = "x_session"
				}
			} else {
				if item.placement == "header" {
					item.key = "X-Seq"
				} else {
					item.key = "x_seq"
				}
			}
		}
		if item.placement == "query" && item.value != "" {
			setQuery(item.key, item.value)
		}
	}
	var payload []byte
	if options.UplinkDataPlacement == "header" || options.UplinkDataPlacement == "cookie" {
		if body != nil {
			var err error
			payload, err = io.ReadAll(io.LimitReader(body, 1<<20+1))
			if err != nil {
				return nil, err
			}
			if len(payload) > 1<<20 {
				return nil, fmt.Errorf("XHTTP uplink data too large")
			}
			body = nil
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	for key, value := range options.Headers {
		req.Header.Set(key, value)
	}
	for _, item := range metadata {
		if item.value == "" {
			continue
		}
		switch item.placement {
		case "header":
			req.Header.Set(item.key, item.value)
		case "cookie":
			req.AddCookie(&http.Cookie{Name: item.key, Value: item.value})
		}
	}
	if payload != nil {
		key := options.UplinkDataKey
		if key == "" {
			if options.UplinkDataPlacement == "header" {
				key = "X-Data"
			} else {
				key = "x_data"
			}
		}
		encoded := base64.RawURLEncoding.EncodeToString(payload)
		chunk := xhttpRangeValue(options.UplinkChunkSize, 4096)
		for i := 0; len(encoded) > 0; i++ {
			n := min(chunk, len(encoded))
			part := encoded[:n]
			encoded = encoded[n:]
			if options.UplinkDataPlacement == "header" {
				req.Header.Set(fmt.Sprintf("%s-%d", key, i), part)
			} else {
				req.AddCookie(&http.Cookie{Name: fmt.Sprintf("%s_%d", key, i), Value: part})
			}
		}
	}
	if body != nil && mode != "packet-up" && !options.NoGRPCHeader {
		req.Header.Set("Content-Type", "application/grpc")
	}
	paddingLength := xhttpRangeValue(options.XPaddingBytes, 100)
	padding := strings.Repeat("X", paddingLength)
	if options.XPaddingObfsMode && options.XPaddingMethod == "tokenish" {
		const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
		var b strings.Builder
		for i := 0; i < paddingLength; i++ {
			n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
			if err != nil {
				break
			}
			b.WriteByte(alphabet[n.Int64()])
		}
		if b.Len() == paddingLength {
			padding = b.String()
		}
	}
	placement, key, header := "queryInHeader", "x_padding", "Referer"
	if options.XPaddingObfsMode {
		placement = options.XPaddingPlacement
		if placement == "" {
			placement = "queryInHeader"
		}
		key = options.XPaddingKey
		if key == "" {
			key = "x_padding"
		}
		header = options.XPaddingHeader
		if header == "" {
			header = "X-Padding"
		}
	}
	switch placement {
	case "query":
		q := req.URL.Query()
		q.Set(key, padding)
		req.URL.RawQuery = q.Encode()
	case "cookie":
		req.AddCookie(&http.Cookie{Name: key, Value: padding})
	case "header":
		req.Header.Set(header, padding)
	case "queryInHeader":
		target := *req.URL
		q := target.Query()
		q.Set(key, padding)
		target.RawQuery = q.Encode()
		req.Header.Set(header, target.String())
	}
	return req, nil
}
