package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
)

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }
func Call(ctx context.Context, r Request) (Response, error) {
	c, err := Dial(ctx)
	if err != nil {
		return Response{}, fmt.Errorf("local control unavailable; start daemon or Windows service")
	}
	defer c.Close()
	return exchange(ctx, c, r)
}
func CallService(ctx context.Context, r Request) (Response, error) {
	c, err := DialService(ctx)
	if err != nil {
		return Response{}, err
	}
	defer c.Close()
	return exchange(ctx, c, r)
}
func exchange(ctx context.Context, c net.Conn, r Request) (Response, error) {
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	}
	r.Version = Version
	if err := json.NewEncoder(c).Encode(r); err != nil {
		return Response{}, fmt.Errorf("control request failed")
	}
	var answer Response
	if err := json.NewDecoder(io.LimitReader(c, 256*1024)).Decode(&answer); err != nil {
		return Response{}, fmt.Errorf("control response failed")
	}
	if answer.Version != Version {
		return answer, fmt.Errorf("unsupported daemon protocol")
	}
	if r.ID != "" && answer.ID != r.ID {
		return answer, fmt.Errorf("control response ID mismatch")
	}
	if answer.Error != "" {
		return answer, fmt.Errorf("%s", answer.Error)
	}
	return answer, nil
}
