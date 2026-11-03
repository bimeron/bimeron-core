package main

import (
	"bimeron/internal/control"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

type developerRecord struct {
	Version int    `json:"version"`
	PID     uint32 `json:"pid"`
	Owner   string `json:"owner"`
	Session uint32 `json:"session"`
	Created string `json:"created"`
	Image   string `json:"image"`
	SHA256  string `json:"sha256"`
	Clean   bool   `json:"clean"`
}

func parseDeveloperRecord(data []byte) (r developerRecord, err error) {
	if len(data) > 8192 {
		return r, errors.New("developer record oversized")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err = d.Decode(&r); err != nil {
		return
	}
	if d.Decode(new(any)) != io.EOF || r.Version != 1 || r.PID == 0 || r.Owner == "" || len(r.Owner) > 128 || r.Created == "" || len(r.Created) > 128 || len(r.Image) > 4096 || r.Image == "" {
		return r, errors.New("developer identity record invalid")
	}
	hash, e := hex.DecodeString(r.SHA256)
	if e != nil || len(hash) != 32 {
		return r, errors.New("developer image identity invalid")
	}
	return
}
func developerDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, 256*1024*1024+1))
	if err != nil || n > 256*1024*1024 {
		return "", errors.New("developer image bound exceeded")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func sameDeveloper(a, b developerRecord) bool {
	return a.Version == b.Version && a.PID == b.PID && a.Owner == b.Owner && a.Session == b.Session && a.Created == b.Created && a.Image == b.Image && a.SHA256 == b.SHA256
}
func developerExchange(ctx context.Context, c net.Conn, command, instance string) (control.Response, error) {
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	deadline := time.Now().Add(30 * time.Second)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	c.SetDeadline(deadline)
	var r control.Response
	if err := json.NewEncoder(c).Encode(control.Request{Version: control.Version, Command: command, Instance: instance, ID: "repair-developer"}); err != nil {
		return r, err
	}
	if err := json.NewDecoder(io.LimitReader(c, 256*1024)).Decode(&r); err != nil {
		return r, err
	}
	if r.Version != control.Version || r.ID != "repair-developer" || r.Error != "" || r.Instance == "" || (instance != "" && r.Instance != instance) {
		return r, errors.New("developer reply identity rejected")
	}
	return r, nil
}

// Every connection is authenticated against a retained OS process identity.
func stopRecordedDeveloper(ctx context.Context, r developerRecord, dial func(context.Context) (net.Conn, error), exited func() bool, read func() ([]byte, error)) error {
	call := func(cmd, instance string) (control.Response, error) {
		c, e := dial(ctx)
		if e != nil {
			return control.Response{}, e
		}
		return developerExchange(ctx, c, cmd, instance)
	}
	hello, e := call("hello", "")
	if e != nil {
		return e
	}
	stopped, e := call("stop", hello.Instance)
	if e != nil {
		return e
	}
	if stopped.Status.State != "disconnected" {
		return errors.New("developer cleanup unconfirmed")
	}
	stopped, e = call("shutdown", hello.Instance)
	if e != nil {
		return e
	}
	if stopped.Status.State != "disconnected" {
		return errors.New("developer shutdown unconfirmed")
	}
	for !exited() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	data, e := read()
	if e != nil {
		return e
	}
	clean, e := parseDeveloperRecord(data)
	if e != nil || !sameDeveloper(r, clean) || !clean.Clean {
		return fmt.Errorf("developer clean exit evidence unavailable")
	}
	return nil
}
