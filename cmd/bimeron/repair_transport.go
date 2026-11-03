package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type repairRequest struct {
	Version         int  `json:"version"`
	Disruption      bool `json:"disruption"`
	NetworkRecovery bool `json:"networkRecovery"`
}

func repairSessionCommand(args []string) error {
	if len(args) != 2 || !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(args[0]) {
		return errors.New("invalid repair session arguments")
	}
	pid, err := strconv.ParseUint(args[1], 10, 32)
	if err != nil || pid == 0 {
		return errors.New("invalid repair caller")
	}
	listener, authenticate, release, err := listenRepairSession(args[0], uint32(pid))
	if err != nil {
		return err
	}
	defer release()
	defer listener.Close()
	timer := time.AfterFunc(30*time.Second, func() { listener.Close() })
	defer timer.Stop()
	conn, err := listener.Accept()
	if err != nil {
		return errors.New("repair session connection unavailable")
	}
	defer conn.Close()
	listener.Close()
	timer.Stop()
	identity, err := authenticate(conn)
	if err != nil {
		return err
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	// One request and at most two consent replies; the entire input is bounded.
	reader := bufio.NewReader(io.LimitReader(conn, 3073))
	line, err := reader.ReadBytes('\n')
	if err != nil || len(line) > 1024 {
		return errors.New("invalid repair request")
	}
	request, err := parseRepairRequest(line)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(conn)
	send := func(event map[string]any) {
		conn.SetWriteDeadline(time.Now().Add(time.Second))
		_ = encoder.Encode(event)
	}
	backend, err := newRepairBackend(identity)
	if err != nil {
		send(map[string]any{"done": true, "ok": false, "stage": "authenticate", "code": repairFailureCode(err)})
		return err
	}
	if closer, ok := backend.(interface{ Close() }); ok {
		defer closer.Close()
	}
	lastStage := repairStage("inspect")
	challenges := 0
	requestConsent := func(ctx context.Context, kind string) (bool, error) {
		challenges++
		if challenges > 2 || (kind != "disruption" && kind != "network-recovery") {
			return false, errors.New("invalid repair consent challenge")
		}
		deadline := time.Now().Add(60 * time.Second)
		if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
			deadline = end
		}
		conn.SetReadDeadline(deadline)
		conn.SetWriteDeadline(time.Now().Add(time.Second))
		if err := encoder.Encode(map[string]any{"consent": kind}); err != nil {
			return false, err
		}
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				return false, context.DeadlineExceeded
			}
			return false, err
		}
		return parseRepairConsent(line, kind)
	}
	err = runRepairWithConsent(context.Background(), backend, repairConsent{Disruption: request.Disruption, NetworkRecovery: request.NetworkRecovery}, func(stage repairStage) { lastStage = stage; send(map[string]any{"stage": stage}) }, requestConsent)
	send(map[string]any{"done": true, "ok": err == nil, "stage": lastStage, "code": repairFailureCode(err)})
	if err != nil {
		return fmt.Errorf("repair session: %w", err)
	}
	return nil
}

type repairPeerCheck func(net.Conn) (string, error)

func repairFailureCode(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, os.ErrPermission) {
		return "permission-denied"
	}
	if errors.Is(err, os.ErrNotExist) {
		return "component-missing"
	}
	message := err.Error()
	for _, entry := range []struct{ needle, code string }{
		{"consent denied", "consent-denied"},
		{"alternate-credential", "identity-mismatch"}, {"consent required", "consent-required"},
		{"ownership", "ownership-unproven"}, {"cleanup", "cleanup-unconfirmed"},
		{"identity", "identity-mismatch"}, {"unprotected", "untrusted-component"},
		{"untrusted", "untrusted-component"}, {"transition", "transition-pending"},
		{"not ready", "readiness-failed"}, {"replacement unavailable", "component-unavailable"},
		{"requires reconciliation", "reconciliation-required"},
	} {
		if strings.Contains(message, entry.needle) {
			return entry.code
		}
	}
	return "operation-failed"
}

func parseRepairConsent(line []byte, kind string) (bool, error) {
	if len(line) > 1024 {
		return false, errors.New("invalid repair consent reply")
	}
	var reply struct {
		Consent  string `json:"consent"`
		Approved *bool  `json:"approved"`
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&reply); err != nil || reply.Consent != kind || reply.Approved == nil {
		return false, errors.New("invalid repair consent reply")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return false, errors.New("invalid repair consent reply")
	}
	return *reply.Approved, nil
}

func parseRepairRequest(line []byte) (repairRequest, error) {
	var request repairRequest
	if len(line) > 1024 {
		return request, errors.New("repair request too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || request.Version != 1 {
		return request, errors.New("invalid repair request")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return request, errors.New("multiple repair requests rejected")
	}
	return request, nil
}
