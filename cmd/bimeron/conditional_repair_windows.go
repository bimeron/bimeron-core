package main

import (
	"bimeron/internal/control"
	"context"
	"encoding/json"
	"golang.org/x/sys/windows/svc"
	"net"
	"time"
)

func conditionalRepairSession(c net.Conn, identity string, line []byte) error {
	result := "unknown"
	fields, err := restoreObject(line, "version", "command", "recovery_identity")
	if err == nil {
		_, err = restoreObject(fields["recovery_identity"], "owner", "instance", "generation")
	}
	var request struct {
		Command  string                   `json:"command"`
		Identity control.RecoveryIdentity `json:"recovery_identity"`
	}
	if err == nil && json.Unmarshal(line, &request) == nil && request.Command == "conditional_recovery" && request.Identity.Valid() {
		result = forwardConditionalRecovery(identity, request.Identity)
	}
	_ = c.SetWriteDeadline(time.Now().Add(time.Second))
	return json.NewEncoder(c).Encode(map[string]any{"version": 3, "done": true, "ok": result == "recovered", "disposition": result})
}

func forwardConditionalRecovery(caller string, i control.RecoveryIdentity) string {
	backend, err := newRepairBackend(caller)
	if err != nil {
		return "unknown"
	}
	b := backend.(*windowsRepairBackend)
	defer b.Close()
	b.service, err = b.manager.OpenService(serviceName)
	if err != nil || b.validateIdentity() != nil {
		return "unknown"
	}
	state, err := b.service.Query()
	if err != nil || state.State != svc.Running || state.ProcessId == 0 {
		return "unknown"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	hello, err := control.CallService(ctx, control.Request{Command: "hello"})
	if err != nil {
		return "unknown"
	}
	if hello.Capabilities == nil || hello.Capabilities.ConditionalRecoveryContract != 1 {
		return "unsupported"
	}
	if hello.Instance != i.Instance || hello.RecoveryIdentity == nil || *hello.RecoveryIdentity != i {
		return "conflict"
	}
	answer, err := control.CallServiceReadiness(ctx, state.ProcessId, control.Request{Command: "conditional_recovery", ID: "repair", RecoveryIdentity: &i})
	if err != nil || answer.Instance != i.Instance {
		return "unknown"
	}
	switch answer.Disposition {
	case "conflict", "unsupported", "recovered":
		return answer.Disposition
	}
	return "unknown"
}
