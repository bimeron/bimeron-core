package main

import (
	"bimeron/internal/control"
	"context"
	"encoding/json"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
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
	if err != nil {
		return "unknown"
	}
	config, err := b.service.Config()
	if err != nil {
		return "unknown"
	}
	state, err := b.service.Query()
	if err != nil {
		return "unknown"
	}
	return requestConditionalRecovery(b.owner, config, state, i, control.CallServiceReadiness)
}

// The owner is authenticated from the original GUI pipe peer, including under
// alternate-administrator elevation. Both requests use the SCM PID-bound pipe.
func requestConditionalRecovery(owner string, config mgr.Config, state svc.Status, i control.RecoveryIdentity, readiness func(context.Context, uint32, control.Request) (control.Response, error)) string {
	if validateRepairRegistration(config, owner) != nil || state.State != svc.Running || state.ProcessId == 0 {
		return "unknown"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	hello, err := readiness(ctx, state.ProcessId, control.Request{Command: "hello"})
	if err != nil {
		return "unknown"
	}
	if hello.ConditionalRecoveryContract != 1 {
		return "unsupported"
	}
	if hello.Instance != i.Instance {
		return "conflict"
	}
	answer, err := readiness(ctx, state.ProcessId, control.Request{Command: "conditional_recovery", ID: "repair", RecoveryIdentity: &i})
	if err != nil || answer.Instance != i.Instance {
		return "unknown"
	}
	switch answer.Disposition {
	case "conflict", "unsupported", "recovered":
		return answer.Disposition
	}
	return "unknown"
}
