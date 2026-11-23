package control

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

type RecoveryIdentity struct {
	Owner      string `json:"owner"`
	Instance   string `json:"instance"`
	Generation string `json:"generation"`
}

func (i RecoveryIdentity) Valid() bool {
	if i.Owner != "system" || !restoreID(i.Instance) || len(i.Generation) != 64 || strings.ToLower(i.Generation) != i.Generation {
		return false
	}
	_, err := hex.DecodeString(i.Generation)
	return err == nil
}

func (s *Server) inspectRecovery(ctx context.Context) *RecoveryIdentity {
	if !s.command.TryLock() {
		return nil
	}
	defer s.command.Unlock()
	if s.closing || s.hold != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	generation, result := s.ConditionalRecovery(ctx, "")
	i := RecoveryIdentity{"system", s.instance, generation}
	if result != "eligible" || !i.Valid() {
		return nil
	}
	return &i
}

func (s *Server) recoverConditionally(ctx context.Context, i *RecoveryIdentity, peer ProcessWatch) string {
	s.command.Lock()
	defer s.command.Unlock()
	if s.ConditionalRecovery == nil {
		return "unsupported"
	}
	if peer == nil || !peer.Alive() {
		return "unknown"
	}
	if s.closing || s.hold != nil || i == nil || !i.Valid() || i.Instance != s.instance {
		return "conflict"
	}
	_, result := s.ConditionalRecovery(ctx, i.Generation)
	return result
}

func validRecoveryWire(raw []byte) bool {
	if !strictForegroundJSON(raw) || !strictRestoreKeys(raw, "version", "id", "command", "recovery_identity") {
		return false
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return false
	}
	nested := obj["recovery_identity"]
	return strictForegroundJSON(nested) && strictRestoreKeys(nested, "owner", "instance", "generation")
}
