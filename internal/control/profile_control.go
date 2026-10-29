package control

import (
	"bimeron/internal/systemvpn"
	"context"
	"errors"
	"sync"
)

func (s *Server) bindProfileControl(cfg systemvpn.Config, remove bool, preview func(systemvpn.Config) (systemvpn.ProfilePlan, error), apply func(systemvpn.Config, bool, string) (systemvpn.ProfilePlan, error)) func() {
	s.foreground = true
	var mu sync.Mutex
	var once sync.Once
	var tasks sync.WaitGroup
	var closing bool

	var plan *systemvpn.ProfilePlan
	operation, code := "preview_pending", ""
	s.foregroundDispatch = func(call context.Context, r Request) Response {
		mu.Lock()
		defer mu.Unlock()
		a := Response{ID: r.ID, Version: Version, Instance: s.instance, Status: s.engine.Status()}
		if r.Installation != s.installation {
			a.Error = "installation_mismatch"
			return a
		}
		finish := func() Response { a.Operation = operation; a.Profile = plan; return a }
		if r.Version != Version {
			a.Error = "unsupported_protocol"
			return finish()
		}
		if r.ID == "" || len(r.ID) > 64 || r.Config != "" || r.After != 0 || r.ChallengeID != "" || len(r.Answers) != 0 || r.Session != "" {
			a.Error = "invalid_request"
			return finish()
		}
		if r.Command != "hello" && r.Instance != s.instance {
			a.Error = "stale_instance"
			return finish()
		}
		if closing {
			a.Error = "owner_closing"
			return finish()
		}
		switch r.Command {
		case "hello":
			if r.PlanToken != "" || r.Instance != "" || r.AcceptRevision != "" {
				a.Error = "invalid_request"
				return finish()
			}
			once.Do(func() {
				operation = "previewing"
				tasks.Add(1)
				go func() {
					defer tasks.Done()
					result, e := preview(cfg)
					if e == nil && remove {
						if result.Action != "unchanged" {
							e = errors.New("ikev2_profile_not_owned")
						} else {
							result.Action = "remove"
						}
					}
					mu.Lock()
					defer mu.Unlock()
					if e != nil {
						operation = "failed"
						code = safeProfileCode(e)
					} else {
						plan = &result
						operation = "previewed"
					}
				}()
			})
			a = s.dispatch(call, r)
		case "status":
			if r.PlanToken != "" || r.AcceptRevision != "" {
				a.Error = "invalid_request"
			}
		case "apply", "remove":
			if !s.acceptedRevision(r.AcceptRevision) {
				a.Error = "core_identity_mismatch"
				return finish()
			}
			if (r.Command == "remove") != remove {
				a.Error = "invalid_request"
				return finish()
			}
			if operation != "previewed" || plan == nil || r.PlanToken != plan.StateToken {
				a.Error = "ikev2_profile_preview_required"
				return finish()
			}
			expected := plan.StateToken
			operation = "applying"
			tasks.Add(1)
			go func() {
				defer tasks.Done()
				result, e := apply(cfg, remove, expected)
				mu.Lock()
				defer mu.Unlock()
				if e != nil {
					operation = "failed"
					code = safeProfileCode(e)
				} else {
					plan = &result
					operation = "succeeded"
				}
			}()
		case "close_owner":
			if r.PlanToken != "" || r.AcceptRevision != "" {
				a.Error = "invalid_request"
				return finish()
			}
			if operation == "applying" || operation == "previewing" {
				a.Error = "operation_pending"
			} else {
				closing = true
				a.closeAccepted = true
			}
		default:
			a.Error = "unknown_command"
		}
		if a.Error == "" && r.Command != "close_owner" {
			a.Error = code
		}
		return finish()
	}
	return tasks.Wait
}

func safeProfileCode(err error) string {
	switch err.Error() {
	case "ikev2_profile_name_not_owned", "ikev2_profile_not_owned", "ikev2_profile_manifest_conflict", "ikev2_profile_incomplete_transaction_manual_review_required", "ikev2_owned_profile_modified_or_missing", "ikev2_existing_ras_connection", "ikev2_profile_preview_required", "ikev2_profile_preview_changed", "ikev2_profile_rollback_incomplete_manual_review_required", "ikev2_profile_rollback_manifest_cleanup_failed", "ikev2_profile_creation_failed_rolled_back", "ikev2_profile_removed_manifest_cleanup_failed", "ikev2_profile_journal_write_failed", "ikev2_saved_credentials_required", "ikev2_saved_eap_identity_required", "ikev2_windows_profile_not_found", "ikev2_profile_identity_changed":
		return err.Error()
	default:
		return "ikev2_profile_operation_failed"
	}
}
