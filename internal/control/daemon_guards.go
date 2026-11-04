package control

import "encoding/json"

func validDaemonGuardRequest(r Request) bool {
	if r.Instance == "" {
		return r.Session == ""
	}
	switch r.Command {
	case "start":
		return r.Session == ""
	case "stop":
		return r.Session != ""
	default:
		return false
	}
}

// validDaemonGuardJSON rejects guard erasure through null or empty identities.
func validDaemonGuardJSON(line []byte) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(line, &fields) != nil {
		return false
	}
	instance, hasInstance := fields["instance"]
	session, hasSession := fields["session"]
	if hasInstance {
		var value string
		if json.Unmarshal(instance, &value) != nil || value == "" {
			return false
		}
	}
	if hasSession {
		var value *string
		if !hasInstance || json.Unmarshal(session, &value) != nil || value == nil {
			return false
		}
	}
	return true
}
