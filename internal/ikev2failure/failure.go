// Package ikev2failure models the frozen offline draft only. It has no runtime authority.
package ikev2failure

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"unicode/utf8"
)

type Domain string
type Stage string

const (
	WindowsRAS        Domain = "windows_ras"
	ProfileInspection Stage  = "profile_inspection"
	Dial              Stage  = "dial"
	ConnectionStatus  Stage  = "connection_status"
	CleanupHangup     Stage  = "cleanup_hangup"
	CleanupStatus     Stage  = "cleanup_status"
	MaxAttempt        uint32 = 2147483647
	MaxMemberBytes           = 512
)

// Record preserves numeric evidence without inferring a cause or connection state.
type Record struct {
	Domain  Domain `json:"domain"`
	Code    uint32 `json:"code"`
	Stage   Stage  `json:"stage"`
	Attempt uint32 `json:"attempt"`
}

// Failure keeps operation and cleanup evidence independent. Nil means unknown.
type Failure struct {
	Version   uint32  `json:"version"`
	Operation *Record `json:"operation,omitempty"`
	Cleanup   *Record `json:"cleanup,omitempty"`
}

// Validate checks evidence against the explicit enclosing attempt, including absence.
func (f *Failure) Validate(attempt uint32) error {
	if attempt == 0 || attempt > MaxAttempt {
		return errors.New("invalid enclosing attempt")
	}
	if f == nil {
		return nil
	}
	if f.Version != 1 || (f.Operation == nil && f.Cleanup == nil) {
		return errors.New("invalid failure version or empty failure")
	}
	for i, r := range []*Record{f.Operation, f.Cleanup} {
		if r == nil {
			continue
		}
		if r.Domain != WindowsRAS || r.Code == 0 || r.Attempt != attempt {
			return errors.New("invalid record domain, code or attempt")
		}
		if i == 0 {
			if r.Stage != ProfileInspection && r.Stage != Dial && r.Stage != ConnectionStatus {
				return errors.New("invalid operation stage")
			}
		} else if r.Stage != CleanupHangup && r.Stage != CleanupStatus {
			return errors.New("invalid cleanup stage")
		}
	}
	return nil
}

// DecodeMember consumes only a frozen-fixture member, not a production envelope.
// A nil slice means an absent member; explicit null and empty input are invalid.
// Exact field checks additionally reject JSON's usual case folding and duplicates.
func DecodeMember(data []byte, attempt uint32) (*Failure, error) {
	if data == nil {
		return nil, (*Failure)(nil).Validate(attempt)
	}
	if len(data) > MaxMemberBytes || !utf8.Valid(data) {
		return nil, errors.New("invalid member size or UTF-8")
	}
	if !validSurrogateEscapes(data) {
		return nil, errors.New("invalid Unicode escape pairing")
	}
	fields, err := object(data, "version", "operation", "cleanup")
	if err != nil {
		return nil, err
	}
	var f Failure
	if err = json.Unmarshal(fields["version"], &f.Version); err != nil {
		return nil, errors.New("invalid version")
	}
	for name, target := range map[string]**Record{"operation": &f.Operation, "cleanup": &f.Cleanup} {
		raw, ok := fields[name]
		if !ok {
			continue
		}
		rf, err := object(raw, "domain", "code", "stage", "attempt")
		if err != nil || len(rf) != 4 {
			return nil, errors.New("invalid record fields")
		}
		var r Record
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, errors.New("invalid record types")
		}
		*target = &r
	}
	if err := f.Validate(attempt); err != nil {
		return nil, err
	}
	return &f, nil
}

// validSurrogateEscapes prevents encoding/json from repairing unpaired surrogates.
// JSON syntax and all other string validation remain with encoding/json.
func validSurrogateEscapes(data []byte) bool {
	inString := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || data[i] != '\\' {
			continue
		}
		i++ // Consume escaped backslashes and quotes without interpreting them again.
		if i >= len(data) || data[i] != 'u' {
			continue
		}
		unit, ok := unicodeEscapeUnit(data[i:])
		if !ok {
			return false
		}
		i += 4
		if unit >= 0xDC00 && unit <= 0xDFFF {
			return false
		}
		if unit >= 0xD800 && unit <= 0xDBFF {
			if i+2 >= len(data) || data[i+1] != '\\' {
				return false
			}
			low, ok := unicodeEscapeUnit(data[i+2:])
			if !ok || low < 0xDC00 || low > 0xDFFF {
				return false
			}
			i += 6
		}
	}
	return true
}

func unicodeEscapeUnit(data []byte) (uint64, bool) {
	if len(data) < 5 || data[0] != 'u' {
		return 0, false
	}
	unit, err := strconv.ParseUint(string(data[1:5]), 16, 16)
	return unit, err == nil
}

func object(data []byte, allowed ...string) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return nil, errors.New("expected object")
	}
	fields := make(map[string]json.RawMessage)
	for d.More() {
		t, err := d.Token()
		if err != nil {
			return nil, errors.New("invalid field")
		}
		name, ok := t.(string)
		if !ok {
			return nil, errors.New("invalid field name")
		}
		known := false
		for _, a := range allowed {
			if name == a {
				known = true
			}
		}
		if _, exists := fields[name]; !known || exists {
			return nil, errors.New("unknown or duplicate field")
		}
		var raw json.RawMessage
		if err := d.Decode(&raw); err != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil, errors.New("invalid or null field")
		}
		fields[name] = raw
	}
	if _, err := d.Token(); err != nil {
		return nil, errors.New("invalid object end")
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("trailing data")
	}
	return fields, nil
}
