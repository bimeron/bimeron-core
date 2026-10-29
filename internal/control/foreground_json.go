package control

import (
	"encoding/json"
	"io"
	"unicode/utf8"
)

func strictForegroundJSON(line []byte) bool {
	if !utf8.Valid(line) {
		return false
	}
	d := json.NewDecoder(bytesReader(line))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return false
		}
		name, ok := key.(string)
		if !ok || seen[name] {
			return false
		}
		seen[name] = true
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return false
		}
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') {
		return false
	}
	var extra any
	return d.Decode(&extra) == io.EOF
}
