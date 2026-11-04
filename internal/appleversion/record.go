package appleversion

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

const Prefix = "BIMERON.APPLE.CORE.VERSION/v1\x00"
const suffix = "\x00END.APPLE.CORE.RECORD/v1\x00"
const MaxVersion = 128
const MaxSection = 64 << 20
const MaxFile = 256 << 20

var semver = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+)(\.[0-9A-Za-z-]+)*)?$`)

func ValidVersion(v string) bool {
	if len(v) == 0 || len(v) > MaxVersion || !semver.MatchString(v) {
		return false
	}
	pre := []byte(v)
	if i := bytes.IndexByte(pre, '-'); i >= 0 {
		for _, id := range bytes.Split(pre[i+1:], []byte(".")) {
			numeric := true
			for _, c := range id {
				if c < '0' || c > '9' {
					numeric = false
				}
			}
			if numeric && len(id) > 1 && id[0] == '0' {
				return false
			}
		}
	}
	return true
}

func Frame(v string) ([]byte, error) {
	if !ValidVersion(v) {
		return nil, fmt.Errorf("invalid SemVer")
	}
	return []byte(fmt.Sprintf("%s%03d:%s%s", Prefix, len(v), v, suffix)), nil
}

// Parse permits surrounding section bytes, but exactly one full domain prefix.
func Parse(data []byte) (string, error) {
	if len(data) > MaxSection || bytes.Count(data, []byte(Prefix)) != 1 {
		return "", fmt.Errorf("record missing, duplicated, or section oversized")
	}
	p := bytes.Index(data, []byte(Prefix)) + len(Prefix)
	if len(data)-p < 4 {
		return "", fmt.Errorf("truncated length")
	}
	n := 0
	for _, c := range data[p : p+3] {
		if c < '0' || c > '9' {
			return "", fmt.Errorf("invalid length")
		}
		n = n*10 + int(c-'0')
	}
	if data[p+3] != ':' || n < 1 || n > MaxVersion || len(data)-(p+4) < n+len(suffix) {
		return "", fmt.Errorf("invalid record bounds")
	}
	v := string(data[p+4 : p+4+n])
	canonical, err := Frame(v)
	if err != nil {
		return "", err
	}
	start := p - len(Prefix)
	if !bytes.Equal(data[start:start+len(canonical)], canonical) {
		return "", fmt.Errorf("noncanonical framing")
	}
	return v, nil
}

// Runtime extracts exactly one complete generated record without materializing the full prefix.
func Runtime(record string) (string, error) {
	const head = "BIMERON.APPLE."
	const tail = "CORE.VERSION/v1\x00"
	p := len(head) + len(tail)
	if len(record) < p+4 || !strings.HasPrefix(record, head) || !strings.HasPrefix(record[len(head):], tail) {
		return "", fmt.Errorf("invalid record prefix")
	}
	n := 0
	for _, c := range record[p : p+3] {
		if c < '0' || c > '9' {
			return "", fmt.Errorf("invalid length")
		}
		n = n*10 + int(c-'0')
	}
	end := p + 4 + n
	if n < 1 || n > MaxVersion || record[p+3] != ':' || end > len(record) || record[end:] != suffix {
		return "", fmt.Errorf("invalid record bounds")
	}
	v := record[p+4 : end]
	if !ValidVersion(v) {
		return "", fmt.Errorf("invalid SemVer")
	}
	return v, nil
}
