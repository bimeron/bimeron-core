package appleversion

import (
	"bytes"
	"strings"
	"testing"
)

func TestCanonicalAgreement(t *testing.T) {
	for _, v := range []string{"0.0.0", "1.2.3", "1.2.3-beta.1", "1.2.3-0", "1.2.3-" + strings.Repeat("a", 122)} {
		b, e := Frame(v)
		if e != nil {
			t.Fatal(v, e)
		}
		for _, parse := range []func([]byte) (string, error){Parse, func(b []byte) (string, error) { return Runtime(string(b)) }} {
			got, e := parse(b)
			if e != nil || got != v {
				t.Fatal(v, got, e)
			}
		}
	}
	for _, v := range []string{"", "01.2.3", "1.2", "1.2.3+build", "1.2.3-01", "1.2.3-", "1.2.3-a..b", "1.2.3-" + strings.Repeat("a", 123)} {
		if _, e := Frame(v); e == nil {
			t.Fatal("accepted", v)
		}
	}
	b, _ := Frame("1.2.3")
	for _, bad := range [][]byte{nil, b[:len(b)-1], append(append([]byte{}, b...), b...), bytes.Replace(b, []byte("005:"), []byte("006:"), 1), bytes.Replace(b, []byte("1.2.3"), []byte("01.23"), 1), bytes.Repeat([]byte("x"), MaxSection+1)} {
		if _, e := Parse(bad); e == nil {
			t.Fatal("accepted malformed section")
		}
	}
	for _, bad := range []string{string(b) + "x", "x" + string(b), string(b[:len(b)-1]), strings.Replace(string(b), "005:", "000:", 1)} {
		if _, e := Runtime(bad); e == nil {
			t.Fatal("accepted malformed runtime record")
		}
	}
}
