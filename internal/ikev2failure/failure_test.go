package ikev2failure

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestFrozenFixture(t *testing.T) {
	data, err := os.ReadFile("../../core/testdata/ikev2-error-draft-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%X", sha256.Sum256(data)); got != "946B21470B8E39DF4AC55FB7762D1CF6D90B91D17D623E0A22B0DA45F97E8E2E" {
		t.Fatal("frozen fixture hash mismatch")
	}
	type fixtureCase struct {
		Name          string
		Attempt       uint32
		NativeFailure json.RawMessage `json:"native_failure"`
	}
	var fixture struct {
		Draft          string
		Valid, Invalid []fixtureCase
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Draft != "ikev2-offline-error-v1" || len(fixture.Valid) != 5 || len(fixture.Invalid) != 10 {
		t.Fatal("unexpected fixture scaffolding")
	}
	for _, c := range fixture.Valid {
		t.Run(c.Name, func(t *testing.T) {
			f, err := DecodeMember(c.NativeFailure, c.Attempt)
			if err != nil {
				t.Fatal(err)
			}
			if c.NativeFailure == nil {
				if f != nil {
					t.Fatal("absence became evidence")
				}
				return
			}
			encoded, err := json.Marshal(f)
			if err != nil {
				t.Fatal(err)
			}
			again, err := DecodeMember(encoded, c.Attempt)
			if err != nil || !reflect.DeepEqual(f, again) {
				t.Fatal("round trip changed evidence", err)
			}
			switch c.Name {
			case "operation_775_unknown_cause":
				if f.Operation.Code != 775 || f.Cleanup != nil {
					t.Fatal("operation evidence changed")
				}
			case "cleanup_only_668":
				if f.Operation != nil || f.Cleanup.Code != 668 {
					t.Fatal("cleanup established operation evidence")
				}
			case "operation_and_cleanup":
				if f.Operation.Code != 775 || f.Cleanup.Code != 668 {
					t.Fatal("cleanup overwrote operation")
				}
			case "unknown_uint32_max":
				if f.Operation.Code != ^uint32(0) {
					t.Fatal("numeric code lost")
				}
			}
		})
	}
	for _, c := range fixture.Invalid {
		t.Run(c.Name, func(t *testing.T) {
			if f, err := DecodeMember(c.NativeFailure, c.Attempt); err == nil || f != nil {
				t.Fatal("accepted invalid fixture")
			}
		})
	}
}

func TestFrozenRawFixture(t *testing.T) {
	data, err := os.ReadFile("../../core/testdata/ikev2-error-raw-addendum-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%X", sha256.Sum256(data)); got != "FACD9603E45A910235D38326C1271AC52ABC1AC5E69DAAA55544F0B6D13A8A9B" {
		t.Fatal("frozen raw fixture hash mismatch")
	}
	var fixture struct {
		Draft string
		Cases []struct {
			Name    string
			Attempt uint32
			Valid   bool
			Raw     string
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Draft != "ikev2-offline-error-raw-addendum-v1" || len(fixture.Cases) != 33 {
		t.Fatal("unexpected raw fixture scaffolding")
	}
	for _, c := range fixture.Cases {
		t.Run(c.Name, func(t *testing.T) {
			// Pass the actual member string: re-encoding would lose duplicate keys.
			f, err := DecodeMember([]byte(c.Raw), c.Attempt)
			if c.Valid {
				if err != nil || f == nil || f.Operation == nil || f.Operation.Code != 775 {
					t.Fatal("valid raw member lost evidence", err)
				}
			} else if err == nil || f != nil {
				t.Fatal("accepted invalid raw member")
			}
		})
	}
}

func TestSurrogateEscapes(t *testing.T) {
	for _, c := range []struct {
		name, raw string
		valid     bool
	}{
		{"high", `"\uD800"`, false},
		{"low", `"\uDC00"`, false},
		{"high_then_text", `"\uD800x"`, false},
		{"high_then_bmp", `"\uD800\u0061"`, false},
		{"two_high", `"\uD800\uDBFF"`, false},
		{"reversed", `"\uDC00\uD800"`, false},
		{"pair", `"\uD800\uDC00"`, true},
		{"pair_upper_boundary", `"\udbff\udfff"`, true},
		{"two_pairs", `"\uD800\uDC00\uDBFF\uDFFF"`, true},
		{"pair_then_low", `"\uD800\uDC00\uDC00"`, false},
		{"escaped_backslash", `"\\uD800"`, true},
		{"escaped_low_backslash", `"\\uDC00"`, true},
		{"backslash_then_high", `"\\\uD800"`, false},
		{"backslash_then_pair", `"\\\uD800\uDC00"`, true},
		{"escaped_pair_backslash", `"\uD800\\uDC00"`, false},
		{"escaped_quote_then_high", `"\"\uD800"`, false},
		{"separate_strings", `{"\uD800":"\uDC00"}`, false},
		{"bmp_boundaries", `"\uD7FF\uE000"`, true},
		{"truncated_escape", `"\uD80`, false},
		{"truncated_pair", `"\uD800\uDC0`, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := validSurrogateEscapes([]byte(c.raw)); got != c.valid {
				t.Fatalf("surrogate validation = %v, want %v", got, c.valid)
			}
		})
	}
	for _, raw := range []string{
		`{"\uD800version":1}`,
		`{"version":1,"operation":{"domain":"\uDC00","code":775,"stage":"dial","attempt":1}}`,
		`{"version":1,"cleanup":{"domain":"windows_ras","code":775,"stage":"\uD800","attempt":1}}`,
	} {
		if f, err := DecodeMember([]byte(raw), 1); f != nil || err == nil || err.Error() != "invalid Unicode escape pairing" {
			t.Fatalf("member did not reject surrogates before JSON decoding: %v", err)
		}
	}
}

func TestStrictMember(t *testing.T) {
	base := `{"version":1,"operation":{"domain":"windows_ras","code":775,"stage":"dial","attempt":1}}`
	cases := []string{"", "null", "[]", base + " {}", strings.Repeat(" ", MaxMemberBytes+1) + base,
		strings.Replace(base, `"version":1`, `"Version":1`, 1),
		strings.Replace(base, `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(base, `"code":775`, `"code":775,"code":668`, 1),
		strings.Replace(base, `"operation":`, `"diagnostic":"secret","operation":`, 1),
		strings.Replace(base, `"operation":`, `"cleanup":null,"operation":`, 1),
		strings.Replace(base, `"stage":"dial"`, `"stage":"cleanup_hangup"`, 1),
		strings.Replace(base, `"operation"`, `"cleanup"`, 1),
		strings.Replace(base, `"code":775,`, "", 1),
		strings.Replace(base, `"stage":"dial"`, "\"stage\":\"\xff\"", 1),
	}
	for _, field := range []struct {
		old    string
		values []string
	}{
		{`"version":1`, []string{`null`, `"1"`, `true`, `[]`, `{}`, `0`, `2`, `1.0`, `1e0`, `-1`, `4294967296`}},
		{`"code":775`, []string{`null`, `"775"`, `true`, `[]`, `{}`, `0`, `-1`, `1.5`, `1e2`, `4294967296`}},
		{`"attempt":1`, []string{`null`, `"1"`, `true`, `[]`, `{}`, `0`, `-1`, `1.5`, `2147483648`, `4294967296`, `2`}},
		{`"domain":"windows_ras"`, []string{`null`, `1`, `true`, `[]`, `{}`, `"other"`}},
		{`"stage":"dial"`, []string{`null`, `1`, `true`, `[]`, `{}`, `"other"`}},
		{`"operation":{"domain":"windows_ras","code":775,"stage":"dial","attempt":1}`, []string{`null`, `1`, `true`, `[]`, `"record"`, `{}`}},
	} {
		key := strings.SplitN(field.old, ":", 2)[0]
		for _, value := range field.values {
			cases = append(cases, strings.Replace(base, field.old, key+":"+value, 1))
		}
	}
	for i, raw := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if f, err := DecodeMember([]byte(raw), 1); err == nil || f != nil {
				t.Fatal("accepted invalid member")
			}
		})
	}
	padding := strings.Repeat(" ", MaxMemberBytes-len(base))
	if _, err := DecodeMember([]byte(base+padding), 1); err != nil {
		t.Fatal("rejected size boundary", err)
	}
}

func TestTypedValidation(t *testing.T) {
	r := Record{Domain: WindowsRAS, Code: 775, Stage: Dial, Attempt: 1}
	f := &Failure{Version: 1, Operation: &r}
	if err := f.Validate(1); err != nil {
		t.Fatal(err)
	}
	if err := f.Validate(2); err == nil {
		t.Fatal("accepted late attempt")
	}
	for _, attempt := range []uint32{0, MaxAttempt + 1, ^uint32(0)} {
		if err := (*Failure)(nil).Validate(attempt); err == nil {
			t.Fatal("accepted invalid enclosing attempt")
		}
	}
	for _, change := range []func(*Failure){
		func(f *Failure) { f.Version = 2 },
		func(f *Failure) { f.Operation = nil },
		func(f *Failure) { f.Operation.Domain = "other" },
		func(f *Failure) { f.Operation.Code = 0 },
		func(f *Failure) { f.Operation.Stage = CleanupStatus },
		func(f *Failure) { f.Operation.Attempt = MaxAttempt + 1 },
	} {
		copyRecord := r
		invalid := &Failure{Version: 1, Operation: &copyRecord}
		change(invalid)
		if err := invalid.Validate(1); err == nil {
			t.Fatal("accepted invalid typed value")
		}
	}
}
