package dnsconfig

import (
	"reflect"
	"testing"
)

func TestResolverList(t *testing.T) {
	got, err := Parse("1.1.1.1, 8.8.8.8")
	if err != nil || !reflect.DeepEqual(got, []string{"1.1.1.1", "8.8.8.8"}) {
		t.Fatalf("resolver list: %v %v", got, err)
	}
}
func TestInvalidResolvers(t *testing.T) {
	for _, value := range []string{"", "1.1.1.1,", "1.1.1.1,,8.8.8.8", "example.com", "::1", "0.0.0.0", "1.1.1.1,1.1.1.1", "1.1.1.1,8.8.8.8,9.9.9.9,8.8.4.4,1.0.0.1"} {
		if _, err := Parse(value); err == nil {
			t.Fatal("invalid DNS accepted")
		}
	}
}
