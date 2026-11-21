package dnsconfig

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"bimeron/internal/problem"
)

func TestSharedDoHVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/doh-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Name, Code, Field string
		DoH, Bootstrap    *string
		DisableIPv6       bool       `json:"disable_ipv6"`
		URLs              []string   `json:"expected_urls"`
		IPs               [][]string `json:"expected_ips"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			got, err := ParseDoH(v.DoH, v.Bootstrap, true, v.DisableIPv6)
			if v.Code != "" {
				if p := problem.Of(err); err == nil || p.Code != v.Code || p.Field != v.Field {
					t.Fatalf("unexpected error: %+v", p)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var urls []string
			var ips [][]string
			for _, endpoint := range got {
				urls = append(urls, endpoint.URL)
				group := make([]string, 0, len(endpoint.IPs))
				for _, ip := range endpoint.IPs {
					group = append(group, ip.String())
				}
				ips = append(ips, group)
			}
			if !reflect.DeepEqual(urls, v.URLs) || !reflect.DeepEqual(ips, v.IPs) {
				t.Fatalf("got %v and %v", urls, ips)
			}
		})
	}
}
