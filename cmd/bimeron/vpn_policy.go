package main

import (
	"encoding/json"
	"fmt"
	"os"
	"bimeron/internal/routing"
)

func vpnPolicy(path string) (*routing.Policy, error) {
	c := routing.Config{Default: routing.Proxy}
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("could not read VPN policy")
		}
		if err := json.Unmarshal(b, &c); err != nil {
			return nil, fmt.Errorf("invalid VPN policy JSON")
		}
	}
	return routing.Compile(c)
}
