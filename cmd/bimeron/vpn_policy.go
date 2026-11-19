package main

import (
	"bimeron/internal/routing"
	"bimeron/internal/safefile"
	"encoding/json"
	"errors"
	"fmt"
)

// maxPolicyFile bounds a JSON routing policy file.
const maxPolicyFile = 4 << 20

// readPolicy decodes the JSON routing policy file at path into c. The file is
// read like a profile-referenced file: a local data file of at most
// maxPolicyFile bytes. name labels the policy in errors.
func readPolicy(path, name string, c *routing.Config) error {
	b, err := safefile.Read(path, maxPolicyFile)
	switch {
	case errors.Is(err, safefile.ErrTooLarge):
		return fmt.Errorf("%s file exceeds the 4 MiB size limit", name)
	case errors.Is(err, safefile.ErrNotLocal), errors.Is(err, safefile.ErrNotRegular):
		return fmt.Errorf("%s file must be a local data file", name)
	case err != nil:
		return fmt.Errorf("could not read %s", name)
	}
	if err := json.Unmarshal(b, c); err != nil {
		return fmt.Errorf("invalid %s JSON", name)
	}
	return nil
}

func vpnPolicy(path string) (*routing.Policy, error) {
	c := routing.Config{Default: routing.Proxy}
	if path != "" {
		if err := readPolicy(path, "VPN policy", &c); err != nil {
			return nil, err
		}
	}
	return routing.Compile(c)
}
