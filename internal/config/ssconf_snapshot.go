package config

import (
	"errors"
	"strings"

	"bimeron/internal/accesskey"
)

// InstallSSConfSnapshot pins a validated Shadowsocks profile to its exact raw source.
func (c *File) InstallSSConfSnapshot(source string, p accesskey.Profile) error {
	raw := c.Access.SSConf
	if raw == "" {
		raw = c.Access.Key
	}
	if !strings.HasPrefix(strings.TrimSpace(raw), "ssconf://") || strings.TrimSpace(raw) != source {
		return errors.New("snapshot source mismatch")
	}
	p, err := c.withShadowTLS(p, nil)
	if err != nil {
		return err
	}
	c.profile = &p
	return nil
}
