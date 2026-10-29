package control

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"

	"bimeron/core"
)

// foregroundConfig binds already-opened configuration bytes to the reviewed
// digest. The privileged caller must secure the file handle and executable
// before calling this function. It deliberately performs no filesystem access.
func foregroundConfig(path, expected string, data []byte) (core.SessionConfig, error) {
	invalid := errors.New("foreground_configuration_rejected")
	if !filepath.IsAbs(path) || len(data) > 64*1024 || len(expected) != 64 {
		return core.SessionConfig{}, invalid
	}
	digest, err := hex.DecodeString(expected)
	if err != nil {
		return core.SessionConfig{}, invalid
	}
	actual := sha256.Sum256(data)
	if string(digest) != string(actual[:]) {
		return core.SessionConfig{}, errors.New("foreground_configuration_changed")
	}
	cfg, err := core.LoadConfigData(data)
	if err != nil || cfg.IKEv2 == nil {
		return core.SessionConfig{}, invalid
	}
	cfg.ProfileID, err = core.ProfileIdentity(path)
	if err != nil {
		return core.SessionConfig{}, invalid
	}
	return cfg, nil
}
