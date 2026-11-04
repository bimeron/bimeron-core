//go:build bimeron_apple_release && !darwin

package core

// Apple release selection intentionally cannot compile on other operating systems.
var _ = bimeronAppleReleaseRequiresDarwin
