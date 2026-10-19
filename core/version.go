package core

import (
	"runtime"
	"runtime/debug"
)

// Version may be set at release time with -ldflags -X bimeron/core.Version=...
var Version = "0.1.0-dev"

type BuildDetails struct {
	Version      string `json:"version"`
	Revision     string `json:"revision,omitempty"`
	CommitTime   string `json:"commit_time,omitempty"`
	Modified     bool   `json:"modified"`
	GoVersion    string `json:"go_version"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
}

func GetBuildInfo() BuildDetails {
	info := BuildDetails{Version: Version, GoVersion: runtime.Version(), Platform: runtime.GOOS, Architecture: runtime.GOARCH}
	if b, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range b.Settings {
			switch setting.Key {
			case "vcs.revision":
				info.Revision = setting.Value
			case "vcs.time":
				info.CommitTime = setting.Value
			case "vcs.modified":
				info.Modified = setting.Value == "true"
			}
		}
	}
	return info
}
