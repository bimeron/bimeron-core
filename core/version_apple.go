//go:build bimeron_apple_release && darwin

package core

import (
	"bimeron/internal/appleversion"
	_ "embed"
)

//go:embed apple-version.record
var appleVersionRecord string

func buildVersion() string {
	v, err := appleversion.Runtime(appleVersionRecord)
	if err != nil {
		panic(err)
	}
	return v
}
