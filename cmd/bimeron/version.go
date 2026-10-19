package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"bimeron/core"
	"bimeron/internal/control"
	"time"
)

func versionCommand(args []string) error {
	if len(args) == 0 {
		return json.NewEncoder(os.Stdout).Encode(core.GetBuildInfo())
	}
	if len(args) != 1 || args[0] != "-daemon" {
		return fmt.Errorf("usage: bimeron version [-daemon]")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a, err := control.Call(ctx, control.Request{Command: "hello"})
	if err != nil {
		return err
	}
	if a.Core == nil {
		return fmt.Errorf("running core does not report build information; update the service")
	}
	return json.NewEncoder(os.Stdout).Encode(a.Core)
}
