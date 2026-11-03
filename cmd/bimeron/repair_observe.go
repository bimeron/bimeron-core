package main

import (
	"context"
	"fmt"
	"time"
)

func observeRepairTransition(ctx context.Context, read func(context.Context) (bool, error)) error {
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		if err := bounded.Err(); err != nil {
			return fmt.Errorf("service transition observation: %w", err)
		}
		stable, err := read(bounded)
		if err != nil {
			return err
		}
		if stable {
			return nil
		}
		select {
		case <-bounded.Done():
			return fmt.Errorf("service transition observation: %w", bounded.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
}
