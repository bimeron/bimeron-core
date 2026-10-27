package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	core "bimeron/core"
)

func runSession(cfg core.SessionConfig) error {
	cfg.SSHPrompt = terminalSSHPrompt
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	e := core.New(core.Options{})
	if err := e.Start(ctx, cfg); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- e.Wait(context.Background()) }()
	fmt.Println("Ctrl+C stops the session and restores owned network settings.")
	printEvent := func(event core.Event) {
		fmt.Printf("%s [%s] %s\n", event.Time.Format("15:04:05"), event.State, event.Message)
		if event.State == core.Reconnecting && event.Code == "state" {
			fmt.Println("Reason:", event.LastError)
		}
	}
	for {
		select {
		case event := <-e.Events():
			printEvent(event)
		case err := <-done:
			for {
				select {
				case event := <-e.Events():
					printEvent(event)
				default:
					return err
				}
			}
		}
	}
}
