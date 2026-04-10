package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/example/vaultwatch/internal/config"
	"github.com/example/vaultwatch/internal/monitor"
	"github.com/example/vaultwatch/internal/notifier"
	"github.com/example/vaultwatch/internal/reporter"
	"github.com/example/vaultwatch/internal/scheduler"
	"github.com/example/vaultwatch/internal/vault"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	vaultClient, err := vault.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("creating vault client: %w", err)
	}

	scanner := vault.NewSecretScanner(vaultClient)
	renewer := vault.NewLeaseRenewer(vaultClient)
	notify := notifier.New(cfg)
	report := reporter.New(cfg, os.Stdout)

	job := monitor.NewScanJob(scanner, renewer, notify, report, cfg)

	sched := scheduler.New(cfg.Interval)
	runner := scheduler.NewFunc(job.Run)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	fmt.Printf("vaultwatch started, monitoring %s every %s\n", cfg.VaultAddress, cfg.Interval)
	return sched.Run(ctx, runner)
}
