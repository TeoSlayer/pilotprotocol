// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pilot-protocol/updater"
)

var version = "dev"

func main() {
	installDir := flag.String("install-dir", "", "directory containing pilot binaries (required)")
	repo := flag.String("repo", "pilot-protocol/pilotprotocol", "GitHub owner/repo for releases")
	pin := flag.String("pin", "", "pin to a specific release tag (e.g. v1.10.5); empty = follow latest")
	interval := flag.Duration("interval", 1*time.Hour, "check interval")
	logLevel := flag.String("log-level", "info", "log level (debug, info, warn, error)")
	logFormat := flag.String("log-format", "text", "log format (text, json)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	if *installDir == "" {
		fmt.Fprintln(os.Stderr, "error: --install-dir is required")
		os.Exit(2)
	}

	setupLogging(*logLevel, *logFormat)

	u := updater.New(updater.Config{
		CheckInterval: *interval,
		Repo:          *repo,
		InstallDir:    *installDir,
		Version:       version,
		PinnedVersion: *pin,
	})

	u.Start()
	slog.Info("updater started",
		"install_dir", *installDir,
		"repo", *repo,
		"interval", interval.String(),
	)
	if *pin != "" {
		slog.Info("version pinned", "tag", *pin)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	slog.Info("shutting down")
	u.Stop()
}

func setupLogging(level, format string) {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler
	if format == "json" {
		h = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		h = slog.NewTextHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(h))
}
