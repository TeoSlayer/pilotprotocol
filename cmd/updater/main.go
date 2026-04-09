package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/logging"
	"github.com/TeoSlayer/pilotprotocol/pkg/updater"
)

var version = "dev"

func main() {
	interval := flag.Duration("interval", 1*time.Hour, "check interval for new releases")
	repo := flag.String("repo", "TeoSlayer/pilotprotocol", "GitHub owner/repo to check for releases")
	installDir := flag.String("install-dir", "", "directory containing pilot binaries (required)")
	showVersion := flag.Bool("version", false, "print version and exit")
	logLevel := flag.String("log-level", "info", "log level (debug, info, warn, error)")
	logFormat := flag.String("log-format", "text", "log format (text, json)")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	if *installDir == "" {
		log.Fatal("-install-dir is required")
	}

	logging.Setup(*logLevel, *logFormat)

	slog.Info("pilot-updater starting",
		"version", version,
		"repo", *repo,
		"install_dir", *installDir,
		"interval", *interval,
	)

	u := updater.New(updater.Config{
		CheckInterval: *interval,
		Repo:          *repo,
		InstallDir:    *installDir,
		Version:       version,
	})

	u.Start()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	slog.Info("shutting down")
	u.Stop()
}
