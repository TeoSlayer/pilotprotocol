package main

import (
	"flag"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"web4/pkg/beacon"
	"web4/pkg/config"
	"web4/pkg/logging"
	"web4/pkg/registry"
)

// rendezvous runs both registry and beacon in one process — deploy this to GCP.
func main() {
	configPath := flag.String("config", "", "path to config file (JSON)")
	registryAddr := flag.String("registry-addr", ":9000", "registry listen address (TCP)")
	beaconAddr := flag.String("beacon-addr", ":9001", "beacon listen address (UDP)")
	storePath := flag.String("store", "", "path to persist registry state (JSON snapshot)")
	tlsCert := flag.String("tls-cert", "", "TLS certificate file (empty = auto self-signed)")
	tlsKey := flag.String("tls-key", "", "TLS key file")
	enableTLS := flag.Bool("tls", false, "enable TLS for registry connections")
	standbyPrimary := flag.String("standby", "", "run as hot standby replicating from the given primary address (e.g. primary:9000)")
	logLevel := flag.String("log-level", "info", "log level (debug, info, warn, error)")
	logFormat := flag.String("log-format", "text", "log format (text, json)")
	flag.Parse()

	if *configPath != "" {
		cfg, err := config.Load(*configPath)
		if err != nil {
			log.Fatalf("load config: %v", err)
		}
		config.ApplyToFlags(cfg)
	}

	logging.Setup(*logLevel, *logFormat)

	slog.Info("starting rendezvous server")

	// Start beacon
	b := beacon.New()
	go func() {
		if err := b.ListenAndServe(*beaconAddr); err != nil {
			log.Fatalf("beacon: %v", err)
		}
	}()

	// Start registry
	r := registry.NewWithStore(*beaconAddr, *storePath)
	if *enableTLS {
		if err := r.SetTLS(*tlsCert, *tlsKey); err != nil {
			log.Fatalf("TLS setup: %v", err)
		}
	}
	if *standbyPrimary != "" {
		r.SetStandby(*standbyPrimary)
		slog.Info("running as hot standby", "primary", *standbyPrimary)
	}
	go func() {
		if err := r.ListenAndServe(*registryAddr); err != nil {
			log.Fatalf("registry: %v", err)
		}
	}()

	mode := "primary"
	if *standbyPrimary != "" {
		mode = "standby"
	}
	slog.Info("rendezvous running", "registry", *registryAddr, "beacon", *beaconAddr, "mode", mode)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	slog.Info("shutting down")
	r.Close()
	b.Close()
}
