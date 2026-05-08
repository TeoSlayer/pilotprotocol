// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"flag"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/beacon"
	"github.com/TeoSlayer/pilotprotocol/pkg/config"
	"github.com/TeoSlayer/pilotprotocol/pkg/logging"
	registry "github.com/TeoSlayer/pilotprotocol/pkg/registry/server"
)

var version = "dev"

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
	httpAddr := flag.String("http", "", "HTTP dashboard listen address (e.g. :3000)")
	logLevel := flag.String("log-level", "info", "log level (debug, info, warn, error)")
	logFormat := flag.String("log-format", "text", "log format (text, json)")
	adminToken := flag.String("admin-token", "", "admin token for network creation (empty = creation disabled)")
	dashboardToken := flag.String("dashboard-token", "", "token for per-network stats on dashboard (empty = public-only)")
	maintenanceBanner := flag.String("maintenance-banner", "", "free-form notice rendered on the dashboard (empty = no banner)")
	replToken := flag.String("repl-token", "", "shared token required for hot-standby replication (empty = replication disabled)")
	staleThreshold := flag.Duration("stale-threshold", 30*time.Minute, "how long since last heartbeat before a node is considered stale on the dashboard (e.g. 30m, 5m). Default 30m tolerates client reconnect storms; smaller values give faster dashboard reflection of disconnects.")
	mutexProfileFraction := flag.Int("mutex-profile-fraction", 1000, "rate for runtime mutex contention profiling (1/N events sampled; 0 = off). Always-on at low overhead so profile data is available without runtime reconfiguration.")
	blockProfileRate := flag.Int("block-profile-rate", 10000, "rate for runtime blocking profile in nanoseconds (0 = off). Captures goroutines blocked on chan/select/Cond — same rationale as -mutex-profile-fraction.")
	flag.Parse()

	if *configPath != "" {
		cfg, err := config.Load(*configPath)
		if err != nil {
			log.Fatalf("load config: %v", err)
		}
		config.ApplyToFlags(cfg)
	}

	logging.Setup(*logLevel, *logFormat)

	// Enable mutex + block profiling early so contention from startup paths
	// is captured. Net runtime cost at the chosen rates is ~1% CPU; the
	// rendezvous endpoint exposes /debug/pprof/{mutex,block} via DefaultServeMux.
	if *mutexProfileFraction > 0 {
		runtime.SetMutexProfileFraction(*mutexProfileFraction)
	}
	if *blockProfileRate > 0 {
		runtime.SetBlockProfileRate(*blockProfileRate)
	}

	slog.Info("starting rendezvous server", "version", version)

	// Start beacon
	b := beacon.New()
	go func() {
		if err := b.ListenAndServe(*beaconAddr); err != nil {
			log.Fatalf("beacon: %v", err)
		}
	}()

	// Start registry
	r := registry.NewWithStore(*beaconAddr, *storePath)
	r.SetStaleNodeThreshold(*staleThreshold)
	r.SetBeaconStats(b)
	if *adminToken != "" {
		r.SetAdminToken(*adminToken)
	}
	if *dashboardToken != "" {
		r.SetDashboardToken(*dashboardToken)
	}
	// Banner persistence: derive sibling path from the registry store dir
	// so PUT /api/banner survives restarts. SetBannerPath reads the file
	// if present, overriding the flag default with the runtime value.
	if *storePath != "" {
		bp := filepath.Join(filepath.Dir(*storePath), "banner.txt")
		if *maintenanceBanner != "" {
			r.SetMaintenanceBanner(*maintenanceBanner) // flag-default first
		}
		r.SetBannerPath(bp) // then override from disk if file exists
	} else if *maintenanceBanner != "" {
		r.SetMaintenanceBanner(*maintenanceBanner)
	}
	if *replToken != "" {
		r.SetReplicationToken(*replToken)
	}
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

	if *httpAddr != "" {
		r.SetDashboardHTTPAddr(*httpAddr)
		go func() {
			if err := r.ServeDashboard(*httpAddr); err != nil {
				log.Fatalf("dashboard: %v", err)
			}
		}()
		slog.Info("dashboard running", "http", *httpAddr)
	}

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
