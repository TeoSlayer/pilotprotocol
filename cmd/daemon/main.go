package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/TeoSlayer/pilotprotocol/pkg/config"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/logging"
)

var version = "dev"

func main() {
	configPath := flag.String("config", "", "path to config file (JSON)")
	registryAddr := flag.String("registry", "34.71.57.205:9000", "registry server address")
	beaconAddr := flag.String("beacon", "34.71.57.205:9001", "beacon server address")
	listenAddr := flag.String("listen", ":0", "UDP listen address for tunnel traffic")
	socketPath := flag.String("socket", "/tmp/pilot.sock", "Unix socket path for IPC")
	endpoint := flag.String("endpoint", "", "fixed public endpoint (host:port) — skips STUN (for cloud VMs with known IPs)")
	encrypt := flag.Bool("encrypt", true, "enable tunnel-layer encryption (X25519 + AES-256-GCM)")
	registryTLS := flag.Bool("registry-tls", false, "use TLS for registry connection")
	registryFingerprint := flag.String("registry-fingerprint", "", "hex SHA-256 fingerprint of registry TLS certificate")
	identityPath := flag.String("identity", "", "path to persist Ed25519 identity (enables stable identity across restarts)")
	email := flag.String("email", "", "email address for account identification and key recovery")
	owner := flag.String("owner", "", "(deprecated: use -email) owner identifier for key rotation recovery")
	keepalive := flag.Duration("keepalive", 0, "keepalive probe interval (default 30s)")
	idleTimeout := flag.Duration("idle-timeout", 0, "idle connection timeout (default 120s)")
	synRate := flag.Int("syn-rate-limit", 0, "max SYN packets per second (default 100)")
	maxConnsPerPort := flag.Int("max-conns-per-port", 0, "max connections per port (default 1024)")
	maxConnsTotal := flag.Int("max-conns-total", 0, "max total connections (default 4096)")
	timeWait := flag.Duration("time-wait", 0, "TIME_WAIT duration (default 10s)")
	public := flag.Bool("public", false, "make this node's endpoint publicly visible (default: private)")
	hostname := flag.String("hostname", "", "hostname for discovery (lowercase alphanumeric + hyphens, max 63 chars)")
	noEcho := flag.Bool("no-echo", false, "disable built-in echo service (port 7)")
	noDataExchange := flag.Bool("no-dataexchange", false, "disable built-in data exchange service (port 1001)")
	noEventStream := flag.Bool("no-eventstream", false, "disable built-in event stream service (port 1002)")
	noTaskSubmit := flag.Bool("no-tasksubmit", false, "disable built-in task submit service (port 1003)")
	webhookURL := flag.String("webhook", "", "HTTP(S) endpoint for event notifications (empty = disabled)")
	adminToken := flag.String("admin-token", "", "admin token for network operations")
	networks := flag.String("networks", "", "comma-separated network IDs to auto-join at startup")
	showVersion := flag.Bool("version", false, "print version and exit")
	logLevel := flag.String("log-level", "info", "log level (debug, info, warn, error)")
	logFormat := flag.String("log-format", "text", "log format (text, json)")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	if *configPath != "" {
		cfg, err := config.Load(*configPath)
		if err != nil {
			log.Fatalf("load config: %v", err)
		}
		config.ApplyToFlags(cfg)
	}

	logging.Setup(*logLevel, *logFormat)

	d := daemon.New(daemon.Config{
		RegistryAddr:          *registryAddr,
		BeaconAddr:            *beaconAddr,
		ListenAddr:            *listenAddr,
		SocketPath:            *socketPath,
		Endpoint:              *endpoint,
		Encrypt:               *encrypt,
		RegistryTLS:           *registryTLS,
		RegistryFingerprint:   *registryFingerprint,
		IdentityPath:          *identityPath,
		Email:                 *email,
		Owner:                 *owner,
		KeepaliveInterval:     *keepalive,
		IdleTimeout:           *idleTimeout,
		SYNRateLimit:          *synRate,
		MaxConnectionsPerPort: *maxConnsPerPort,
		MaxTotalConnections:   *maxConnsTotal,
		TimeWaitDuration:      *timeWait,
		Public:                *public,
		Hostname:              *hostname,
		DisableEcho:           *noEcho,
		DisableDataExchange:   *noDataExchange,
		DisableEventStream:    *noEventStream,
		DisableTaskSubmit:     *noTaskSubmit,
		WebhookURL:            *webhookURL,
		AdminToken:            *adminToken,
		Networks:              parseNetworkIDs(*networks),
	})

	if err := d.Start(); err != nil {
		log.Fatalf("daemon start: %v", err)
	}

	// Wait for signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	slog.Info("shutting down")
	d.Stop()
}

// parseNetworkIDs parses a comma-separated string of network IDs into a uint16 slice.
func parseNetworkIDs(s string) []uint16 {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var ids []uint16
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			log.Printf("warning: invalid network ID %q: %v", p, err)
			continue
		}
		ids = append(ids, uint16(n))
	}
	return ids
}
