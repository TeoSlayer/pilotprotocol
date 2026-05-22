// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/config"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/logging"

	// L11 plugin imports — cmd/daemon (L12) is the only place these
	// are allowed. The daemon proper imports only pkg/coreapi
	// interfaces.
	"github.com/TeoSlayer/pilotprotocol/plugins/dataexchange"
	"github.com/pilot-protocol/eventstream"
	"github.com/TeoSlayer/pilotprotocol/plugins/handshake"
	"github.com/TeoSlayer/pilotprotocol/plugins/policy"
	"github.com/TeoSlayer/pilotprotocol/plugins/runtime"
	"github.com/pilot-protocol/skillinject"
	"github.com/pilot-protocol/trustedagents"
	"github.com/pilot-protocol/webhook"
)

var version = "dev"

func main() {
	configPath := flag.String("config", "", "path to config file (JSON)")
	registryDefault := "34.71.57.205:9000"
	if v := os.Getenv("PILOT_REGISTRY"); v != "" {
		registryDefault = v
	}
	beaconDefault := "34.71.57.205:9001"
	if v := os.Getenv("PILOT_BEACON"); v != "" {
		beaconDefault = v
	}
	registryAddr := flag.String("registry", registryDefault, "registry server address (or $PILOT_REGISTRY)")
	beaconAddr := flag.String("beacon", beaconDefault, "beacon server address (or $PILOT_BEACON)")
	listenAddr := flag.String("listen", ":0", "UDP listen address for tunnel traffic")
	socketPath := flag.String("socket", "/tmp/pilot.sock", "Unix socket path for IPC")
	endpoint := flag.String("endpoint", "", "fixed public endpoint (host:port) — skips STUN (for cloud VMs with known IPs)")
	fakeListenAddr := flag.String("fake-listen-addr", "", "advertise this listen_addr to the registry instead of the real one (real socket binding unaffected)")
	encrypt := flag.Bool("encrypt", true, "enable tunnel-layer encryption (X25519 + AES-256-GCM)")
	registryTLS := flag.Bool("registry-tls", false, "use TLS for registry connection")
	registryFingerprint := flag.String("registry-fingerprint", "", "hex SHA-256 fingerprint of registry TLS certificate (required when -registry-trust=pinned)")
	registryTrust := flag.String("registry-trust", "pinned", "trust store for -registry-tls: 'pinned' (verify cert against -registry-fingerprint) or 'system' (OS x509 root store — used for compat-mode registry on registry.pilotprotocol.network:443 with Let's Encrypt)")
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
	relayOnly := flag.Bool("relay-only", false, "hide real_addr from peers; reach this node only via beacon-relay path. Privacy stance: peers cannot enumerate this daemon's public IP. Trade-off: relay adds one beacon hop. Default false (current direct-first behavior).")
	hostname := flag.String("hostname", "", "hostname for discovery (lowercase alphanumeric + hyphens, max 63 chars)")
	noEcho := flag.Bool("no-echo", false, "disable built-in echo service (port 7)")
	noDataExchange := flag.Bool("no-dataexchange", false, "disable built-in data exchange service (port 1001)")
	dataExchangeB64 := flag.Bool("dataexchange-b64", false, "include raw base64 payload (`data_b64`) alongside `data` in inbox messages — needed only for binary payloads (e.g. zlib-compressed envelopes)")
	noEventStream := flag.Bool("no-eventstream", false, "disable built-in event stream service (port 1002)")
	webhookURL := flag.String("webhook", "", "HTTP(S) endpoint for event notifications (empty = disabled)")
	adminToken := flag.String("admin-token", "", "admin token for network operations")
	networks := flag.String("networks", "", "comma-separated network IDs to auto-join at startup")
	trustAutoApprove := flag.Bool("trust-auto-approve", false, "automatically approve all incoming trust handshakes")
	beaconRTTProbe := flag.Bool("beacon-rtt-probe", false, "probe beacon RTT before selection; override hash pick when >2× slower than best (ablation test, default off)")
	transportMode := flag.String("transport", "udp", "tunnel transport: 'udp' (default) or 'compat' (WSS to beacon, opt-in, for UDP-blocked environments)")
	compatBeacon := flag.String("compat-beacon", "wss://beacon.pilotprotocol.network/v1/compat", "beacon WSS URL for -transport=compat")
	tlsTrust := flag.String("tls-trust", "system", "TLS trust store for -transport=compat: 'system' (OS trust store; current default while compat mode uses Let's Encrypt certs on beacon.pilotprotocol.network) or 'pinned' (Pilot CA root embedded in the daemon binary; will become the default in a future release once production root ships)")
	showVersion := flag.Bool("version", false, "print version and exit")
	logLevel := flag.String("log-level", "info", "log level (debug, info, warn, error)")
	logFormat := flag.String("log-format", "text", "log format (text, json)")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	// Auto-load ~/.pilot/config.json when -config isn't passed. Without
	// this, launching the daemon directly (vs. via `pilotctl daemon
	// start`) gives an empty IdentityPath, which silently disables
	// identity persistence AND trust-state persistence (Manager.loadTrust
	// only runs when IdentityPath != ""). Result: every restart loses
	// trust.json contents from the runtime even though the file is on
	// disk. Mirroring `pilotctl daemon start`'s implicit config path
	// here closes that gap.
	if *configPath == "" {
		if home, err := os.UserHomeDir(); err == nil {
			defaultConfig := home + "/.pilot/config.json"
			if _, err := os.Stat(defaultConfig); err == nil {
				configPath = &defaultConfig
			}
		}
	}
	if *configPath != "" {
		cfg, err := config.Load(*configPath)
		if err != nil {
			log.Fatalf("load config: %v", err)
		}
		config.ApplyToFlags(cfg)
	}

	// Compat-mode 443-only defaults. When -transport=compat is selected
	// and the operator hasn't explicitly overridden -registry/-registry-tls/
	// -registry-trust, route the registry to its TLS hostname (TCP/443
	// via nginx SNI routing on the production rendezvous box) so the
	// daemon really does use a single port. The TCP/9000 fallback is
	// still available to anyone who passes -registry explicitly.
	if *transportMode == "compat" {
		explicit := map[string]bool{}
		flag.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
		if !explicit["registry"] && os.Getenv("PILOT_REGISTRY") == "" {
			v := "registry.pilotprotocol.network:443"
			registryAddr = &v
		}
		if !explicit["registry-tls"] {
			v := true
			registryTLS = &v
		}
		if !explicit["registry-trust"] {
			v := "system"
			registryTrust = &v
		}
	}

	logging.Setup(*logLevel, *logFormat)

	d := daemon.New(daemon.Config{
		RegistryAddr:          *registryAddr,
		BeaconAddr:            *beaconAddr,
		ListenAddr:            *listenAddr,
		SocketPath:            *socketPath,
		Endpoint:              *endpoint,
		FakeListenAddr:        *fakeListenAddr,
		Encrypt:               *encrypt,
		RegistryTLS:           *registryTLS,
		RegistryFingerprint:   *registryFingerprint,
		RegistryTrust:         *registryTrust,
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
		RelayOnly:             *relayOnly,
		Hostname:              *hostname,
		DisableEcho:           *noEcho,
		DisableDataExchange:   *noDataExchange,
		DisableEventStream:    *noEventStream,
		WebhookURL:            *webhookURL,
		AdminToken:            *adminToken,
		Networks:              parseNetworkIDs(*networks),
		Version:               version,
		TrustAutoApprove:      *trustAutoApprove,
		BeaconRTTProbe:        *beaconRTTProbe,
		TransportMode:         *transportMode,
		CompatBeaconURL:       *compatBeacon,
		CompatTLSTrust:        *tlsTrust,
	})

	// L11 plugin lifecycle (T7.1): composition root owns the
	// ServiceRegistry via plugins/runtime. Daemon never imports
	// pkg/coreapi.
	rt := runtime.New(d)

	ta := trustedagents.NewService()
	if err := rt.Register(ta); err != nil {
		log.Fatalf("register trustedagents: %v", err)
	}
	d.RegisterTrustChecker(ta)

	if err := rt.Register(skillinject.NewService(skillinject.Config{})); err != nil {
		log.Fatalf("register skillinject: %v", err)
	}

	if !*noDataExchange {
		if err := rt.Register(dataexchange.NewService(dataexchange.ServiceConfig{
			IncludeBase64: *dataExchangeB64,
		})); err != nil {
			log.Fatalf("register dataexchange: %v", err)
		}
	}

	if !*noEventStream {
		if err := rt.Register(eventstream.NewService()); err != nil {
			log.Fatalf("register eventstream: %v", err)
		}
	}

	policySvc := policy.NewService(runtime.NewPolicyRuntime(d))
	if err := rt.Register(policySvc); err != nil {
		log.Fatalf("register policy: %v", err)
	}
	d.RegisterPolicyManager(runtime.AsDaemonPolicyManager(policySvc.Manager()))

	// Manual trust-handshake (port 444) — extracted from pkg/daemon in T3.3.
	hsSvc := handshake.NewService(runtime.NewHandshakeRuntime(d))
	if err := rt.Register(hsSvc); err != nil {
		log.Fatalf("register handshake: %v", err)
	}
	d.RegisterHandshakeService(runtime.NewHandshakeServiceAdapter(hsSvc))

	// Webhook (T4.1): the daemon publishes events to the in-process
	// bus, the plugin subscribes and POSTs to the configured URL. URL
	// hot-swap (IPC's `set-webhook`) routes through SetURL on the
	// plugin via the daemon's WebhookManager interface.
	webhookSvc := webhook.NewService(*webhookURL)
	if err := rt.Register(webhookSvc); err != nil {
		log.Fatalf("register webhook: %v", err)
	}
	d.RegisterWebhookManager(webhookManagerAdapter{svc: webhookSvc})

	// T4.1: subscribe plugins to the bus BEFORE Daemon.Start so the
	// webhook plugin captures the node.registered / agent.registered
	// events published from registerWithRegistry inside d.Start.
	// Plugin Start methods don't depend on d.Start having run; ports
	// and tunnels are constructed in daemon.New.
	if err := rt.StartPlugins(context.Background()); err != nil {
		log.Fatalf("plugin startup: %v", err)
	}
	if err := d.Start(); err != nil {
		log.Fatalf("daemon start: %v", err)
	}

	// Wait for signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	// Order matters: Daemon.Stop publishes daemon.shutting_down to the
	// bus before tearing down ports/IPC/tunnels. Plugins (notably
	// webhook) are still subscribed at that point, so the event flows
	// through. StopPlugins then drains each plugin's queue. Reversing
	// this order would lose the shutdown event because the webhook's
	// bus subscription would be cancelled before doStop publishes.
	slog.Info("shutting down")
	d.Stop()

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := rt.StopPlugins(stopCtx); err != nil {
		slog.Warn("plugin shutdown error", "err", err)
	}
	stopCancel()
}

// webhookManagerAdapter bridges *webhook.Service to the daemon's
// WebhookManager interface. Defined here (composition root) rather
// than in the plugin to keep the plugin free of pkg/daemon imports.
type webhookManagerAdapter struct{ svc *webhook.Service }

func (a webhookManagerAdapter) SetURL(url string) { a.svc.SetURL(url) }
func (a webhookManagerAdapter) Stats() daemon.WebhookStats {
	s := a.svc.Stats()
	return daemon.WebhookStats{Dropped: s.Dropped, CircuitSkips: s.CircuitSkips}
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
