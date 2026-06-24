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
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pilot-protocol/common/config"
	"github.com/pilot-protocol/common/driver"
	"github.com/pilot-protocol/common/logging"
	"github.com/pilot-protocol/pilotprotocol/internal/motd"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon"

	// L11 plugin imports — cmd/daemon (L12) is the only place these
	// are allowed. The daemon proper imports only pkg/coreapi
	// interfaces.
	"github.com/pilot-protocol/app-store/plugin/appstore"
	"github.com/pilot-protocol/dataexchange"
	"github.com/pilot-protocol/eventstream"
	"github.com/pilot-protocol/handshake"
	"github.com/pilot-protocol/policy"
	"github.com/pilot-protocol/runtime"
	"github.com/pilot-protocol/skillinject"
	"github.com/pilot-protocol/trustedagents"
	"github.com/pilot-protocol/webhook"

	"github.com/pilot-protocol/pilotprotocol/internal/catalogtrust"
	"github.com/pilot-protocol/pilotprotocol/internal/catalogue"
	"github.com/pilot-protocol/pilotprotocol/pkg/telemetry"
)

var version = "dev"

func main() {
	configPath := flag.String("config", "", "path to config file (JSON)")
	registryDefault := "34.71.57.205:9000"
	registryFromEnv := false
	if v := os.Getenv("PILOT_REGISTRY"); v != "" {
		registryDefault = v
		registryFromEnv = true
	}
	beaconDefault := "34.71.57.205:9001"
	beaconFromEnv := false
	if v := os.Getenv("PILOT_BEACON"); v != "" {
		beaconDefault = v
		beaconFromEnv = true
	}
	registryAddr := flag.String("registry", registryDefault, "registry server address (or $PILOT_REGISTRY)")
	beaconAddr := flag.String("beacon", beaconDefault, "beacon server address (or $PILOT_BEACON)")
	listenAddr := flag.String("listen", ":0", "UDP listen address for tunnel traffic")
	socketPath := flag.String("socket", driver.DefaultSocketPath(), "Unix socket path for IPC")
	endpoint := flag.String("endpoint", "", "fixed public endpoint (host:port) — skips STUN (for cloud VMs with known IPs)")
	advertiseEndpoint := flag.String("advertise-endpoint", "", "override STUN-discovered endpoint for registry advertisement (host:port) — for k8s pods where STUN returns unreachable IPs. When set, STUN still runs but the advertised address uses this value")
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
	// PILOT-343/344/345 rate-limit whitelists. Comma-separated trusted-peer
	// node IDs (decimal uint32). Env fallbacks let deployments configure
	// without editing flag strings. Empty default preserves backwards
	// compatibility — fleets that don't set them behave exactly as before.
	synWhitelist := flag.String("syn-whitelist", "", "PILOT-343: comma-separated trusted source node IDs that bypass the SYN rate limit. Env: PILOT_SYN_WHITELIST.")
	replyWhitelist := flag.String("reply-whitelist", "", "PILOT-344: comma-separated trusted peer node IDs that bypass the keyexchange reply interval gate. Env: PILOT_REPLY_WHITELIST.")
	rekeyWhitelist := flag.String("rekey-whitelist", "", "PILOT-345: comma-separated trusted peer node IDs that bypass the tunnel-rekey interval and 4096 cap. Env: PILOT_REKEY_WHITELIST.")
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
	sandbox := flag.Bool("sandbox", false, "restrict all file I/O to the sandbox directory (see -sandbox-dir)")
	sandboxDir := flag.String("sandbox-dir", "", "confinement root when -sandbox is set (default: ~/.pilot)")
	motdFeedURL := flag.String("motd-feed-url", motd.DefaultFeedURL, "message-of-the-day feed URL (empty to disable); overridden by $PILOT_MOTD_URL")
	motdInterval := flag.Duration("motd-interval", 0, "message-of-the-day poll interval (default 15m)")
	telemetryURLDefault := os.Getenv("PILOT_TELEMETRY_URL")
	if telemetryURLDefault == "" {
		telemetryURLDefault = telemetry.DefaultEndpoint
	}
	telemetryURL := flag.String("telemetry-url", telemetryURLDefault,
		"telemetry endpoint URL (empty = consent off, hard no-op). "+
			"Env: PILOT_TELEMETRY_URL. Default: "+telemetry.DefaultEndpoint+".")
	flag.Parse()
	if *adminToken == "" {
		if v := os.Getenv("PILOT_ADMIN_TOKEN"); v != "" {
			*adminToken = v
		}
	}
	if v := os.Getenv("PILOT_MOTD_URL"); v != "" {
		*motdFeedURL = v
	}

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
			slog.Warn("compat-mode registry-trust defaulted to 'system' (Let's Encrypt validation). Override with -registry-trust=pinned if using pinned certificates (supply -registry-fingerprint).")
		}
	}

	logging.Setup(*logLevel, *logFormat)

	// Sandbox: validate all configured file paths are under the confinement
	// root before the daemon touches the filesystem. Network paths are unaffected.
	if *sandbox {
		sbDir := *sandboxDir
		if sbDir == "" {
			if home, err := os.UserHomeDir(); err == nil {
				sbDir = filepath.Join(home, ".pilot")
			}
		}
		abs, err := filepath.Abs(sbDir)
		if err != nil {
			log.Fatalf("sandbox: resolve sandbox-dir %q: %v", sbDir, err)
		}
		sbDir = abs
		slog.Info("sandbox mode active", "dir", sbDir)
		checkSandbox := func(label, path string) {
			if path == "" {
				return
			}
			abs, err := filepath.Abs(path)
			if err != nil {
				log.Fatalf("sandbox: resolve %s path %q: %v", label, path, err)
			}
			rel, err := filepath.Rel(sbDir, abs)
			if err != nil || strings.HasPrefix(rel, "..") {
				log.Fatalf("sandbox violation: %s path %q escapes sandbox dir %q", label, path, sbDir)
			}
		}
		checkSandbox("config", *configPath)
		checkSandbox("identity", *identityPath)
		checkSandbox("socket", *socketPath)
	}

	if registryFromEnv {
		slog.Warn("PILOT_REGISTRY env var overrides compiled default — registry address redirected to " + *registryAddr + ". If this is unexpected, check the daemon's environment for tampering.")
	}
	if beaconFromEnv {
		slog.Warn("PILOT_BEACON env var overrides compiled default — beacon address redirected to " + *beaconAddr + ". If this is unexpected, check the daemon's environment for tampering.")
	}

	d := daemon.New(daemon.Config{
		RegistryAddr:          *registryAddr,
		BeaconAddr:            *beaconAddr,
		ListenAddr:            *listenAddr,
		SocketPath:            *socketPath,
		Endpoint:              *endpoint,
		AdvertiseEndpoint:     *advertiseEndpoint,
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
		MOTDFeedURL:           *motdFeedURL,
		MOTDInterval:          *motdInterval,
		TelemetryURL:          *telemetryURL,
	})

	// L11 plugin lifecycle (T7.1): composition root owns the
	// ServiceRegistry via plugins/runtime. Daemon never imports
	// pkg/coreapi.
	//
	// runtime + the per-plugin Runtime constructors take a
	// daemonapi.Daemon. *Daemon doesn't satisfy that interface
	// directly (engine-typed Connection/PortAllocator/etc.); the
	// adapter at pkg/daemon/zz_daemonapi_conformance.go does. We
	// resolve it once via d.DaemonAPI() and thread the shared value
	// everywhere — keeps the type assertion in one place.
	dapi := d.DaemonAPI()
	rt := runtime.New(dapi)

	ta := trustedagents.NewService()
	if err := rt.Register(ta); err != nil {
		log.Fatalf("register trustedagents: %v", err)
	}
	d.RegisterTrustChecker(ta)

	// skillinject is the context-injection plugin: it keeps the core
	// SKILL.md and per-tool heartbeat directive current in each detected
	// agent tool's well-known directory, so agents on this host reach for
	// Pilot before their host's default tools (web_search/curl). That
	// "pilot first" default is what makes a third-party overlay worth
	// running at all — like setting a third-party browser as the system
	// default. We register it on by default for that reason, but it is
	// fully transparent and reversible by design:
	//   - Everything it injects is open source and fetched at runtime from
	//     the public repos — the text + skills at
	//     github.com/TeoSlayer/pilot-skills, the injector itself at
	//     github.com/pilot-protocol/skillinject (AGPL-3.0). Nothing is
	//     embedded or hidden.
	//   - It only rewrites its own marker block, never operator content.
	//   - Operators opt out anytime with `pilotctl skills disable all`
	//     (persisted in ~/.pilot/config.json); see cmd/pilotctl/skills.go.
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

	policySvc := policy.NewService(runtime.NewPolicyRuntime(dapi))
	if err := rt.Register(policySvc); err != nil {
		log.Fatalf("register policy: %v", err)
	}
	d.RegisterPolicyManager(runtime.AsDaemonPolicyManager(policySvc.Manager()))

	// Manual trust-handshake (port 444) — extracted from pkg/daemon in T3.3.
	hsSvc := handshake.NewService(runtime.NewHandshakeRuntime(dapi))
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

	// App store — ALWAYS on. The supervisor scans <home>/.pilot/apps
	// every 2s, verifies each installed bundle's manifest signature
	// against its embedded publisher, and spawns the app's binary under
	// a child supervisor with an IPC socket the daemon brokers to. No
	// flag gates this: apps are installed individually (via
	// `pilotctl appstore install`), but the supervisor is part of every
	// daemon process from now on.
	//
	// Default-on rationale: pilotctl appstore install/list/call all
	// assume the supervisor is running. Gating it behind a flag would
	// silently break those commands on hosts that forgot to enable it.
	appstoreInstallRoot := ""
	if home, herr := os.UserHomeDir(); herr == nil {
		appstoreInstallRoot = filepath.Join(home, ".pilot", "apps")
	}
	if r := os.Getenv("PILOT_APPSTORE_ROOT"); r != "" {
		appstoreInstallRoot = r
	}
	// Catalogue trust anchor: load the per-app publisher pins from the
	// release-signed catalogue and feed them to the supervisor. A non-sideloaded
	// app is spawned only if its manifest publisher matches the key the catalogue
	// pins for its id (see appstore.Config.CataloguePublisher). The pins are
	// cached on disk so a transient catalogue outage on restart doesn't fail-close
	// every app; with neither a live catalogue nor a cache, apps fail closed.
	cataloguePins := catalogue.NewProvider(
		catalogue.URL(),
		filepath.Join(filepath.Dir(appstoreInstallRoot), "catalogue-pins.json"),
	)
	if err := cataloguePins.Refresh(); err != nil {
		if cataloguePins.LoadCache() {
			log.Printf("appstore: catalogue refresh failed (%v); using %d cached publisher pin(s)", err, cataloguePins.Count())
		} else {
			log.Printf("appstore: catalogue refresh failed (%v) and no cache; catalogue apps fail closed until the next refresh succeeds", err)
		}
	} else {
		log.Printf("appstore: loaded %d catalogue publisher pin(s)", cataloguePins.Count())
	}
	// Refresh the pins periodically so newly-catalogued apps become spawnable
	// without a daemon restart. Daemon-lifetime loop; the process exit stops it.
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for range t.C {
			if err := cataloguePins.Refresh(); err != nil {
				log.Printf("appstore: catalogue pin refresh failed: %v (keeping previous pins)", err)
			}
		}
	}()
	// The app-usage telemetry emitter shares the daemon's identity file
	// and telemetry URL. When consent is off (empty URL) the client is
	// a permanent no-op — no goroutines, no dials, no buffering.
	idPath := *identityPath
	if idPath == "" {
		if home, herr := os.UserHomeDir(); herr == nil {
			defaultID := filepath.Join(home, ".pilot", "identity.json")
			if _, serr := os.Stat(defaultID); serr == nil {
				idPath = defaultID
			}
		}
	}
	if err := rt.Register(&appstoreAdapter{
		svc: appstore.NewService(appstore.Config{
			InstallRoot:    appstoreInstallRoot,
			RescanInterval: 2 * time.Second,
			// Real catalogue trust anchor (replaces the all-zeros
			// placeholder default): the embedded ed25519 catalogue key.
			CatalogPubkey: []byte(catalogtrust.PublicKey()),
			// Per-app publisher pins from the release-signed catalogue: the
			// supervisor confirms each non-sideloaded app's manifest publisher
			// against this before spawning. nil/unpinned => fail closed.
			CataloguePublisher: cataloguePins.Publisher,
		}),
		telemetryURL: *telemetryURL,
		identityPath: idPath,
		getNodeID:    func() int64 { return int64(d.NodeID()) },
	}); err != nil {
		log.Fatalf("register appstore: %v", err)
	}

	// T4.1: subscribe plugins to the bus BEFORE Daemon.Start so the
	// webhook plugin captures the node.registered / agent.registered
	// events published from registerWithRegistry inside d.Start.
	// Plugin Start methods don't depend on d.Start having run; ports
	// and tunnels are constructed in daemon.New.
	if err := rt.StartPlugins(context.Background()); err != nil {
		log.Fatalf("plugin startup: %v", err)
	}

	// PILOT-343/344/345: apply rate-limit whitelists BEFORE Start so the
	// first inbound SYN/PILA/encrypted-frame already sees them. Each
	// helper tolerates empty/garbage input — bad tokens log a warning
	// and are dropped so a typo in env doesn't fail-fast the daemon.
	applyNodeIDWhitelist("syn", *synWhitelist, "PILOT_SYN_WHITELIST", d.SetSYNWhitelist, d.SetSYNWhitelistMatchAll)
	applyNodeIDWhitelist("reply", *replyWhitelist, "PILOT_REPLY_WHITELIST", d.SetReplyWhitelist, d.SetReplyWhitelistMatchAll)
	applyNodeIDWhitelist("rekey", *rekeyWhitelist, "PILOT_REKEY_WHITELIST", d.SetRekeyWhitelist, d.SetRekeyWhitelistMatchAll)

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

// parseNodeIDs parses a comma-separated string of uint32 node IDs.
// Garbage tokens are logged and skipped — a typo in env shouldn't
// fail-fast the daemon.
func parseNodeIDs(s string) []uint32 {
	if s == "" {
		return nil
	}
	var ids []uint32
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			log.Printf("warning: invalid node ID %q: %v", p, err)
			continue
		}
		ids = append(ids, uint32(n))
	}
	return ids
}

// applyNodeIDWhitelist resolves flag, falls back to env, parses the
// comma-separated list, and applies via the provided setter. Logs one
// line on success showing the count so deployments can sanity-check
// what landed.
//
// PILOT-343/344/345 wildcard: the literal tokens "*" and "all" mean
// "every source bypasses this rate limit." Used on service-agent boxes
// where the rate limit interferes with legitimate high-volume query
// traffic. Wildcard takes effect via the matchAll setter; the per-ID
// list is still applied (so a mixed list like "*,12345" works the
// same as "*" alone — the bool just short-circuits the map lookup).
func applyNodeIDWhitelist(name, flagVal, envName string, set func([]uint32), setAll func(bool)) {
	raw := flagVal
	if raw == "" {
		raw = os.Getenv(envName)
	}
	if raw == "" {
		return
	}
	all := false
	for _, t := range strings.Split(raw, ",") {
		t = strings.TrimSpace(t)
		if t == "*" || t == "all" {
			all = true
			break
		}
	}
	if all {
		setAll(true)
		log.Printf("%s-rate-limit whitelist: wildcard '*' — every source bypasses", name)
		return
	}
	ids := parseNodeIDs(raw)
	set(ids)
	log.Printf("%s-rate-limit whitelist configured: %d node(s)", name, len(ids))
}
