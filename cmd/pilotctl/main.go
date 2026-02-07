package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"web4/pkg/config"
	"web4/pkg/daemon"
	"web4/pkg/driver"
	"web4/pkg/gateway"
	"web4/pkg/logging"
	"web4/pkg/protocol"
	"web4/pkg/registry"
)

// Global flags
var jsonOutput bool

// Config paths
const (
	defaultConfigDir  = ".pilot"
	defaultConfigFile = "config.json"
	defaultPIDFile    = "pilot.pid"
	defaultLogFile    = "pilot.log"
	defaultSocket     = "/tmp/pilot.sock"
)

func configDir() string {
	home, _ := os.UserHomeDir()
	return home + "/" + defaultConfigDir
}

func configPath() string  { return configDir() + "/" + defaultConfigFile }
func pidFilePath() string { return configDir() + "/" + defaultPIDFile }
func logFilePath() string { return configDir() + "/" + defaultLogFile }

// --- Output helpers ---

func output(data interface{}) {
	if jsonOutput {
		envelope := map[string]interface{}{"status": "ok", "data": data}
		b, _ := json.Marshal(envelope)
		fmt.Println(string(b))
	} else {
		switch v := data.(type) {
		case map[string]interface{}:
			b, _ := json.MarshalIndent(v, "", "  ")
			fmt.Println(string(b))
		default:
			fmt.Println(v)
		}
	}
}

func outputOK(fields map[string]interface{}) {
	if fields == nil {
		fields = map[string]interface{}{}
	}
	output(fields)
}

func fatalCode(code string, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if jsonOutput {
		b, _ := json.Marshal(map[string]string{
			"status":  "error",
			"code":    code,
			"message": msg,
		})
		fmt.Fprintln(os.Stderr, string(b))
	} else {
		fmt.Fprintf(os.Stderr, "error: %s\n", msg)
	}
	os.Exit(1)
}

func fatal(format string, args ...interface{}) {
	fatalCode("internal", format, args...)
}

// parseNodeID parses a string as a uint32 node ID or exits with an error (M18 fix).
func parseNodeID(s string) uint32 {
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		fatalCode("invalid_argument", "invalid node_id %q: %v", s, err)
	}
	return uint32(v)
}

// parseUint16 parses a string as a uint16 or exits with an error (M18 fix).
func parseUint16(s, label string) uint16 {
	v, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		fatalCode("invalid_argument", "invalid %s %q: %v", label, s, err)
	}
	return uint16(v)
}

func formatBytes(b uint64) string {
	switch {
	case b >= 1024*1024*1024:
		return fmt.Sprintf("%.1f GB", float64(b)/1024/1024/1024)
	case b >= 1024*1024:
		return fmt.Sprintf("%.1f MB", float64(b)/1024/1024)
	case b >= 1024:
		return fmt.Sprintf("%.1f KB", float64(b)/1024)
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// --- Env / config helpers ---

func getSocket() string {
	if v := os.Getenv("PILOT_SOCKET"); v != "" {
		return v
	}
	cfg := loadConfig()
	if s, ok := cfg["socket"].(string); ok && s != "" {
		return s
	}
	return defaultSocket
}

func getRegistry() string {
	if v := os.Getenv("PILOT_REGISTRY"); v != "" {
		return v
	}
	cfg := loadConfig()
	if s, ok := cfg["registry"].(string); ok && s != "" {
		return s
	}
	return "127.0.0.1:9000"
}

func loadConfig() map[string]interface{} {
	f, err := os.Open(configPath())
	if err != nil {
		return map[string]interface{}{}
	}
	defer f.Close()
	var cfg map[string]interface{}
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return map[string]interface{}{}
	}
	return cfg
}

func saveConfig(cfg map[string]interface{}) error {
	dir := configDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.Create(configPath())
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(cfg)
}

// --- Arg parsing helpers ---

// parseFlags extracts --key=value and --flag from args, returns remaining positional args.
func parseFlags(args []string) (map[string]string, []string) {
	flags := map[string]string{}
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "--") {
			key := a[2:]
			if idx := strings.Index(key, "="); idx >= 0 {
				flags[key[:idx]] = key[idx+1:]
			} else if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				flags[key] = args[i+1]
				i++
			} else {
				flags[key] = "true"
			}
		} else {
			pos = append(pos, a)
		}
	}
	return flags, pos
}

func flagDuration(flags map[string]string, key string, def time.Duration) time.Duration {
	v, ok := flags[key]
	if !ok {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		// Try as seconds
		secs, err2 := strconv.ParseFloat(v, 64)
		if err2 != nil {
			fatalCode("invalid_argument", "invalid duration for --%s: %v", key, err)
		}
		return time.Duration(secs * float64(time.Second))
	}
	return d
}

func flagInt(flags map[string]string, key string, def int) int {
	v, ok := flags[key]
	if !ok {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		fatalCode("invalid_argument", "invalid integer for --%s: %v", key, err)
	}
	return n
}

func flagString(flags map[string]string, key string, def string) string {
	if v, ok := flags[key]; ok {
		return v
	}
	return def
}

func flagBool(flags map[string]string, key string) bool {
	v, ok := flags[key]
	return ok && (v == "true" || v == "1" || v == "")
}

// --- Connection helpers ---

func connectDriver() *driver.Driver {
	d, err := driver.Connect(getSocket())
	if err != nil {
		fatalCode("not_running", "connect to daemon: %v", err)
	}
	return d
}

func connectRegistry() *registry.Client {
	rc, err := registry.Dial(getRegistry())
	if err != nil {
		fatalCode("connection_failed", "connect to registry: %v", err)
	}
	return rc
}

func resolveHostnameToAddr(d *driver.Driver, hostname string) (protocol.Addr, uint32, error) {
	result, err := d.ResolveHostname(hostname)
	if err != nil {
		return protocol.Addr{}, 0, err
	}
	nodeIDVal, ok := result["node_id"].(float64)
	if !ok {
		return protocol.Addr{}, 0, fmt.Errorf("missing node_id in resolve response")
	}
	nodeID := uint32(nodeIDVal)
	addrStr, ok := result["address"].(string)
	if !ok {
		return protocol.Addr{}, 0, fmt.Errorf("missing address in resolve response")
	}
	addr, err := protocol.ParseAddr(addrStr)
	if err != nil {
		return protocol.Addr{}, 0, fmt.Errorf("parse address: %w", err)
	}
	return addr, nodeID, nil
}

func parseAddrOrHostname(d *driver.Driver, arg string) (protocol.Addr, error) {
	addr, err := protocol.ParseAddr(arg)
	if err == nil {
		return addr, nil
	}
	resolved, _, resolveErr := resolveHostnameToAddr(d, arg)
	if resolveErr != nil {
		return protocol.Addr{}, fmt.Errorf("not a valid address or hostname: %v", resolveErr)
	}
	if !jsonOutput {
		fmt.Fprintf(os.Stderr, "resolved hostname %q → %s\n", arg, resolved)
	}
	return resolved, nil
}

// --- Usage ---

func usage() {
	fmt.Fprintf(os.Stderr, `pilotctl — Pilot Protocol CLI

Global flags:
  --json                        Output structured JSON (for agent/programmatic use)

Bootstrap:
  pilotctl init --registry <addr> [--hostname <name>] [--beacon <addr>]
  pilotctl config [--set key=value]

Daemon lifecycle:
  pilotctl daemon start [--config <path>] [--registry <addr>] [--beacon <addr>]
  pilotctl daemon stop
  pilotctl daemon status

Registry commands:
  pilotctl register [listen_addr]
  pilotctl lookup <node_id>
  pilotctl rotate-key <node_id> <owner>
  pilotctl set-public <node_id>
  pilotctl set-private <node_id>
  pilotctl deregister <node_id>

Discovery commands:
  pilotctl find <hostname>
  pilotctl set-hostname <hostname>
  pilotctl clear-hostname

Communication commands:
  pilotctl connect <address|hostname> [port] [--message <msg>] [--timeout <dur>]
  pilotctl send <address|hostname> <port> --data <msg> [--timeout <dur>]
  pilotctl recv <port> [--count <n>] [--timeout <dur>]
  pilotctl send-file <address> <filepath>

Trust commands:
  pilotctl handshake <node_id|hostname> [justification]
  pilotctl approve <node_id>
  pilotctl reject <node_id> [reason]
  pilotctl untrust <node_id>
  pilotctl pending
  pilotctl trust

Management commands:
  pilotctl connections
  pilotctl disconnect <conn_id>

Diagnostic commands:
  pilotctl info
  pilotctl peers [--search <query>]
  pilotctl ping <address|hostname> [--count <n>] [--timeout <dur>]
  pilotctl traceroute <address> [--timeout <dur>]
  pilotctl bench <address|hostname> [size_mb] [--timeout <dur>]
  pilotctl listen <port> [--count <n>] [--timeout <dur>]
  pilotctl broadcast <network_id> <message>

Agent tool discovery:
  pilotctl context

Gateway (requires root for ports <1024):
  pilotctl gateway start [--subnet <cidr>] [--ports <list>] [<pilot-addr>...]
  pilotctl gateway stop
  pilotctl gateway map <pilot-addr> [local-ip]
  pilotctl gateway unmap <local-ip>
  pilotctl gateway list

Environment:
  PILOT_REGISTRY     Registry address (default: 127.0.0.1:9000)
  PILOT_SOCKET       Daemon socket path (default: /tmp/pilot.sock)

Config file: ~/.pilot/config.json
`)
	os.Exit(2)
}

// --- Main ---

func main() {
	// Extract --json before subcommand
	var args []string
	for _, a := range os.Args[1:] {
		if a == "--json" {
			jsonOutput = true
		} else {
			args = append(args, a)
		}
	}

	if len(args) < 1 {
		usage()
	}

	cmd := args[0]
	cmdArgs := args[1:]

	switch cmd {
	// Bootstrap
	case "init":
		cmdInit(cmdArgs)
	case "config":
		cmdConfig(cmdArgs)
	case "context":
		cmdContext()

	// Daemon lifecycle
	case "daemon":
		if len(cmdArgs) < 1 {
			fatalCode("invalid_argument", "usage: pilotctl daemon <start|stop|status>")
		}
		switch cmdArgs[0] {
		case "start":
			cmdDaemonStart(cmdArgs[1:])
		case "stop":
			cmdDaemonStop()
		case "status":
			cmdDaemonStatus(cmdArgs[1:])
		default:
			fatalCode("invalid_argument", "unknown daemon subcommand: %s", cmdArgs[0])
		}

	// Gateway
	case "gateway":
		if len(cmdArgs) < 1 {
			fatalCode("invalid_argument", "usage: pilotctl gateway <start|stop|map|unmap|list>")
		}
		switch cmdArgs[0] {
		case "start":
			cmdGatewayStart(cmdArgs[1:])
		case "stop":
			cmdGatewayStop()
		case "map":
			cmdGatewayMap(cmdArgs[1:])
		case "unmap":
			cmdGatewayUnmap(cmdArgs[1:])
		case "list":
			cmdGatewayList()
		default:
			fatalCode("invalid_argument", "unknown gateway subcommand: %s", cmdArgs[0])
		}

	// Registry
	case "register":
		cmdRegister(cmdArgs)
	case "lookup":
		cmdLookup(cmdArgs)
	case "rotate-key":
		cmdRotateKey(cmdArgs)
	case "set-public":
		cmdSetPublic(cmdArgs)
	case "set-private":
		cmdSetPrivate(cmdArgs)
	case "deregister":
		cmdDeregister(cmdArgs)

	// Discovery
	case "find":
		cmdFind(cmdArgs)
	case "set-hostname":
		cmdSetHostname(cmdArgs)
	case "clear-hostname":
		cmdClearHostname()

	// Communication
	case "connect":
		cmdConnect(cmdArgs)
	case "send":
		cmdSend(cmdArgs)
	case "recv":
		cmdRecv(cmdArgs)
	case "send-file":
		cmdSendFile(cmdArgs)

	// Trust
	case "handshake":
		cmdHandshake(cmdArgs)
	case "approve":
		cmdApprove(cmdArgs)
	case "reject":
		cmdReject(cmdArgs)
	case "untrust":
		cmdUntrust(cmdArgs)
	case "pending":
		cmdPending()
	case "trust":
		cmdTrust()

	// Management
	case "connections":
		cmdConnections()
	case "disconnect":
		cmdDisconnect(cmdArgs)

	// Diagnostics
	case "info":
		cmdInfo()
	case "peers":
		cmdPeers(cmdArgs)
	case "ping":
		cmdPing(cmdArgs)
	case "traceroute":
		cmdTraceroute(cmdArgs)
	case "bench":
		cmdBench(cmdArgs)
	case "listen":
		cmdListen(cmdArgs)
	case "broadcast":
		cmdBroadcast(cmdArgs)

	// Internal: forked daemon process
	case "_daemon-run":
		runDaemonInternal(cmdArgs)

	default:
		if jsonOutput {
			fatalCode("invalid_argument", "unknown command: %s", cmd)
		}
		usage()
	}
}

// ===================== BOOTSTRAP =====================

func cmdInit(args []string) {
	flags, _ := parseFlags(args)

	registryAddr := flagString(flags, "registry", "127.0.0.1:9000")
	beaconAddr := flagString(flags, "beacon", "127.0.0.1:9001")
	hostname := flagString(flags, "hostname", "")
	socketPath := flagString(flags, "socket", defaultSocket)

	cfg := loadConfig()
	cfg["registry"] = registryAddr
	cfg["beacon"] = beaconAddr
	cfg["socket"] = socketPath
	if hostname != "" {
		cfg["hostname"] = hostname
	}

	if err := saveConfig(cfg); err != nil {
		fatalCode("internal", "save config: %v", err)
	}

	outputOK(map[string]interface{}{
		"config_path": configPath(),
		"registry":    registryAddr,
		"beacon":      beaconAddr,
		"socket":      socketPath,
		"hostname":    hostname,
	})
}

func cmdConfig(args []string) {
	flags, _ := parseFlags(args)

	if setVal, ok := flags["set"]; ok {
		parts := strings.SplitN(setVal, "=", 2)
		if len(parts) != 2 {
			fatalCode("invalid_argument", "usage: pilotctl config --set key=value")
		}
		cfg := loadConfig()
		cfg[parts[0]] = parts[1]
		if err := saveConfig(cfg); err != nil {
			fatalCode("internal", "save config: %v", err)
		}
		outputOK(map[string]interface{}{
			"key":   parts[0],
			"value": parts[1],
		})
		return
	}

	// Show config
	cfg := loadConfig()
	cfg["config_path"] = configPath()
	cfg["pid_file"] = pidFilePath()
	cfg["log_file"] = logFilePath()
	// Add defaults for unset values
	if _, ok := cfg["registry"]; !ok {
		cfg["registry"] = getRegistry()
	}
	if _, ok := cfg["socket"]; !ok {
		cfg["socket"] = getSocket()
	}
	output(cfg)
}

// ===================== CONTEXT =====================

func cmdContext() {
	ctx := map[string]interface{}{
		"version": "1.1",
		"commands": map[string]interface{}{
			"init": map[string]interface{}{
				"args":        []string{"--registry <addr>", "--beacon <addr>", "--hostname <name>", "[--socket <path>]"},
				"description": "Initialize pilot configuration (writes ~/.pilot/config.json)",
				"returns":     "config_path, registry, beacon, socket, hostname",
			},
			"config": map[string]interface{}{
				"args":        []string{"[--set key=value]"},
				"description": "Show or set configuration values",
				"returns":     "current configuration as JSON",
			},
			"daemon start": map[string]interface{}{
				"args":        []string{"[--config <path>]", "[--registry <addr>]", "[--beacon <addr>]", "[--listen <addr>]", "[--identity <path>]", "[--owner <owner>]", "[--hostname <name>]", "[--log-level <level>]", "[--log-format <fmt>]", "[--public]", "[--foreground]", "[--no-encrypt]", "[--socket <path>]"},
				"description": "Start the daemon as a background process. Blocks until registered, then prints status and exits",
				"returns":     "node_id, address, pid, socket, hostname, log_file",
			},
			"daemon stop": map[string]interface{}{
				"args":        []string{},
				"description": "Stop the running daemon",
				"returns":     "pid, forced (bool)",
			},
			"daemon status": map[string]interface{}{
				"args":        []string{"[--check]"},
				"description": "Check if daemon is running and responsive. --check: silent, exits 0 if responsive, 1 otherwise",
				"returns":     "running (bool), responsive (bool), pid, pid_file, socket, node_id, address, hostname, uptime_secs, peers, connections",
			},
			"register": map[string]interface{}{
				"args":        []string{"[listen_addr]"},
				"description": "Register a new node with the registry",
				"returns":     "node_id, address, public_key",
			},
			"lookup": map[string]interface{}{
				"args":        []string{"<node_id>"},
				"description": "Look up a node by ID",
				"returns":     "node_id, address, real_addr, public, hostname",
			},
			"find": map[string]interface{}{
				"args":        []string{"<hostname>"},
				"description": "Discover a node by hostname",
				"returns":     "hostname, node_id, address, public",
			},
			"set-hostname": map[string]interface{}{
				"args":        []string{"<hostname>"},
				"description": "Set hostname for this daemon's node",
				"returns":     "hostname, node_id",
			},
			"clear-hostname": map[string]interface{}{
				"args":        []string{},
				"description": "Clear hostname for this daemon's node",
				"returns":     "hostname, node_id",
			},
			"info": map[string]interface{}{
				"args":        []string{},
				"description": "Show daemon status: node_id, address, hostname, uptime, peers, connections, encryption, identity",
				"returns":     "node_id, address, hostname, uptime_secs, connections, ports, peers, encrypt, bytes_sent, bytes_recv, conn_list, peer_list",
			},
			"peers": map[string]interface{}{
				"args":        []string{"[--search <query>]"},
				"description": "List connected peers with optional search filter",
				"returns":     "peers [{node_id, endpoint, encrypted, authenticated}], total",
			},
			"connections": map[string]interface{}{
				"args":        []string{},
				"description": "List active connections",
				"returns":     "connections [{id, local_port, remote_addr, remote_port, state, ...}], total",
			},
			"connect": map[string]interface{}{
				"args":        []string{"<address|hostname>", "[port]", "[--message <msg>]", "[--timeout <dur>]"},
				"description": "Open a stream connection. Use --message to send a single message and get a response",
				"returns":     "target, port, sent, response (with --message), or interactive stdio session",
			},
			"send": map[string]interface{}{
				"args":        []string{"<address|hostname>", "<port>", "--data <msg>", "[--timeout <dur>]"},
				"description": "Send a single message to a port and read the response",
				"returns":     "target, port, sent, response",
			},
			"recv": map[string]interface{}{
				"args":        []string{"<port>", "[--count <n>]", "[--timeout <dur>]"},
				"description": "Accept incoming connections, receive messages",
				"returns":     "messages [{seq, port, data, bytes}], timeout (bool)",
			},
			"send-file": map[string]interface{}{
				"args":        []string{"<address>", "<filepath>"},
				"description": "Send a file to a node on port 1001 (data exchange)",
				"returns":     "filename, bytes, destination",
			},
			"ping": map[string]interface{}{
				"args":        []string{"<address|hostname>", "[--count <n>]", "[--timeout <dur>]"},
				"description": "Ping a node via echo port. Default 4 pings",
				"returns":     "target, results [{seq, bytes, rtt_ms, error}], timeout (bool)",
			},
			"traceroute": map[string]interface{}{
				"args":        []string{"<address>", "[--timeout <dur>]"},
				"description": "Trace path to a node (connection setup + RTT samples)",
				"returns":     "target, setup_ms, rtt_samples [{rtt_ms, bytes}]",
			},
			"bench": map[string]interface{}{
				"args":        []string{"<address|hostname>", "[size_mb]", "[--timeout <dur>]"},
				"description": "Throughput benchmark via echo port (default 1 MB)",
				"returns":     "target, sent_bytes, recv_bytes, send_duration_ms, total_duration_ms, send_mbps, total_mbps",
			},
			"listen": map[string]interface{}{
				"args":        []string{"<port>", "[--count <n>]", "[--timeout <dur>]"},
				"description": "Listen for incoming datagrams. Default: infinite (NDJSON streaming). Use --count/--timeout to bound",
				"returns":     "messages [{src_addr, src_port, data, bytes}], timeout (bool). Unbounded: NDJSON per line",
			},
			"handshake": map[string]interface{}{
				"args":        []string{"<node_id|hostname>", "[justification]"},
				"description": "Send a trust handshake request to a remote node",
				"returns":     "status, node_id",
			},
			"approve": map[string]interface{}{
				"args":        []string{"<node_id>"},
				"description": "Approve a pending handshake request",
				"returns":     "status, node_id",
			},
			"reject": map[string]interface{}{
				"args":        []string{"<node_id>", "[reason]"},
				"description": "Reject a pending handshake request",
				"returns":     "status, node_id",
			},
			"untrust": map[string]interface{}{
				"args":        []string{"<node_id>"},
				"description": "Revoke trust for a peer",
				"returns":     "node_id",
			},
			"pending": map[string]interface{}{
				"args":        []string{},
				"description": "List pending handshake requests",
				"returns":     "pending [{node_id, justification, received_at}]",
			},
			"trust": map[string]interface{}{
				"args":        []string{},
				"description": "List trusted peers",
				"returns":     "trusted [{node_id, mutual, network, approved_at}]",
			},
			"disconnect": map[string]interface{}{
				"args":        []string{"<conn_id>"},
				"description": "Close a connection by ID",
				"returns":     "conn_id",
			},
			"broadcast": map[string]interface{}{
				"args":        []string{"<network_id>", "<message>"},
				"description": "Broadcast a message to all network members",
				"returns":     "network_id, message",
			},
			"rotate-key": map[string]interface{}{
				"args":        []string{"<node_id>", "<owner>"},
				"description": "Rotate keypair via owner recovery",
				"returns":     "node_id, new public_key",
			},
			"set-public": map[string]interface{}{
				"args":        []string{"<node_id>"},
				"description": "Make node endpoint publicly visible",
				"returns":     "status",
			},
			"set-private": map[string]interface{}{
				"args":        []string{"<node_id>"},
				"description": "Hide node endpoint (private, default)",
				"returns":     "status",
			},
			"deregister": map[string]interface{}{
				"args":        []string{"<node_id>"},
				"description": "Remove a node from the registry",
				"returns":     "status",
			},
			"gateway start": map[string]interface{}{
				"args":        []string{"[--subnet <cidr>]", "[--ports <list>]", "[<pilot-addr>...]"},
				"description": "Start the IP gateway (bridges TCP to Pilot Protocol)",
				"returns":     "pid, subnet, mappings [{local_ip, pilot_addr}]",
			},
			"gateway stop": map[string]interface{}{
				"args":        []string{},
				"description": "Stop the running gateway",
				"returns":     "pid",
			},
			"gateway map": map[string]interface{}{
				"args":        []string{"<pilot-addr>", "[local-ip]"},
				"description": "Add a mapping to the running gateway",
				"returns":     "local_ip, pilot_addr",
			},
			"gateway unmap": map[string]interface{}{
				"args":        []string{"<local-ip>"},
				"description": "Remove a mapping and clean up loopback alias",
				"returns":     "unmapped",
			},
			"gateway list": map[string]interface{}{
				"args":        []string{},
				"description": "List all current gateway mappings",
				"returns":     "mappings [{local_ip, pilot_addr}], total",
			},
		},
		"error_codes": map[string]interface{}{
			"invalid_argument":  "Bad input or usage error (do not retry)",
			"not_found":         "Resource not found (hostname/name resolve failure)",
			"already_exists":    "Duplicate operation (daemon/gateway already running)",
			"not_running":       "Service not available (daemon/gateway not running)",
			"connection_failed": "Network or dial failure (may retry)",
			"timeout":           "Operation timed out (may retry with longer timeout)",
			"internal":          "Unexpected system error",
		},
		"global_flags": map[string]interface{}{
			"--json": "Output structured JSON for all commands. Success: {status:ok, data:{...}}. Error: {status:error, code:string, message:string}",
		},
		"environment": map[string]interface{}{
			"PILOT_REGISTRY": "Registry address (default: 127.0.0.1:9000)",
			"PILOT_SOCKET":   "Daemon socket path (default: /tmp/pilot.sock)",
		},
		"config_file": "~/.pilot/config.json",
	}
	output(ctx)
}

// ===================== DAEMON LIFECYCLE =====================

func cmdDaemonStart(args []string) {
	flags, _ := parseFlags(args)

	// Check if already running
	if pid := readPID(); pid > 0 {
		if processExists(pid) {
			fatalCode("already_exists", "daemon already running (pid %d)", pid)
		}
		// Stale PID file
		os.Remove(pidFilePath())
	}

	// Clean up stale socket
	socketPath := getSocket()
	if _, err := os.Stat(socketPath); err == nil {
		// Try to connect — if it works, daemon is running
		d, err := driver.Connect(socketPath)
		if err == nil {
			d.Close()
			fatalCode("already_exists", "daemon already running (socket %s is active)", socketPath)
		}
		// Stale socket — remove it
		os.Remove(socketPath)
	}

	// Build daemon config
	cfg := loadConfig()
	registryAddr := flagString(flags, "registry", "")
	if registryAddr == "" {
		if r, ok := cfg["registry"].(string); ok {
			registryAddr = r
		} else {
			registryAddr = getRegistry()
		}
	}
	beaconAddr := flagString(flags, "beacon", "")
	if beaconAddr == "" {
		if b, ok := cfg["beacon"].(string); ok {
			beaconAddr = b
		} else {
			beaconAddr = "127.0.0.1:9001"
		}
	}
	listenAddr := flagString(flags, "listen", ":0")
	hostname := flagString(flags, "hostname", "")
	if hostname == "" {
		if h, ok := cfg["hostname"].(string); ok {
			hostname = h
		}
	}
	encrypt := !flagBool(flags, "no-encrypt")
	identityPath := flagString(flags, "identity", "")
	if identityPath == "" {
		identityPath = configDir() + "/identity.key"
	}
	owner := flagString(flags, "owner", "")
	configFile := flagString(flags, "config", "")
	logLevel := flagString(flags, "log-level", "info")
	logFormat := flagString(flags, "log-format", "text")
	public := flagBool(flags, "public")

	// If --foreground, run in-process
	if flagBool(flags, "foreground") {
		runDaemonForeground(configFile, registryAddr, beaconAddr, listenAddr,
			socketPath, encrypt, identityPath, owner, hostname, logLevel, logFormat, public)
		return
	}

	// Fork: re-exec self with _daemon-run internal command
	selfPath, err := os.Executable()
	if err != nil {
		fatalCode("internal", "find executable: %v", err)
	}

	// Ensure config dir + log file exist
	os.MkdirAll(configDir(), 0700)
	logFile, err := os.OpenFile(logFilePath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		fatalCode("internal", "open log file: %v", err)
	}

	daemonArgs := []string{"_daemon-run",
		"--registry", registryAddr,
		"--beacon", beaconAddr,
		"--listen", listenAddr,
		"--socket", socketPath,
		"--identity", identityPath,
		"--log-level", logLevel,
		"--log-format", logFormat,
	}
	if !encrypt {
		daemonArgs = append(daemonArgs, "--no-encrypt")
	}
	if owner != "" {
		daemonArgs = append(daemonArgs, "--owner", owner)
	}
	if hostname != "" {
		daemonArgs = append(daemonArgs, "--hostname", hostname)
	}
	if configFile != "" {
		daemonArgs = append(daemonArgs, "--config", configFile)
	}
	if public {
		daemonArgs = append(daemonArgs, "--public")
	}

	proc := exec.Command(selfPath, daemonArgs...)
	proc.Stdout = logFile
	proc.Stderr = logFile
	proc.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := proc.Start(); err != nil {
		fatalCode("internal", "start daemon: %v", err)
	}

	pid := proc.Process.Pid
	os.WriteFile(pidFilePath(), []byte(strconv.Itoa(pid)), 0600)

	// Wait for daemon to become ready (socket appears and responds)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
		d, err := driver.Connect(socketPath)
		if err != nil {
			continue
		}
		info, err := d.Info()
		d.Close()
		if err != nil {
			continue
		}
		// Daemon is ready
		outputOK(map[string]interface{}{
			"pid":      pid,
			"node_id":  int(info["node_id"].(float64)),
			"address":  info["address"],
			"hostname": info["hostname"],
			"socket":   socketPath,
			"log_file": logFilePath(),
		})
		return
	}

	fatalCode("timeout", "daemon started (pid %d) but did not become ready within 15s — check %s", pid, logFilePath())
}

func cmdDaemonStop() {
	pid := readPID()
	if pid <= 0 {
		// Try socket
		d, err := driver.Connect(getSocket())
		if err != nil {
			fatalCode("not_running", "no daemon running (no PID file and socket not responding)")
		}
		d.Close()
		fatalCode("not_running", "daemon socket active but no PID file — kill manually")
	}

	if !processExists(pid) {
		os.Remove(pidFilePath())
		fatalCode("not_running", "daemon not running (stale pid %d)", pid)
	}

	// Send SIGTERM
	proc, err := os.FindProcess(pid)
	if err != nil {
		fatalCode("internal", "find process: %v", err)
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		fatalCode("internal", "signal daemon: %v", err)
	}

	// Wait for exit
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
		if !processExists(pid) {
			os.Remove(pidFilePath())
			outputOK(map[string]interface{}{"pid": pid})
			return
		}
	}

	// Force kill
	proc.Signal(syscall.SIGKILL)
	os.Remove(pidFilePath())
	outputOK(map[string]interface{}{"pid": pid, "forced": true})
}

func cmdDaemonStatus(args []string) {
	flags, _ := parseFlags(args)
	checkMode := flagBool(flags, "check")

	pid := readPID()
	running := false
	if pid > 0 && processExists(pid) {
		running = true
	}

	// --check mode: silent health check, exit 0 if responsive, exit 1 otherwise
	if checkMode {
		d, err := driver.Connect(getSocket())
		if err != nil {
			os.Exit(1)
		}
		_, err = d.Info()
		d.Close()
		if err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}

	result := map[string]interface{}{
		"running":  running,
		"pid":      pid,
		"pid_file": pidFilePath(),
		"socket":   getSocket(),
	}

	// Try to get info from daemon
	d, err := driver.Connect(getSocket())
	if err != nil {
		if !running {
			// Clean up stale files
			if pid > 0 {
				os.Remove(pidFilePath())
			}
		}
		result["responsive"] = false
		output(result)
		return
	}
	defer d.Close()

	info, err := d.Info()
	if err != nil {
		result["responsive"] = false
		output(result)
		return
	}

	result["responsive"] = true
	result["running"] = true
	result["node_id"] = int(info["node_id"].(float64))
	result["address"] = info["address"]
	if h, ok := info["hostname"].(string); ok {
		result["hostname"] = h
	}
	result["uptime_secs"] = info["uptime_secs"]
	result["peers"] = int(info["peers"].(float64))
	result["connections"] = int(info["connections"].(float64))

	if !jsonOutput {
		uptime := info["uptime_secs"].(float64)
		hours := int(uptime) / 3600
		mins := (int(uptime) % 3600) / 60
		secs := int(uptime) % 60
		statusStr := "stopped"
		if running {
			statusStr = "running"
		}
		fmt.Printf("Daemon: %s (pid %d)\n", statusStr, pid)
		fmt.Printf("  Node ID:     %d\n", int(info["node_id"].(float64)))
		fmt.Printf("  Address:     %s\n", info["address"])
		if h, ok := info["hostname"].(string); ok && h != "" {
			fmt.Printf("  Hostname:    %s\n", h)
		}
		fmt.Printf("  Uptime:      %02d:%02d:%02d\n", hours, mins, secs)
		fmt.Printf("  Peers:       %d\n", int(info["peers"].(float64)))
		fmt.Printf("  Connections: %d\n", int(info["connections"].(float64)))
		return
	}
	output(result)
}

// _daemon-run is the internal command used by "daemon start" to run in the forked process.
func runDaemonInternal(args []string) {
	flags, _ := parseFlags(args)

	registryAddr := flagString(flags, "registry", "127.0.0.1:9000")
	beaconAddr := flagString(flags, "beacon", "127.0.0.1:9001")
	listenAddr := flagString(flags, "listen", ":0")
	socketPath := flagString(flags, "socket", defaultSocket)
	identityPath := flagString(flags, "identity", "")
	owner := flagString(flags, "owner", "")
	hostname := flagString(flags, "hostname", "")
	logLevel := flagString(flags, "log-level", "info")
	logFormat := flagString(flags, "log-format", "text")
	configFile := flagString(flags, "config", "")
	encrypt := !flagBool(flags, "no-encrypt")
	public := flagBool(flags, "public")

	runDaemonForeground(configFile, registryAddr, beaconAddr, listenAddr,
		socketPath, encrypt, identityPath, owner, hostname, logLevel, logFormat, public)
}

func runDaemonForeground(configFile, registryAddr, beaconAddr, listenAddr,
	socketPath string, encrypt bool, identityPath, owner, hostname,
	logLevel, logFormat string, public bool) {

	if configFile != "" {
		cfg, err := config.Load(configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load config: %v\n", err)
			os.Exit(1)
		}
		// Apply config values as defaults (CLI flags override)
		if registryAddr == "127.0.0.1:9000" {
			if v, ok := cfg["registry"].(string); ok {
				registryAddr = v
			}
		}
		if beaconAddr == "127.0.0.1:9001" {
			if v, ok := cfg["beacon"].(string); ok {
				beaconAddr = v
			}
		}
	}

	logging.Setup(logLevel, logFormat)

	d := daemon.New(daemon.Config{
		RegistryAddr: registryAddr,
		BeaconAddr:   beaconAddr,
		ListenAddr:   listenAddr,
		SocketPath:   socketPath,
		Encrypt:      encrypt,
		IdentityPath: identityPath,
		Owner:        owner,
		Public:       public,
		Hostname:     hostname,
	})

	if err := d.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "daemon start: %v\n", err)
		os.Exit(1)
	}

	// Auto-start gateway alongside daemon
	var gw *gateway.Gateway
	gw, err := gateway.New(gateway.Config{
		Subnet:     "10.4.0.0/16",
		SocketPath: socketPath,
	})
	if err != nil {
		slog.Warn("gateway init failed, continuing without gateway", "error", err)
	} else {
		if err := gw.Start(); err != nil {
			slog.Warn("gateway start failed, continuing without gateway", "error", err)
			gw = nil
		} else {
			slog.Info("gateway started", "subnet", "10.4.0.0/16")
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	if gw != nil {
		gw.Stop()
	}
	d.Stop()
}

// PID file helpers
func readPID() int {
	data, err := os.ReadFile(pidFilePath())
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0
	}
	return pid
}

func processExists(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Unix, FindProcess always succeeds. Use Signal(0) to check.
	return proc.Signal(syscall.Signal(0)) == nil
}

// ===================== GATEWAY =====================

const gatewayPIDFile = "gateway.pid"

func gatewayPIDPath() string { return configDir() + "/" + gatewayPIDFile }

func cmdGatewayStart(args []string) {
	flags, pos := parseFlags(args)

	// Check if already running
	if pid := readGatewayPID(); pid > 0 && processExists(pid) {
		fatalCode("already_exists", "gateway already running (pid %d)", pid)
	}

	subnet := flagString(flags, "subnet", "10.4.0.0/16")
	portsStr := flagString(flags, "ports", "")
	socketPath := getSocket()

	var ports []uint16
	if portsStr != "" {
		for _, s := range strings.Split(portsStr, ",") {
			s = strings.TrimSpace(s)
			p, err := strconv.ParseUint(s, 10, 16)
			if err != nil {
				fatalCode("invalid_argument", "invalid port %q: %v", s, err)
			}
			ports = append(ports, uint16(p))
		}
	}

	gw, err := gateway.New(gateway.Config{
		Subnet:     subnet,
		SocketPath: socketPath,
		Ports:      ports,
	})
	if err != nil {
		fatalCode("internal", "create gateway: %v", err)
	}

	if err := gw.Start(); err != nil {
		fatalCode("internal", "start gateway: %v", err)
	}

	// Map any addresses from positional args
	var mappings []map[string]interface{}
	for _, addr := range pos {
		pilotAddr, err := protocol.ParseAddr(addr)
		if err != nil {
			fatalCode("invalid_argument", "parse address %s: %v", addr, err)
		}
		assigned, err := gw.Map(pilotAddr, "")
		if err != nil {
			fatalCode("internal", "map %s: %v", addr, err)
		}
		mappings = append(mappings, map[string]interface{}{
			"local_ip":   assigned,
			"pilot_addr": pilotAddr.String(),
		})
	}

	// Write PID
	os.MkdirAll(configDir(), 0700)
	os.WriteFile(gatewayPIDPath(), []byte(strconv.Itoa(os.Getpid())), 0600)

	if jsonOutput {
		outputOK(map[string]interface{}{
			"pid":      os.Getpid(),
			"subnet":   subnet,
			"mappings": mappings,
		})
	} else {
		for _, m := range mappings {
			fmt.Printf("mapped %s → %s\n", m["local_ip"], m["pilot_addr"])
		}
		fmt.Println("gateway running")
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	gw.Stop()
	os.Remove(gatewayPIDPath())
}

func cmdGatewayStop() {
	pid := readGatewayPID()
	if pid <= 0 || !processExists(pid) {
		fatalCode("not_running", "gateway not running")
	}
	proc, _ := os.FindProcess(pid)
	proc.Signal(syscall.SIGTERM)
	time.Sleep(time.Second)
	os.Remove(gatewayPIDPath())
	outputOK(map[string]interface{}{"pid": pid})
}

func cmdGatewayMap(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl gateway map <pilot-addr> [local-ip]")
	}
	pilotAddr, err := protocol.ParseAddr(args[0])
	if err != nil {
		fatalCode("invalid_argument", "parse address: %v", err)
	}
	localIP := ""
	if len(args) > 1 {
		localIP = args[1]
	}

	gw, err := gateway.New(gateway.Config{
		SocketPath: getSocket(),
	})
	if err != nil {
		fatalCode("internal", "create gateway: %v", err)
	}
	if err := gw.Start(); err != nil {
		fatalCode("internal", "start gateway: %v", err)
	}
	assigned, err := gw.Map(pilotAddr, localIP)
	if err != nil {
		fatalCode("internal", "map: %v", err)
	}
	outputOK(map[string]interface{}{
		"local_ip":   assigned,
		"pilot_addr": pilotAddr.String(),
	})
}

func cmdGatewayUnmap(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl gateway unmap <local-ip>")
	}
	localIP := args[0]

	pid := readGatewayPID()
	if pid <= 0 || !processExists(pid) {
		fatalCode("not_running", "gateway not running")
	}

	gw, err := gateway.New(gateway.Config{
		SocketPath: getSocket(),
	})
	if err != nil {
		fatalCode("internal", "create gateway: %v", err)
	}
	if err := gw.Unmap(localIP); err != nil {
		fatalCode("not_found", "unmap: %v", err)
	}
	outputOK(map[string]interface{}{
		"unmapped": localIP,
	})
}

func cmdGatewayList() {
	pid := readGatewayPID()
	if pid <= 0 || !processExists(pid) {
		fatalCode("not_running", "gateway not running")
	}

	gw, err := gateway.New(gateway.Config{
		SocketPath: getSocket(),
	})
	if err != nil {
		fatalCode("internal", "create gateway: %v", err)
	}

	mappings := gw.Mappings().All()
	result := make([]map[string]interface{}, 0, len(mappings))
	for _, m := range mappings {
		result = append(result, map[string]interface{}{
			"local_ip":   m.LocalIP.String(),
			"pilot_addr": m.PilotAddr.String(),
		})
	}

	if jsonOutput {
		outputOK(map[string]interface{}{
			"mappings": result,
			"total":    len(result),
		})
	} else {
		if len(result) == 0 {
			fmt.Println("no mappings")
			return
		}
		for _, m := range result {
			fmt.Printf("%s → %s\n", m["local_ip"], m["pilot_addr"])
		}
		fmt.Printf("total: %d\n", len(result))
	}
}

func readGatewayPID() int {
	data, err := os.ReadFile(gatewayPIDPath())
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	return pid
}

// ===================== REGISTRY =====================

func cmdRegister(args []string) {
	listenAddr := ""
	if len(args) > 0 {
		listenAddr = args[0]
	}
	rc := connectRegistry()
	defer rc.Close()
	resp, err := rc.Register(listenAddr)
	if err != nil {
		fatalCode("connection_failed", "register: %v", err)
	}
	output(resp)
}

func cmdLookup(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl lookup <node_id>")
	}
	nodeID := parseNodeID(args[0])
	rc := connectRegistry()
	defer rc.Close()
	resp, err := rc.Lookup(nodeID)
	if err != nil {
		fatalCode("connection_failed", "lookup: %v", err)
	}
	output(resp)
}

func cmdRotateKey(args []string) {
	if len(args) < 2 {
		fatalCode("invalid_argument", "usage: pilotctl rotate-key <node_id> <owner>")
	}
	nodeID := parseNodeID(args[0])
	owner := args[1]
	rc := connectRegistry()
	defer rc.Close()
	resp, err := rc.RotateKey(nodeID, "", owner)
	if err != nil {
		fatalCode("connection_failed", "rotate-key: %v", err)
	}
	output(resp)
}

func cmdSetPublic(args []string) {
	d := connectDriver()
	defer d.Close()
	resp, err := d.SetVisibility(true)
	if err != nil {
		fatalCode("connection_failed", "set-public: %v", err)
	}
	output(resp)
}

func cmdSetPrivate(args []string) {
	d := connectDriver()
	defer d.Close()
	resp, err := d.SetVisibility(false)
	if err != nil {
		fatalCode("connection_failed", "set-private: %v", err)
	}
	output(resp)
}

func cmdDeregister(args []string) {
	d := connectDriver()
	defer d.Close()
	resp, err := d.Deregister()
	if err != nil {
		fatalCode("connection_failed", "deregister: %v", err)
	}
	output(resp)
}

// ===================== DISCOVERY =====================

func cmdFind(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl find <hostname>")
	}
	d := connectDriver()
	defer d.Close()

	hostname := args[0]
	result, err := d.ResolveHostname(hostname)
	if err != nil {
		fatalCode("not_found", "find: %v", err)
	}

	nodeID := int(result["node_id"].(float64))
	address := result["address"].(string)
	public := false
	if p, ok := result["public"].(bool); ok {
		public = p
	}

	if jsonOutput {
		output(map[string]interface{}{
			"hostname": hostname,
			"node_id":  nodeID,
			"address":  address,
			"public":   public,
		})
	} else {
		fmt.Printf("Hostname:  %s\n", hostname)
		fmt.Printf("Node ID:   %d\n", nodeID)
		fmt.Printf("Address:   %s\n", address)
		visibility := "private"
		if public {
			visibility = "public"
		}
		fmt.Printf("Visible:   %s\n", visibility)
	}
}

func cmdSetHostname(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl set-hostname <hostname>")
	}
	d := connectDriver()
	defer d.Close()

	hostname := args[0]
	result, err := d.SetHostname(hostname)
	if err != nil {
		fatalCode("connection_failed", "set-hostname: %v", err)
	}

	if jsonOutput {
		outputOK(map[string]interface{}{
			"hostname": result["hostname"],
			"node_id":  result["node_id"],
		})
	} else if hostname == "" {
		fmt.Printf("hostname cleared\n")
	} else {
		fmt.Printf("hostname set: %s\n", result["hostname"])
	}
}

func cmdClearHostname() {
	d := connectDriver()
	defer d.Close()

	_, err := d.SetHostname("")
	if err != nil {
		fatalCode("connection_failed", "clear-hostname: %v", err)
	}

	if jsonOutput {
		outputOK(map[string]interface{}{
			"hostname": "",
		})
	} else {
		fmt.Printf("hostname cleared\n")
	}
}

// ===================== COMMUNICATION =====================

func cmdConnect(args []string) {
	flags, pos := parseFlags(args)
	if len(pos) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl connect <address|hostname> [port] [--message <msg>] [--timeout <dur>]")
	}

	d := connectDriver()
	defer d.Close()

	target, err := parseAddrOrHostname(d, pos[0])
	if err != nil {
		fatalCode("not_found", "%v", err)
	}

	port := protocol.PortStdIO
	if len(pos) > 1 {
		p, _ := strconv.ParseUint(pos[1], 10, 16)
		port = uint16(p)
	}

	message := flagString(flags, "message", "")
	timeout := flagDuration(flags, "timeout", 30*time.Second)

	// --message mode: send one message, read one response, exit
	if message != "" {
		conn, err := d.DialAddr(target, port)
		if err != nil {
			fatalCode("connection_failed", "dial: %v", err)
		}
		defer conn.Close()

		if _, err := conn.Write([]byte(message)); err != nil {
			fatalCode("connection_failed", "write: %v", err)
		}

		buf := make([]byte, 65535)
		done := make(chan int)
		var readErr error
		go func() {
			n, err := conn.Read(buf)
			readErr = err
			done <- n
		}()

		select {
		case n := <-done:
			if readErr != nil {
				fatalCode("connection_failed", "read: %v", readErr)
			}
			response := string(buf[:n])
			if jsonOutput {
				output(map[string]interface{}{
					"target":   target.String(),
					"port":     port,
					"sent":     message,
					"response": response,
				})
			} else {
				fmt.Print(response)
				fmt.Println()
			}
		case <-time.After(timeout):
			fatalCode("timeout", "timeout waiting for response")
		}
		return
	}

	// Interactive mode (unchanged from original)
	if !jsonOutput {
		fmt.Fprintf(os.Stderr, "connecting to %s:%d...\n", target, port)
	}
	conn, err := d.DialAddr(target, port)
	if err != nil {
		fatalCode("connection_failed", "dial: %v", err)
	}
	defer conn.Close()
	if !jsonOutput {
		fmt.Fprintf(os.Stderr, "connected. Type messages, Ctrl+D to quit.\n")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			os.Stdout.Write(buf[:n])
			os.Stdout.Write([]byte("\n"))
		}
	}()

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		if _, err := conn.Write([]byte(line)); err != nil {
			break
		}
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
	conn.Close()
}

func cmdSend(args []string) {
	flags, pos := parseFlags(args)
	if len(pos) < 2 {
		fatalCode("invalid_argument", "usage: pilotctl send <address|hostname> <port> --data <msg> [--timeout <dur>]")
	}

	d := connectDriver()
	defer d.Close()

	target, err := parseAddrOrHostname(d, pos[0])
	if err != nil {
		fatalCode("not_found", "%v", err)
	}
	p, _ := strconv.ParseUint(pos[1], 10, 16)
	port := uint16(p)

	data := flagString(flags, "data", "")
	if data == "" {
		fatalCode("invalid_argument", "--data is required")
	}
	timeout := flagDuration(flags, "timeout", 30*time.Second)

	conn, err := d.DialAddr(target, port)
	if err != nil {
		fatalCode("connection_failed", "dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte(data)); err != nil {
		fatalCode("connection_failed", "write: %v", err)
	}

	buf := make([]byte, 65535)
	doneCh := make(chan int)
	var readErr error
	go func() {
		n, err := conn.Read(buf)
		readErr = err
		doneCh <- n
	}()

	select {
	case n := <-doneCh:
		if readErr != nil {
			fatalCode("connection_failed", "read: %v", readErr)
		}
		response := string(buf[:n])
		if jsonOutput {
			output(map[string]interface{}{
				"target":   target.String(),
				"port":     port,
				"sent":     data,
				"response": response,
			})
		} else {
			fmt.Println(response)
		}
	case <-time.After(timeout):
		fatalCode("timeout", "timeout waiting for response")
	}
}

func cmdRecv(args []string) {
	flags, pos := parseFlags(args)
	if len(pos) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl recv <port> [--count <n>] [--timeout <dur>]")
	}

	p, _ := strconv.ParseUint(pos[0], 10, 16)
	port := uint16(p)
	count := flagInt(flags, "count", 1)
	timeout := flagDuration(flags, "timeout", 30*time.Second)

	d := connectDriver()
	defer d.Close()

	ln, err := d.Listen(port)
	if err != nil {
		fatalCode("connection_failed", "listen: %v", err)
	}

	var messages []map[string]interface{}
	deadline := time.After(timeout)

	for i := 0; i < count; i++ {
		doneCh := make(chan net.Conn)
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				doneCh <- nil
				return
			}
			doneCh <- conn
		}()

		select {
		case conn := <-doneCh:
			if conn == nil {
				fatalCode("connection_failed", "accept error")
			}
			buf := make([]byte, 65535)
			n, err := conn.Read(buf)
			msg := map[string]interface{}{
				"seq":  i,
				"port": port,
			}
			if err != nil {
				msg["error"] = err.Error()
			} else {
				msg["data"] = string(buf[:n])
				msg["bytes"] = n
			}
			messages = append(messages, msg)
			conn.Close()

			if !jsonOutput {
				if errStr, ok := msg["error"].(string); ok {
					fmt.Fprintf(os.Stderr, "error: %s\n", errStr)
				} else {
					fmt.Println(msg["data"])
				}
			}
		case <-deadline:
			if jsonOutput {
				output(map[string]interface{}{
					"messages": messages,
					"timeout":  true,
				})
			} else {
				fmt.Fprintln(os.Stderr, "timeout")
			}
			return
		}
	}

	if jsonOutput {
		output(map[string]interface{}{
			"messages": messages,
			"timeout":  false,
		})
	}
}

func cmdSendFile(args []string) {
	if len(args) < 2 {
		fatalCode("invalid_argument", "usage: pilotctl send-file <address> <filepath>")
	}

	d := connectDriver()
	defer d.Close()

	target, err := parseAddrOrHostname(d, args[0])
	if err != nil {
		fatalCode("invalid_argument", "%v", err)
	}

	filePath := args[1]
	f, err := os.Open(filePath)
	if err != nil {
		fatalCode("internal", "open file: %v", err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		fatalCode("internal", "stat file: %v", err)
	}

	conn, err := d.DialAddr(target, protocol.PortDataExchange)
	if err != nil {
		fatalCode("connection_failed", "dial: %v", err)
	}
	defer conn.Close()

	filename := fi.Name()
	data, err := io.ReadAll(f)
	if err != nil {
		fatalCode("internal", "read file: %v", err)
	}

	payload := append([]byte(filename), 0)
	payload = append(payload, data...)

	header := make([]byte, 8)
	header[3] = 4 // type = file
	l := uint32(len(payload))
	header[4] = byte(l >> 24)
	header[5] = byte(l >> 16)
	header[6] = byte(l >> 8)
	header[7] = byte(l)

	frame := append(header, payload...)
	if _, err := conn.Write(frame); err != nil {
		fatalCode("connection_failed", "send: %v", err)
	}

	outputOK(map[string]interface{}{
		"filename":    filename,
		"bytes":       len(data),
		"destination": target.String(),
	})
}

// ===================== TRUST =====================

func cmdHandshake(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl handshake <node_id|hostname> [justification]")
	}
	d := connectDriver()
	defer d.Close()

	var nodeID uint32
	target := args[0]
	if id, err := strconv.ParseUint(target, 10, 32); err == nil {
		nodeID = uint32(id)
	} else {
		_, resolved, err := resolveHostnameToAddr(d, target)
		if err != nil {
			fatalCode("not_found", "resolve hostname %q: %v", target, err)
		}
		nodeID = resolved
		if !jsonOutput {
			fmt.Fprintf(os.Stderr, "resolved %s → node %d\n", target, nodeID)
		}
	}

	justification := ""
	if len(args) > 1 {
		justification = args[1]
	}

	result, err := d.Handshake(nodeID, justification)
	if err != nil {
		fatalCode("connection_failed", "handshake: %v", err)
	}
	if jsonOutput {
		result["node_id"] = nodeID
		output(result)
	} else {
		fmt.Printf("handshake request sent to node %d\n", nodeID)
		b, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(b))
	}
}

func cmdApprove(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl approve <node_id>")
	}
	d := connectDriver()
	defer d.Close()

	nodeID := parseNodeID(args[0])

	result, err := d.ApproveHandshake(nodeID)
	if err != nil {
		fatalCode("connection_failed", "approve: %v", err)
	}
	if jsonOutput {
		result["node_id"] = nodeID
		output(result)
	} else {
		fmt.Printf("handshake from node %d approved\n", nodeID)
		b, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(b))
	}
}

func cmdReject(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl reject <node_id> [reason]")
	}
	d := connectDriver()
	defer d.Close()

	nodeID := parseNodeID(args[0])
	reason := ""
	if len(args) > 1 {
		reason = args[1]
	}

	result, err := d.RejectHandshake(nodeID, reason)
	if err != nil {
		fatalCode("connection_failed", "reject: %v", err)
	}
	if jsonOutput {
		result["node_id"] = nodeID
		output(result)
	} else {
		fmt.Printf("handshake from node %d rejected\n", nodeID)
		b, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(b))
	}
}

func cmdUntrust(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl untrust <node_id>")
	}
	nodeID, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		fatalCode("invalid_argument", "invalid node_id: %v", err)
	}

	d := connectDriver()
	defer d.Close()

	_, err = d.RevokeTrust(uint32(nodeID))
	if err != nil {
		fatalCode("connection_failed", "untrust: %v", err)
	}
	outputOK(map[string]interface{}{"node_id": nodeID})
}

func cmdPending() {
	d := connectDriver()
	defer d.Close()

	result, err := d.PendingHandshakes()
	if err != nil {
		fatalCode("connection_failed", "pending: %v", err)
	}

	pending, ok := result["pending"].([]interface{})
	if !ok {
		pending = []interface{}{}
	}

	if jsonOutput {
		output(map[string]interface{}{"pending": pending})
		return
	}

	if len(pending) == 0 {
		fmt.Println("no pending handshake requests")
		return
	}

	fmt.Printf("%-10s  %-40s  %s\n", "NODE ID", "JUSTIFICATION", "RECEIVED")
	for _, p := range pending {
		req := p.(map[string]interface{})
		nodeID := int(req["node_id"].(float64))
		justification, _ := req["justification"].(string)
		receivedAt := int64(req["received_at"].(float64))
		t := time.Unix(receivedAt, 0)
		fmt.Printf("%-10d  %-40s  %s\n", nodeID, justification, t.Format("2006-01-02 15:04:05"))
	}
}

func cmdTrust() {
	d := connectDriver()
	defer d.Close()

	result, err := d.TrustedPeers()
	if err != nil {
		fatalCode("connection_failed", "trust: %v", err)
	}

	trusted, ok := result["trusted"].([]interface{})
	if !ok {
		trusted = []interface{}{}
	}

	if jsonOutput {
		output(map[string]interface{}{"trusted": trusted})
		return
	}

	if len(trusted) == 0 {
		fmt.Println("no trusted peers")
		return
	}

	fmt.Printf("%-10s  %-10s  %-10s  %s\n", "NODE ID", "MUTUAL", "NETWORK", "APPROVED AT")
	for _, t := range trusted {
		rec := t.(map[string]interface{})
		nodeID := int(rec["node_id"].(float64))
		mutual := false
		if m, ok := rec["mutual"].(bool); ok {
			mutual = m
		}
		network := uint16(0)
		if n, ok := rec["network"].(float64); ok {
			network = uint16(n)
		}
		approvedAt := int64(rec["approved_at"].(float64))
		at := time.Unix(approvedAt, 0)

		mutualStr := "no"
		if mutual {
			mutualStr = "yes"
		}
		netStr := "-"
		if network > 0 {
			netStr = fmt.Sprintf("%d", network)
		}
		fmt.Printf("%-10d  %-10s  %-10s  %s\n", nodeID, mutualStr, netStr, at.Format("2006-01-02 15:04:05"))
	}
}

// ===================== MANAGEMENT =====================

func cmdConnections() {
	d := connectDriver()
	defer d.Close()

	info, err := d.Info()
	if err != nil {
		fatalCode("connection_failed", "info: %v", err)
	}

	connList, ok := info["conn_list"].([]interface{})
	if !ok {
		connList = []interface{}{}
	}

	if jsonOutput {
		output(map[string]interface{}{
			"connections": connList,
			"total":       len(connList),
		})
		return
	}

	if len(connList) == 0 {
		fmt.Println("no active connections")
		return
	}

	maxDisplay := 50
	fmt.Printf("Active connections: %d\n\n", len(connList))
	fmt.Printf("%-4s  %-6s  %-22s  %-6s  %-11s  %-8s  %-8s  %-8s  %-6s  %-6s  %-8s  %-8s\n",
		"ID", "LOCAL", "REMOTE ADDR", "RPORT", "STATE", "CWND", "FLIGHT", "SRTT", "UNACK", "OOO", "PEERWIN", "RCVWIN")
	displayed := 0
	for _, c := range connList {
		if displayed >= maxDisplay {
			fmt.Printf("\n... and %d more connections (showing first %d)\n", len(connList)-maxDisplay, maxDisplay)
			break
		}
		displayed++
		conn := c.(map[string]interface{})
		peerWin := int(conn["peer_recv_win"].(float64))
		recvWin := int(conn["recv_win"].(float64))
		fmt.Printf("%-4d  %-6d  %-22s  %-6d  %-11s  %-8s  %-8s  %-6.0fms  %-6d  %-6d  %-8s  %-8s\n",
			int(conn["id"].(float64)),
			int(conn["local_port"].(float64)),
			conn["remote_addr"],
			int(conn["remote_port"].(float64)),
			conn["state"],
			formatBytes(uint64(conn["cong_win"].(float64))),
			formatBytes(uint64(conn["in_flight"].(float64))),
			conn["srtt_ms"].(float64),
			int(conn["unacked"].(float64)),
			int(conn["ooo_buf"].(float64)),
			formatBytes(uint64(peerWin)),
			formatBytes(uint64(recvWin)),
		)
		bytesSent := uint64(conn["bytes_sent"].(float64))
		bytesRecv := uint64(conn["bytes_recv"].(float64))
		segsSent := uint64(conn["segs_sent"].(float64))
		segsRecv := uint64(conn["segs_recv"].(float64))
		retx := uint64(conn["retransmits"].(float64))
		fastRetx := uint64(conn["fast_retx"].(float64))
		sackRecv := uint64(conn["sack_recv"].(float64))
		sackSent := uint64(conn["sack_sent"].(float64))
		dupAcks := uint64(conn["dup_acks"].(float64))
		fmt.Printf("      tx: %s (%d segs)  rx: %s (%d segs)  retx: %d  fast-retx: %d  sack: %d/%d  dup-ack: %d\n",
			formatBytes(bytesSent), segsSent, formatBytes(bytesRecv), segsRecv,
			retx, fastRetx, sackSent, sackRecv, dupAcks)
	}
}

func cmdDisconnect(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl disconnect <conn_id>")
	}
	connID, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		fatalCode("invalid_argument", "invalid connection ID: %v", err)
	}

	d := connectDriver()
	defer d.Close()

	if err := d.Disconnect(uint32(connID)); err != nil {
		fatalCode("connection_failed", "disconnect: %v", err)
	}
	outputOK(map[string]interface{}{"conn_id": connID})
}

// ===================== DIAGNOSTICS =====================

func cmdInfo() {
	d := connectDriver()
	defer d.Close()

	info, err := d.Info()
	if err != nil {
		fatalCode("connection_failed", "info: %v", err)
	}

	if jsonOutput {
		output(info)
		return
	}

	// Human-readable
	uptime := info["uptime_secs"].(float64)
	hours := int(uptime) / 3600
	mins := (int(uptime) % 3600) / 60
	secs := int(uptime) % 60

	bytesSent := uint64(info["bytes_sent"].(float64))
	bytesRecv := uint64(info["bytes_recv"].(float64))
	pktsSent := uint64(info["pkts_sent"].(float64))
	pktsRecv := uint64(info["pkts_recv"].(float64))

	encryptEnabled := false
	if e, ok := info["encrypt"].(bool); ok {
		encryptEnabled = e
	}
	encryptedPeers := 0
	if ep, ok := info["encrypted_peers"].(float64); ok {
		encryptedPeers = int(ep)
	}

	fmt.Printf("Pilot Protocol Daemon\n")
	fmt.Printf("  Node ID:     %d\n", int(info["node_id"].(float64)))
	fmt.Printf("  Address:     %s\n", info["address"])
	if hostname, ok := info["hostname"].(string); ok && hostname != "" {
		fmt.Printf("  Hostname:    %s\n", hostname)
	}
	fmt.Printf("  Uptime:      %02d:%02d:%02d\n", hours, mins, secs)
	fmt.Printf("  Connections: %d\n", int(info["connections"].(float64)))
	fmt.Printf("  Ports:       %d\n", int(info["ports"].(float64)))
	fmt.Printf("  Peers:       %d\n", int(info["peers"].(float64)))
	authenticatedPeers := 0
	if ap, ok := info["authenticated_peers"].(float64); ok {
		authenticatedPeers = int(ap)
	}
	if encryptEnabled {
		fmt.Printf("  Encryption:  enabled (X25519 + AES-256-GCM), %d/%d peers encrypted, %d authenticated\n",
			encryptedPeers, int(info["peers"].(float64)), authenticatedPeers)
	} else {
		fmt.Printf("  Encryption:  disabled\n")
	}
	hasIdentity := false
	if id, ok := info["identity"].(bool); ok {
		hasIdentity = id
	}
	if hasIdentity {
		pubKey, _ := info["public_key"].(string)
		fingerprint := pubKey
		if len(fingerprint) > 16 {
			fingerprint = fingerprint[:16] + "..."
		}
		fmt.Printf("  Identity:    persistent (Ed25519 %s)\n", fingerprint)
	} else {
		fmt.Printf("  Identity:    ephemeral (not persisted)\n")
	}
	if owner, ok := info["owner"].(string); ok && owner != "" {
		fmt.Printf("  Owner:       %s\n", owner)
	}
	fmt.Printf("  Traffic:     %s sent / %s recv\n", formatBytes(bytesSent), formatBytes(bytesRecv))
	fmt.Printf("  Packets:     %d sent / %d recv\n", pktsSent, pktsRecv)

	connList, ok := info["conn_list"].([]interface{})
	if ok && len(connList) > 0 {
		maxDisplay := 50
		fmt.Printf("\nActive connections: %d\n", len(connList))
		fmt.Printf("  %-4s  %-6s  %-22s  %-6s  %-11s  %-8s  %-8s  %-6s\n",
			"ID", "LOCAL", "REMOTE ADDR", "RPORT", "STATE", "CWND", "FLIGHT", "SRTT")
		displayed := 0
		for _, c := range connList {
			if displayed >= maxDisplay {
				fmt.Printf("\n  ... and %d more connections (showing first %d)\n", len(connList)-maxDisplay, maxDisplay)
				break
			}
			displayed++
			conn := c.(map[string]interface{})
			recoveryStr := ""
			if inRec, ok := conn["in_recovery"].(bool); ok && inRec {
				recoveryStr = " [RECOVERY]"
			}
			fmt.Printf("  %-4d  %-6d  %-22s  %-6d  %-11s  %-8s  %-8s  %.0fms%s\n",
				int(conn["id"].(float64)),
				int(conn["local_port"].(float64)),
				conn["remote_addr"],
				int(conn["remote_port"].(float64)),
				conn["state"],
				formatBytes(uint64(conn["cong_win"].(float64))),
				formatBytes(uint64(conn["in_flight"].(float64))),
				conn["srtt_ms"].(float64),
				recoveryStr,
			)
		}
	}
}

func cmdPeers(args []string) {
	flags, _ := parseFlags(args)
	search := flagString(flags, "search", "")

	d := connectDriver()
	defer d.Close()

	info, err := d.Info()
	if err != nil {
		fatalCode("connection_failed", "info: %v", err)
	}

	peerList, ok := info["peer_list"].([]interface{})
	if !ok {
		peerList = []interface{}{}
	}

	// Filter by search query
	var filtered []interface{}
	for _, p := range peerList {
		if search == "" {
			filtered = append(filtered, p)
			continue
		}
		peer := p.(map[string]interface{})
		searchLower := strings.ToLower(search)
		nodeIDStr := fmt.Sprintf("%d", int(peer["node_id"].(float64)))
		endpoint, _ := peer["endpoint"].(string)
		if strings.Contains(nodeIDStr, searchLower) ||
			strings.Contains(strings.ToLower(endpoint), searchLower) {
			filtered = append(filtered, p)
		}
	}

	if jsonOutput {
		output(map[string]interface{}{
			"peers": filtered,
			"total": len(filtered),
		})
		return
	}

	if len(filtered) == 0 {
		if search != "" {
			fmt.Printf("no peers matching %q\n", search)
		} else {
			fmt.Println("no peers connected")
		}
		return
	}

	maxDisplay := 50
	fmt.Printf("%-10s  %-30s  %-20s  %s\n", "NODE ID", "ENDPOINT", "ENCRYPTED", "AUTH")
	displayed := 0
	for _, p := range filtered {
		if displayed >= maxDisplay {
			fmt.Printf("\n... and %d more peers (showing first %d)\n", len(filtered)-maxDisplay, maxDisplay)
			break
		}
		displayed++
		peer := p.(map[string]interface{})
		encrypted := false
		if e, ok := peer["encrypted"].(bool); ok {
			encrypted = e
		}
		authenticated := false
		if a, ok := peer["authenticated"].(bool); ok {
			authenticated = a
		}
		encStr := "no"
		if encrypted {
			encStr = "yes (AES-256-GCM)"
		}
		authStr := "no"
		if authenticated {
			authStr = "yes (Ed25519)"
		}
		fmt.Printf("%-10d  %-30s  %-20s  %s\n", int(peer["node_id"].(float64)), peer["endpoint"], encStr, authStr)
	}
}

func cmdPing(args []string) {
	flags, pos := parseFlags(args)
	if len(pos) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl ping <address|hostname> [--count <n>] [--timeout <dur>]")
	}

	count := flagInt(flags, "count", 4)
	timeout := flagDuration(flags, "timeout", 30*time.Second)

	d := connectDriver()
	defer d.Close()

	target, err := parseAddrOrHostname(d, pos[0])
	if err != nil {
		fatalCode("not_found", "%v", err)
	}

	if !jsonOutput {
		fmt.Printf("PING %s\n", target)
	}

	var results []map[string]interface{}
	deadline := time.After(timeout)

	for i := 0; i < count; i++ {
		select {
		case <-deadline:
			if jsonOutput {
				output(map[string]interface{}{
					"target":  target.String(),
					"results": results,
					"timeout": true,
				})
			} else {
				fmt.Println("timeout")
			}
			return
		default:
		}

		start := time.Now()
		conn, err := d.DialAddr(target, protocol.PortEcho)
		if err != nil {
			r := map[string]interface{}{"seq": i, "error": err.Error()}
			results = append(results, r)
			if !jsonOutput {
				fmt.Printf("seq=%d error: %v\n", i, err)
			}
			time.Sleep(time.Second)
			continue
		}

		payload := fmt.Sprintf("ping-%d", i)
		conn.Write([]byte(payload))

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		conn.Close()

		rtt := time.Since(start)
		r := map[string]interface{}{
			"seq":    i,
			"rtt_ms": float64(rtt.Microseconds()) / 1000.0,
		}
		if err != nil {
			r["error"] = err.Error()
			if !jsonOutput {
				fmt.Printf("seq=%d error: %v\n", i, err)
			}
		} else {
			r["bytes"] = n
			if !jsonOutput {
				fmt.Printf("seq=%d bytes=%d time=%v\n", i, n, rtt)
			}
		}
		results = append(results, r)

		if i < count-1 {
			time.Sleep(time.Second)
		}
	}

	if jsonOutput {
		output(map[string]interface{}{
			"target":  target.String(),
			"results": results,
			"timeout": false,
		})
	}
}

func cmdTraceroute(args []string) {
	flags, pos := parseFlags(args)
	if len(pos) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl traceroute <address> [--timeout <dur>]")
	}

	timeout := flagDuration(flags, "timeout", 30*time.Second)

	d := connectDriver()
	defer d.Close()

	target, err := protocol.ParseAddr(pos[0])
	if err != nil {
		fatalCode("invalid_argument", "parse address: %v", err)
	}

	if !jsonOutput {
		fmt.Printf("TRACEROUTE %s\n", target)
	}

	start := time.Now()
	connDone := make(chan *driver.Conn)
	var dialErr error
	go func() {
		conn, err := d.DialAddr(target, protocol.PortEcho)
		dialErr = err
		connDone <- conn
	}()

	var conn *driver.Conn
	select {
	case conn = <-connDone:
	case <-time.After(timeout):
		fatalCode("timeout", "dial timeout")
	}

	setupTime := time.Since(start)
	if dialErr != nil {
		if jsonOutput {
			output(map[string]interface{}{
				"target":   target.String(),
				"setup_ms": float64(setupTime.Microseconds()) / 1000.0,
				"error":    dialErr.Error(),
			})
		} else {
			fmt.Printf("  1  %s  connection failed: %v\n", target, dialErr)
		}
		return
	}

	if !jsonOutput {
		fmt.Printf("  1  %s  setup=%v\n", target, setupTime)
	}

	var rttSamples []map[string]interface{}
	for i := 0; i < 3; i++ {
		pingStart := time.Now()
		payload := fmt.Sprintf("trace-%d", i)
		conn.Write([]byte(payload))

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		rtt := time.Since(pingStart)

		sample := map[string]interface{}{
			"rtt_ms": float64(rtt.Microseconds()) / 1000.0,
		}
		if err != nil {
			sample["error"] = err.Error()
			if !jsonOutput {
				fmt.Printf("     rtt=%v error: %v\n", rtt, err)
			}
		} else {
			sample["bytes"] = n
			if !jsonOutput {
				fmt.Printf("     rtt=%v bytes=%d\n", rtt, n)
			}
		}
		rttSamples = append(rttSamples, sample)
	}
	conn.Close()

	if jsonOutput {
		output(map[string]interface{}{
			"target":      target.String(),
			"setup_ms":    float64(setupTime.Microseconds()) / 1000.0,
			"rtt_samples": rttSamples,
		})
	} else {
		fmt.Printf("\nsetup includes: tunnel negotiation + SYN/ACK handshake\n")
		fmt.Printf("rtt is: data round-trip over established connection\n")
	}
}

func cmdBench(args []string) {
	flags, pos := parseFlags(args)
	if len(pos) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl bench <address|hostname> [size_mb] [--timeout <dur>]")
	}

	timeout := flagDuration(flags, "timeout", 120*time.Second)

	d := connectDriver()
	defer d.Close()

	target, err := parseAddrOrHostname(d, pos[0])
	if err != nil {
		fatalCode("not_found", "%v", err)
	}

	totalSize := 1024 * 1024
	if len(pos) > 1 {
		sizeMB, err := strconv.ParseFloat(pos[1], 64)
		if err != nil {
			fatalCode("invalid_argument", "invalid size: %v", err)
		}
		totalSize = int(sizeMB * 1024 * 1024)
	}
	const chunkSize = 4096

	if !jsonOutput {
		fmt.Printf("BENCH %s — sending %s via echo port\n", target, formatBytes(uint64(totalSize)))
	}

	conn, err := d.DialAddr(target, protocol.PortEcho)
	if err != nil {
		fatalCode("connection_failed", "dial: %v", err)
	}
	defer conn.Close()

	var recvTotal int
	recvDone := make(chan struct{})
	go func() {
		defer close(recvDone)
		buf := make([]byte, 65535)
		for recvTotal < totalSize {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			recvTotal += n
		}
	}()

	chunk := make([]byte, chunkSize)
	for i := range chunk {
		chunk[i] = byte(i % 256)
	}

	start := time.Now()
	sent := 0
	for sent < totalSize {
		remaining := totalSize - sent
		writeSize := chunkSize
		if remaining < writeSize {
			writeSize = remaining
		}
		if _, err := conn.Write(chunk[:writeSize]); err != nil {
			fatalCode("connection_failed", "write: %v", err)
		}
		sent += writeSize
	}
	sendDuration := time.Since(start)

	select {
	case <-recvDone:
	case <-time.After(timeout):
		if !jsonOutput {
			fmt.Printf("warning: receive timed out (got %s of %s)\n",
				formatBytes(uint64(recvTotal)), formatBytes(uint64(totalSize)))
		}
	}
	totalDuration := time.Since(start)

	sendThroughput := float64(totalSize) / sendDuration.Seconds() / 1024 / 1024
	totalThroughput := float64(totalSize) / totalDuration.Seconds() / 1024 / 1024

	if jsonOutput {
		output(map[string]interface{}{
			"target":            target.String(),
			"sent_bytes":        sent,
			"recv_bytes":        recvTotal,
			"send_duration_ms":  float64(sendDuration.Milliseconds()),
			"total_duration_ms": float64(totalDuration.Milliseconds()),
			"send_mbps":         sendThroughput,
			"total_mbps":        totalThroughput,
		})
	} else {
		fmt.Printf("  Sent:     %s in %v (%.1f MB/s)\n", formatBytes(uint64(sent)), sendDuration.Round(time.Millisecond), sendThroughput)
		fmt.Printf("  Echoed:   %s in %v (%.1f MB/s round-trip)\n", formatBytes(uint64(recvTotal)), totalDuration.Round(time.Millisecond), totalThroughput)
	}
}

func cmdListen(args []string) {
	flags, pos := parseFlags(args)
	if len(pos) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl listen <port> [--count <n>] [--timeout <dur>]")
	}

	p, _ := strconv.ParseUint(pos[0], 10, 16)
	port := uint16(p)
	count := flagInt(flags, "count", 0) // 0 = infinite
	timeout := flagDuration(flags, "timeout", 0)

	d := connectDriver()
	defer d.Close()

	if !jsonOutput {
		fmt.Fprintf(os.Stderr, "listening for datagrams on port %d...\n", port)
	}

	var messages []map[string]interface{}
	received := 0

	var deadline <-chan time.Time
	if timeout > 0 {
		deadline = time.After(timeout)
	}

	for {
		if count > 0 && received >= count {
			break
		}

		dgCh := make(chan *driver.Datagram)
		errCh := make(chan error)
		go func() {
			dg, err := d.RecvFrom()
			if err != nil {
				errCh <- err
				return
			}
			dgCh <- dg
		}()

		select {
		case dg := <-dgCh:
			if dg.DstPort == port {
				received++
				msg := map[string]interface{}{
					"src_addr": dg.SrcAddr.String(),
					"src_port": dg.SrcPort,
					"data":     string(dg.Data),
					"bytes":    len(dg.Data),
				}
				messages = append(messages, msg)

				if jsonOutput {
					if count > 0 && received >= count {
						break // will exit loop and print all
					}
					// Stream each message as NDJSON for unbounded
					if count == 0 {
						b, _ := json.Marshal(msg)
						fmt.Println(string(b))
					}
				} else {
					fmt.Printf("[%s:%d] %s\n", dg.SrcAddr, dg.SrcPort, string(dg.Data))
				}
			}
		case err := <-errCh:
			fatalCode("connection_failed", "recv: %v", err)
		case <-deadline:
			if jsonOutput && count > 0 {
				output(map[string]interface{}{
					"messages": messages,
					"timeout":  true,
				})
			} else if !jsonOutput {
				fmt.Fprintln(os.Stderr, "timeout")
			}
			return
		}
	}

	if jsonOutput && count > 0 {
		output(map[string]interface{}{
			"messages": messages,
			"timeout":  false,
		})
	}
}

func cmdBroadcast(args []string) {
	fatalCode("unavailable", "broadcast is not available yet — custom networks are WIP")
}
