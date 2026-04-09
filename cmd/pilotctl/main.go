package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/config"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/dataexchange"
	"github.com/TeoSlayer/pilotprotocol/pkg/driver"
	"github.com/TeoSlayer/pilotprotocol/pkg/eventstream"
	"github.com/TeoSlayer/pilotprotocol/pkg/gateway"
	"github.com/TeoSlayer/pilotprotocol/pkg/logging"
	"github.com/TeoSlayer/pilotprotocol/pkg/policy"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
	"github.com/TeoSlayer/pilotprotocol/pkg/tasksubmit"
)

var version = "dev"

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

// fatalHint is like fatalCode but adds an actionable hint telling the user what to do next.
func fatalHint(code, hint, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if jsonOutput {
		b, _ := json.Marshal(map[string]string{
			"status":  "error",
			"code":    code,
			"message": msg,
			"hint":    hint,
		})
		fmt.Fprintln(os.Stderr, string(b))
	} else {
		fmt.Fprintf(os.Stderr, "error: %s\nhint:  %s\n", msg, hint)
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
	return "34.71.57.205:9000"
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

func getAdminToken() string {
	if v := os.Getenv("PILOT_ADMIN_TOKEN"); v != "" {
		return v
	}
	cfg := loadConfig()
	if s, ok := cfg["admin_token"].(string); ok && s != "" {
		return s
	}
	return ""
}

func requireAdminToken() string {
	token := getAdminToken()
	if token == "" {
		fatalHint("auth_required",
			"set PILOT_ADMIN_TOKEN env var or admin_token in ~/.pilot/config.json",
			"admin token required for this operation")
	}
	return token
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
		fatalHint("not_running",
			"start the daemon with: pilotctl daemon start",
			"daemon is not running")
	}
	return d
}

func connectRegistry() *registry.Client {
	addr := getRegistry()
	rc, err := registry.Dial(addr)
	if err != nil {
		fatalHint("connection_failed",
			fmt.Sprintf("check that the registry is running at %s, or set PILOT_REGISTRY", addr),
			"cannot reach registry at %s", addr)
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
	// Try full address (e.g. "0:0000.0000.000B")
	addr, err := protocol.ParseAddr(arg)
	if err == nil {
		return addr, nil
	}
	// Try bare node ID (e.g. "11" → backbone address 0:0000.0000.000B)
	if id, numErr := strconv.ParseUint(arg, 10, 32); numErr == nil {
		return protocol.Addr{Network: 0, Node: uint32(id)}, nil
	}
	// Try hostname resolution
	resolved, _, resolveErr := resolveHostnameToAddr(d, arg)
	if resolveErr != nil {
		return protocol.Addr{}, fmt.Errorf("cannot resolve %q — is the hostname correct and is there mutual trust? (see: pilotctl handshake)", arg)
	}
	if !jsonOutput {
		fmt.Fprintf(os.Stderr, "resolved %q → %s\n", arg, resolved)
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
  pilotctl daemon start [--config <path>] [--registry <addr>] [--beacon <addr>] [--email <addr>] [--webhook <url>] [--trust-auto-approve]
  pilotctl daemon stop
  pilotctl daemon status

Registry commands:
  pilotctl register [listen_addr]
  pilotctl lookup <node_id>
  pilotctl rotate-key <node_id> <email>
  pilotctl set-public
  pilotctl set-private
  pilotctl deregister

Discovery commands:
  pilotctl find <hostname>
  pilotctl set-hostname <hostname>
  pilotctl clear-hostname
  pilotctl set-tags <tag1> [tag2] ...
  pilotctl clear-tags
  pilotctl enable-tasks
  pilotctl disable-tasks

Communication commands:
  pilotctl connect <address|hostname> [port] [--message <msg>] [--timeout <dur>]
  pilotctl send <address|hostname> <port> --data <msg> [--timeout <dur>]
  pilotctl recv <port> [--count <n>] [--timeout <dur>]
  pilotctl send-file <address|hostname> <filepath>
  pilotctl send-message <address|hostname> --data <text> [--type text|json|binary]
  pilotctl subscribe <address|hostname> <topic> [--count <n>] [--timeout <dur>]
  pilotctl publish <address|hostname> <topic> --data <message>

Task commands:
  pilotctl task submit <address|hostname> --task <description>
  pilotctl task accept --id <task_id>
  pilotctl task decline --id <task_id> --justification <reason>
  pilotctl task execute
  pilotctl task send-results --id <task_id> --results <text> | --file <filepath>
  pilotctl task list [--type received|submitted]
  pilotctl task queue

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

Mailbox:
  pilotctl received [--clear]
  pilotctl inbox [--clear]

Service Agents (AI-powered overlay services):
  pilotctl tui                                     Interactive TUI for all service agents
  pilotctl ls                                      List available service agents and config status

  pilotctl scriptorium <command> [body] [--node <address|hostname>]
  pilotctl scriptorium polymarket "from: 2026-04-01T00:00:00Z, to: 2026-04-02T00:00:00Z"
  pilotctl scriptorium stockmarket "from: 2026-04-01"

  pilotctl ai "<query>" [--node <address>] [--timeout <dur>] [--output-file [path]]
  pilotctl clawdit ["<query>"] [--file <openclaw.json>] [--node <address>] [--timeout <dur>] [--output-file [path]]

  Examples:
    pilotctl ai "how do I send a message to another node?"
    pilotctl ai "list all trusted peers as a table" --output-file peers.txt
    pilotctl clawdit
    pilotctl clawdit "check if port 443 is exposed without TLS"
    pilotctl clawdit --file /etc/openclaw/openclaw.json --output-file audit.md

  Config:
    ~/.pilot/scriptorium.yaml  — default node for 'ai' (key: node)
    ~/.pilot/clawdit.yaml      — default node for 'clawdit' (key: node)

Diagnostic commands:
  pilotctl info
  pilotctl health
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
  PILOT_REGISTRY     Registry address (default: 34.71.57.205:9000)
  PILOT_SOCKET       Daemon socket path (default: /tmp/pilot.sock)

Version:
  pilotctl version

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
	case "version":
		fmt.Println(version)
		return

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
			fatalHint("invalid_argument",
				"available: pilotctl daemon start | stop | status",
				"missing subcommand")
		}
		switch cmdArgs[0] {
		case "start":
			cmdDaemonStart(cmdArgs[1:])
		case "stop":
			cmdDaemonStop()
		case "status":
			cmdDaemonStatus(cmdArgs[1:])
		default:
			fatalHint("invalid_argument",
				"available: start, stop, status",
				"unknown daemon subcommand: %s", cmdArgs[0])
		}

	// Gateway
	case "gateway":
		if len(cmdArgs) < 1 {
			fatalHint("invalid_argument",
				"available: pilotctl gateway start | stop | map | unmap | list",
				"missing subcommand")
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
			fatalHint("invalid_argument",
				"available: start, stop, map, unmap, list",
				"unknown gateway subcommand: %s", cmdArgs[0])
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
	case "set-tags":
		cmdSetTags(cmdArgs)
	case "clear-tags":
		cmdClearTags()
	case "enable-tasks":
		cmdEnableTasks()
	case "disable-tasks":
		cmdDisableTasks()
	case "set-webhook":
		cmdSetWebhook(cmdArgs)
	case "clear-webhook":
		cmdClearWebhook()

	// Communication
	case "connect":
		cmdConnect(cmdArgs)
	case "send":
		cmdSend(cmdArgs)
	case "recv":
		cmdRecv(cmdArgs)
	case "send-file":
		cmdSendFile(cmdArgs)
	case "send-message":
		cmdSendMessage(cmdArgs)
	case "task":
		if len(cmdArgs) < 1 {
			fatalHint("invalid_argument",
				"available: pilotctl task submit | accept | decline | execute | send-results | list | queue",
				"missing subcommand")
		}
		switch cmdArgs[0] {
		case "submit":
			cmdTaskSubmit(cmdArgs[1:])
		case "accept":
			cmdTaskAccept(cmdArgs[1:])
		case "decline":
			cmdTaskDecline(cmdArgs[1:])
		case "execute":
			cmdTaskExecute(cmdArgs[1:])
		case "send-results":
			cmdTaskSendResults(cmdArgs[1:])
		case "list":
			cmdTaskList(cmdArgs[1:])
		case "queue":
			cmdTaskQueue(cmdArgs[1:])
		default:
			fatalHint("invalid_argument",
				"available: submit, accept, decline, execute, send-results, list, queue",
				"unknown task subcommand: %s", cmdArgs[0])
		}
	case "subscribe":
		cmdSubscribe(cmdArgs)
	case "publish":
		cmdPublish(cmdArgs)

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

	// Networks
	case "network":
		if len(cmdArgs) < 1 {
			fatalHint("invalid_argument",
				"available: list, join, leave, members, invite, invites, accept, reject, create, delete, rename, promote, demote, kick, role, policy",
				"usage: pilotctl network <subcommand>")
		}
		switch cmdArgs[0] {
		case "list":
			cmdNetworkList()
		case "join":
			cmdNetworkJoin(cmdArgs[1:])
		case "leave":
			cmdNetworkLeave(cmdArgs[1:])
		case "members":
			cmdNetworkMembers(cmdArgs[1:])
		case "invite":
			cmdNetworkInvite(cmdArgs[1:])
		case "invites":
			cmdNetworkInvites()
		case "accept":
			cmdNetworkAccept(cmdArgs[1:])
		case "reject":
			cmdNetworkReject(cmdArgs[1:])
		// Enterprise operations (direct to registry, require admin token)
		case "create":
			cmdNetworkCreate(cmdArgs[1:])
		case "delete":
			cmdNetworkDelete(cmdArgs[1:])
		case "rename":
			cmdNetworkRename(cmdArgs[1:])
		case "promote":
			cmdNetworkPromote(cmdArgs[1:])
		case "demote":
			cmdNetworkDemote(cmdArgs[1:])
		case "kick":
			cmdNetworkKick(cmdArgs[1:])
		case "role":
			cmdNetworkRole(cmdArgs[1:])
		case "policy":
			cmdNetworkPolicy(cmdArgs[1:])
		default:
			fatalHint("invalid_argument",
				"available: list, join, leave, members, invite, invites, accept, reject, create, delete, rename, promote, demote, kick, role, policy",
				"unknown network subcommand: %s", cmdArgs[0])
		}

	// Managed networks
	case "managed":
		if len(cmdArgs) < 1 {
			fatalHint("invalid_argument",
				"available: score, status, rankings, cycle",
				"usage: pilotctl managed <subcommand>")
		}
		switch cmdArgs[0] {
		case "score":
			cmdManagedScore(cmdArgs[1:])
		case "status":
			cmdManagedStatus(cmdArgs[1:])
		case "rankings":
			cmdManagedRankings(cmdArgs[1:])
		case "cycle":
			cmdManagedCycle(cmdArgs[1:])
		default:
			fatalHint("invalid_argument",
				"available: score, status, rankings, cycle",
				"unknown managed subcommand: %s", cmdArgs[0])
		}

	case "member-tags":
		if len(cmdArgs) < 1 {
			fatalHint("invalid_argument",
				"available: set, get",
				"usage: pilotctl member-tags <subcommand>")
		}
		switch cmdArgs[0] {
		case "set":
			cmdMemberTagsSet(cmdArgs[1:])
		case "get":
			cmdMemberTagsGet(cmdArgs[1:])
		default:
			fatalHint("invalid_argument",
				"available: set, get",
				"unknown member-tags subcommand: %s", cmdArgs[0])
		}

	case "policy":
		if len(cmdArgs) < 1 {
			fatalHint("invalid_argument",
				"available: get, set, validate, test",
				"usage: pilotctl policy <subcommand>")
		}
		switch cmdArgs[0] {
		case "get":
			cmdPolicyGet(cmdArgs[1:])
		case "set":
			cmdPolicySet(cmdArgs[1:])
		case "validate":
			cmdPolicyValidate(cmdArgs[1:])
		case "test":
			cmdPolicyTest(cmdArgs[1:])
		default:
			fatalHint("invalid_argument",
				"available: get, set, validate, test",
				"unknown policy subcommand: %s", cmdArgs[0])
		}

	// Enterprise admin commands (direct to registry)
	case "audit":
		cmdAudit(cmdArgs)
	case "provision":
		cmdProvision(cmdArgs)
	case "idp":
		cmdIDP(cmdArgs)
	case "audit-export":
		cmdAuditExport(cmdArgs)
	case "provision-status":
		cmdProvisionStatus()
	case "directory-sync":
		cmdDirectorySync(cmdArgs)
	case "directory-status":
		cmdDirectoryStatus(cmdArgs)

	// Management
	case "connections":
		cmdConnections()
	case "disconnect":
		cmdDisconnect(cmdArgs)

	// Diagnostics
	case "info":
		cmdInfo()
	case "health":
		cmdHealth()
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

	// Mailbox
	case "received":
		cmdReceived(cmdArgs)
	case "inbox":
		cmdInbox(cmdArgs)

	// Scriptorium — pre-configured command wrappers for the responder
	case "scriptorium":
		cmdScriptorium(cmdArgs)

	// Service agent shortcuts
	case "ai":
		cmdAi(cmdArgs)
	case "clawdit":
		cmdClawdit(cmdArgs)
	case "ls":
		cmdLs(cmdArgs)
	case "tui":
		cmdTui(cmdArgs)

	// Internal: forked daemon process
	case "_daemon-run":
		runDaemonInternal(cmdArgs)

	default:
		if jsonOutput {
			fatalHint("invalid_argument",
				"run 'pilotctl context' for the full command list",
				"unknown command: %s", cmd)
		}
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		usage()
	}
}

// ===================== BOOTSTRAP =====================

func cmdInit(args []string) {
	flags, _ := parseFlags(args)

	registryAddr := flagString(flags, "registry", "34.71.57.205:9000")
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
		"version": "1.2",
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
				"args":        []string{"[--config <path>]", "[--registry <addr>]", "[--beacon <addr>]", "[--listen <addr>]", "[--identity <path>]", "[--email <addr>]", "[--hostname <name>]", "[--log-level <level>]", "[--log-format <fmt>]", "[--public]", "[--foreground]", "[--no-encrypt]", "[--socket <path>]", "[--webhook <url>]"},
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
			"set-tags": map[string]interface{}{
				"args":        []string{"<tag1>", "[tag2]", "..."},
				"description": "Set capability tags for this daemon's node (replaces existing tags)",
				"returns":     "node_id, tags",
			},
			"clear-tags": map[string]interface{}{
				"args":        []string{},
				"description": "Clear all tags for this daemon's node",
				"returns":     "node_id, tags",
			},
			"enable-tasks": map[string]interface{}{
				"args":        []string{},
				"description": "Advertise that this node can execute tasks",
				"returns":     "node_id, task_exec",
			},
			"disable-tasks": map[string]interface{}{
				"args":        []string{},
				"description": "Stop advertising task execution capability",
				"returns":     "node_id, task_exec",
			},
			"set-webhook": map[string]interface{}{
				"args":        []string{"<url>"},
				"description": "Set the webhook URL for event notifications (applies immediately if daemon is running)",
				"returns":     "webhook, applied",
			},
			"clear-webhook": map[string]interface{}{
				"args":        []string{},
				"description": "Clear the webhook URL (applies immediately if daemon is running)",
				"returns":     "webhook, applied",
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
				"args":        []string{"<address|hostname>", "<filepath>"},
				"description": "Send a file to a node on port 1001 (data exchange)",
				"returns":     "filename, bytes, destination, ack",
			},
			"send-message": map[string]interface{}{
				"args":        []string{"<address|hostname>", "--data <text>", "[--type text|json|binary]"},
				"description": "Send a typed message via data exchange (port 1001). Default type: text",
				"returns":     "target, type, bytes, ack",
			},
			"subscribe": map[string]interface{}{
				"args":        []string{"<address|hostname>", "<topic>", "[--count <n>]", "[--timeout <dur>]"},
				"description": "Subscribe to event stream topics (port 1002). Use * for all topics. Without --count: streams NDJSON",
				"returns":     "events [{topic, data, bytes}], timeout (bool). Unbounded: NDJSON per line",
			},
			"publish": map[string]interface{}{
				"args":        []string{"<address|hostname>", "<topic>", "--data <message>"},
				"description": "Publish an event to a topic on the target's event stream broker (port 1002)",
				"returns":     "target, topic, bytes",
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
				"args":        []string{"<node_id>", "<email>"},
				"description": "Rotate keypair via email recovery",
				"returns":     "node_id, new public_key",
			},
			"set-public": map[string]interface{}{
				"args":        []string{},
				"description": "Make this node's endpoint publicly visible (routes through daemon)",
				"returns":     "status",
			},
			"set-private": map[string]interface{}{
				"args":        []string{},
				"description": "Hide this node's endpoint (private, default; routes through daemon)",
				"returns":     "status",
			},
			"deregister": map[string]interface{}{
				"args":        []string{},
				"description": "Deregister this node from the registry (routes through daemon)",
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
			"received": map[string]interface{}{
				"args":        []string{"[--clear]"},
				"description": "List files received via data exchange (port 1001). Files saved to ~/.pilot/received/. Use --clear to delete all",
				"returns":     "files [{name, bytes, modified, path}], total, dir",
			},
			"inbox": map[string]interface{}{
				"args":        []string{"[--clear]"},
				"description": "List messages received via data exchange (port 1001). Messages saved to ~/.pilot/inbox/. Use --clear to delete all",
				"returns":     "messages [{type, from, data, received_at}], total, dir",
			},
			"scriptorium": map[string]interface{}{
				"args":        []string{"<command>", "[body]", "[--node <address|hostname>]"},
				"description": "Send a command to a Scriptorium service agent (e.g. stockmarket, polymarket)",
				"returns":     "command, body, node, ack",
			},
			"ai": map[string]interface{}{
				"args":        []string{"<query>", "[--node <address>]", "[--timeout <dur>]", "[--output-file [path]]"},
				"description": "Send a natural-language query to the AI assistant and wait for the reply",
				"returns":     "reply",
			},
			"clawdit": map[string]interface{}{
				"args":        []string{"[query]", "[--file <openclaw.json>]", "[--node <address>]", "[--timeout <dur>]", "[--output-file [path]]"},
				"description": "Run a security audit of an OpenClaw installation",
				"returns":     "reply",
			},
			"ls": map[string]interface{}{
				"args":        []string{},
				"description": "List all available service agents and their configuration status",
				"returns":     "agents [{name, description, usage, config, configured, node}]",
			},
			"tui": map[string]interface{}{
				"args":        []string{},
				"description": "Launch the interactive service-agent TUI (chat with AI, query Scriptorium, run audits)",
				"returns":     "(interactive — no JSON output)",
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
			"PILOT_REGISTRY": "Registry address (default: 34.71.57.205:9000)",
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
			fatalHint("already_exists",
				"stop it first with: pilotctl daemon stop",
				"daemon is already running (pid %d)", pid)
		}
		// Stale PID file — clean up silently
		os.Remove(pidFilePath())
	}

	// Clean up stale socket
	socketPath := flagString(flags, "socket", "")
	if socketPath == "" {
		socketPath = getSocket()
	}
	if _, err := os.Stat(socketPath); err == nil {
		// Try to connect — if it works, daemon is running
		d, err := driver.Connect(socketPath)
		if err == nil {
			d.Close()
			fatalHint("already_exists",
				"stop it first with: pilotctl daemon stop",
				"daemon is already running (socket %s is active)", socketPath)
		}
		// Stale socket — clean up silently
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
		identityPath = configDir() + "/identity.json"
	}
	email := flagString(flags, "email", "")
	owner := flagString(flags, "owner", "")
	if email == "" && owner != "" {
		email = owner // backward compat: -owner as fallback for -email
	}
	if email == "" {
		if e, ok := cfg["email"].(string); ok {
			email = e
		}
	}
	configFile := flagString(flags, "config", "")
	logLevel := flagString(flags, "log-level", "info")
	logFormat := flagString(flags, "log-format", "text")
	public := flagBool(flags, "public")
	webhookURL := flagString(flags, "webhook", "")
	if webhookURL == "" {
		if w, ok := cfg["webhook"].(string); ok {
			webhookURL = w
		}
	}
	adminToken := flagString(flags, "admin-token", "")
	if adminToken == "" {
		if a, ok := cfg["admin_token"].(string); ok {
			adminToken = a
		}
	}
	networks := flagString(flags, "networks", "")
	if networks == "" {
		if n, ok := cfg["networks"].(string); ok {
			networks = n
		}
	}
	trustAutoApprove := flagBool(flags, "trust-auto-approve")

	// If --foreground, run in-process
	if flagBool(flags, "foreground") {
		runDaemonForeground(configFile, registryAddr, beaconAddr, listenAddr,
			socketPath, encrypt, identityPath, email, hostname, logLevel, logFormat, public, webhookURL,
			adminToken, networks, trustAutoApprove)
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
	if email != "" {
		daemonArgs = append(daemonArgs, "--email", email)
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
	if webhookURL != "" {
		daemonArgs = append(daemonArgs, "--webhook", webhookURL)
	}
	if adminToken != "" {
		daemonArgs = append(daemonArgs, "--admin-token", adminToken)
	}
	if networks != "" {
		daemonArgs = append(daemonArgs, "--networks", networks)
	}
	if trustAutoApprove {
		daemonArgs = append(daemonArgs, "--trust-auto-approve")
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

	if !jsonOutput {
		fmt.Fprintf(os.Stderr, "starting daemon (pid %d)...", pid)
	}

	// Wait for daemon to become ready (socket appears and responds)
	deadline := time.Now().Add(15 * time.Second)
	dots := 0
	for time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
		dots++
		if !jsonOutput && dots%5 == 0 { // every second
			fmt.Fprint(os.Stderr, ".")
		}
		d, err := driver.Connect(socketPath)
		if err != nil {
			continue
		}
		info, err := d.Info()
		d.Close()
		if err != nil {
			continue
		}
		if !jsonOutput {
			fmt.Fprintln(os.Stderr) // end the dots line
		}
		// Daemon is ready — show a friendly summary
		nodeID := int(info["node_id"].(float64))
		address := info["address"]
		hn, _ := info["hostname"].(string)
		if jsonOutput {
			outputOK(map[string]interface{}{
				"pid":      pid,
				"node_id":  nodeID,
				"address":  address,
				"hostname": hn,
				"socket":   socketPath,
				"log_file": logFilePath(),
			})
		} else {
			fmt.Printf("Daemon running (pid %d)\n", pid)
			fmt.Printf("  Address:  %s\n", address)
			if hn != "" {
				fmt.Printf("  Hostname: %s\n", hn)
			}
			fmt.Printf("  Socket:   %s\n", socketPath)
			fmt.Printf("  Logs:     %s\n", logFilePath())
		}
		return
	}

	if !jsonOutput {
		fmt.Fprintln(os.Stderr) // end the dots line
	}

	fatalHint("timeout",
		fmt.Sprintf("check logs: tail -f %s", logFilePath()),
		"daemon started (pid %d) but did not become ready within 15s", pid)
}

func cmdDaemonStop() {
	pid := readPID()
	if pid <= 0 {
		// Try socket
		d, err := driver.Connect(getSocket())
		if err != nil {
			fatalCode("not_running", "daemon is not running")
		}
		d.Close()
		fatalHint("not_running",
			fmt.Sprintf("find and kill the process manually: lsof -U | grep %s", getSocket()),
			"daemon socket is active but PID file is missing")
	}

	if !processExists(pid) {
		os.Remove(pidFilePath())
		fatalCode("not_running", "daemon is not running (cleaned up stale state)")
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
	waitDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(waitDeadline) {
		time.Sleep(200 * time.Millisecond)
		if !processExists(pid) {
			os.Remove(pidFilePath())
			if jsonOutput {
				outputOK(map[string]interface{}{"pid": pid})
			} else {
				fmt.Printf("daemon stopped (pid %d)\n", pid)
			}
			return
		}
	}

	// Force kill
	proc.Signal(syscall.SIGKILL)
	os.Remove(pidFilePath())
	if jsonOutput {
		outputOK(map[string]interface{}{"pid": pid, "forced": true})
	} else {
		fmt.Printf("daemon force-stopped (pid %d)\n", pid)
	}
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
		if jsonOutput {
			output(result)
		} else {
			fmt.Println("Daemon: stopped")
			fmt.Printf("  start with: pilotctl daemon start\n")
		}
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

	registryAddr := flagString(flags, "registry", "34.71.57.205:9000")
	beaconAddr := flagString(flags, "beacon", "127.0.0.1:9001")
	listenAddr := flagString(flags, "listen", ":0")
	socketPath := flagString(flags, "socket", defaultSocket)
	identityPath := flagString(flags, "identity", "")
	email := flagString(flags, "email", "")
	owner := flagString(flags, "owner", "")
	if email == "" && owner != "" {
		email = owner
	}
	hostname := flagString(flags, "hostname", "")
	logLevel := flagString(flags, "log-level", "info")
	logFormat := flagString(flags, "log-format", "text")
	configFile := flagString(flags, "config", "")
	encrypt := !flagBool(flags, "no-encrypt")
	public := flagBool(flags, "public")
	webhookURL := flagString(flags, "webhook", "")
	adminToken := flagString(flags, "admin-token", "")
	networks := flagString(flags, "networks", "")
	trustAutoApprove := flagBool(flags, "trust-auto-approve")

	runDaemonForeground(configFile, registryAddr, beaconAddr, listenAddr,
		socketPath, encrypt, identityPath, email, hostname, logLevel, logFormat, public, webhookURL,
		adminToken, networks, trustAutoApprove)
}

func runDaemonForeground(configFile, registryAddr, beaconAddr, listenAddr,
	socketPath string, encrypt bool, identityPath, email, hostname,
	logLevel, logFormat string, public bool, webhookURL string,
	adminToken, networks string, trustAutoApprove bool) {

	if configFile != "" {
		cfg, err := config.Load(configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load config: %v\n", err)
			os.Exit(1)
		}
		// Apply config values as defaults (CLI flags override)
		if registryAddr == "34.71.57.205:9000" {
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
		RegistryAddr:     registryAddr,
		BeaconAddr:       beaconAddr,
		ListenAddr:       listenAddr,
		SocketPath:       socketPath,
		Encrypt:          encrypt,
		IdentityPath:     identityPath,
		Email:            email,
		Public:           public,
		Hostname:         hostname,
		WebhookURL:       webhookURL,
		AdminToken:       adminToken,
		Networks:         pilotctlParseNetworkIDs(networks),
		TrustAutoApprove: trustAutoApprove,
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

// pilotctlParseNetworkIDs parses a comma-separated string of network IDs into a uint16 slice.
func pilotctlParseNetworkIDs(s string) []uint16 {
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
			slog.Warn("invalid network ID", "value", p, "error", err)
			continue
		}
		ids = append(ids, uint16(n))
	}
	return ids
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
		fatalHint("already_exists",
			"stop it first with: pilotctl gateway stop",
			"gateway is already running (pid %d)", pid)
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
		fatalCode("not_running", "gateway is not running")
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
		fatalHint("not_running",
			"start with: pilotctl gateway start",
			"gateway is not running")
	}

	gw, err := gateway.New(gateway.Config{
		SocketPath: getSocket(),
	})
	if err != nil {
		fatalCode("internal", "create gateway: %v", err)
	}
	if err := gw.Unmap(localIP); err != nil {
		fatalCode("not_found", "no mapping for %s", localIP)
	}
	outputOK(map[string]interface{}{
		"unmapped": localIP,
	})
}

func cmdGatewayList() {
	pid := readGatewayPID()
	if pid <= 0 || !processExists(pid) {
		fatalHint("not_running",
			"start with: pilotctl gateway start [--ports <list>] [<pilot-addr>...]",
			"gateway is not running")
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
		fatalCode("invalid_argument", "usage: pilotctl rotate-key <node_id> <email>")
	}
	nodeID := parseNodeID(args[0])
	email := args[1]
	rc := connectRegistry()
	defer rc.Close()
	resp, err := rc.RotateKey(nodeID, "", email)
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

func cmdEnableTasks() {
	d := connectDriver()
	defer d.Close()
	resp, err := d.SetTaskExec(true)
	if err != nil {
		fatalCode("connection_failed", "enable-tasks: %v", err)
	}
	output(resp)
}

func cmdDisableTasks() {
	d := connectDriver()
	defer d.Close()
	resp, err := d.SetTaskExec(false)
	if err != nil {
		fatalCode("connection_failed", "disable-tasks: %v", err)
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
		fatalHint("not_found",
			fmt.Sprintf("establish trust first: pilotctl handshake %s \"reason\"", hostname),
			"cannot find %q — hostname not found or no mutual trust", hostname)
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

	// Persist to config.json so hostname survives daemon restart
	cfg := loadConfig()
	if hostname != "" {
		cfg["hostname"] = hostname
	} else {
		delete(cfg, "hostname")
	}
	saveConfig(cfg)

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

	// Persist to config.json so hostname stays cleared on daemon restart
	cfg := loadConfig()
	delete(cfg, "hostname")
	saveConfig(cfg)

	if jsonOutput {
		outputOK(map[string]interface{}{
			"hostname": "",
		})
	} else {
		fmt.Printf("hostname cleared\n")
	}
}

func cmdSetWebhook(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl set-webhook <url>")
	}
	url := args[0]
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		fatalCode("invalid_argument", "webhook URL must start with http:// or https://")
	}

	// Persist to config so it survives daemon restart
	cfg := loadConfig()
	cfg["webhook"] = url
	if err := saveConfig(cfg); err != nil {
		fatalCode("internal", "save config: %v", err)
	}

	// Apply to running daemon (best-effort — daemon may not be running)
	applied := false
	d, err := driver.Connect(getSocket())
	if err == nil {
		_, err = d.SetWebhook(url)
		d.Close()
		if err == nil {
			applied = true
		}
	}

	if jsonOutput {
		outputOK(map[string]interface{}{
			"webhook": url,
			"applied": applied,
		})
	} else {
		fmt.Printf("webhook set: %s\n", url)
		if applied {
			fmt.Printf("applied to running daemon\n")
		} else {
			fmt.Printf("will take effect on next daemon start\n")
		}
	}
}

func cmdClearWebhook() {
	cfg := loadConfig()
	delete(cfg, "webhook")
	if err := saveConfig(cfg); err != nil {
		fatalCode("internal", "save config: %v", err)
	}

	// Apply to running daemon (best-effort)
	applied := false
	d, err := driver.Connect(getSocket())
	if err == nil {
		_, err = d.SetWebhook("")
		d.Close()
		if err == nil {
			applied = true
		}
	}

	if jsonOutput {
		outputOK(map[string]interface{}{
			"webhook": "",
			"applied": applied,
		})
	} else {
		fmt.Printf("webhook cleared\n")
		if applied {
			fmt.Printf("applied to running daemon\n")
		} else {
			fmt.Printf("will take effect on next daemon start\n")
		}
	}
}

func cmdSetTags(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl set-tags <tag1> [tag2] ...")
	}
	if len(args) > 3 {
		fatalCode("invalid_argument", "set-tags: maximum 3 tags allowed, got %d", len(args))
	}
	d := connectDriver()
	defer d.Close()

	result, err := d.SetTags(args)
	if err != nil {
		fatalCode("connection_failed", "set-tags: %v", err)
	}

	if jsonOutput {
		outputOK(map[string]interface{}{
			"node_id": result["node_id"],
			"tags":    result["tags"],
		})
	} else {
		tags := "none"
		if t, ok := result["tags"].([]interface{}); ok && len(t) > 0 {
			parts := make([]string, len(t))
			for i, v := range t {
				parts[i] = fmt.Sprintf("#%s", v)
			}
			tags = strings.Join(parts, " ")
		}
		fmt.Printf("tags set: %s\n", tags)
	}
}

func cmdClearTags() {
	d := connectDriver()
	defer d.Close()

	_, err := d.SetTags([]string{})
	if err != nil {
		fatalCode("connection_failed", "clear-tags: %v", err)
	}

	if jsonOutput {
		outputOK(map[string]interface{}{
			"tags": []string{},
		})
	} else {
		fmt.Printf("tags cleared\n")
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
		p, err := strconv.ParseUint(pos[1], 10, 16)
		if err != nil {
			fatalCode("invalid_argument", "invalid port %q: %v", pos[1], err)
		}
		port = uint16(p)
	}

	message := flagString(flags, "message", "")
	timeout := flagDuration(flags, "timeout", 30*time.Second)

	// --message mode: send one message, read one response, exit
	if message != "" {
		conn, err := d.DialAddr(target, port)
		if err != nil {
			fatalHint("connection_failed",
				fmt.Sprintf("check that %s is reachable: pilotctl ping %s", target, target),
				"cannot connect to %s port %d", target, port)
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
			response := ""
			if n > 0 {
				response = string(buf[:n])
			}
			if readErr != nil && response == "" && !errors.Is(readErr, io.EOF) {
				fatalCode("connection_failed", "read: %v", readErr)
			}
			if jsonOutput {
				output(map[string]interface{}{
					"target":   target.String(),
					"port":     port,
					"sent":     message,
					"response": response,
				})
			} else if response != "" {
				fmt.Println(response)
			} else {
				fmt.Fprintf(os.Stderr, "sent %d bytes (no response)\n", len(message))
			}
		case <-time.After(timeout):
			fatalHint("timeout",
				"increase with --timeout, or check if the target is listening on that port",
				"no response within %s", timeout)
		}
		return
	}

	// Pipe mode: read all of stdin, send it, read response
	stat, _ := os.Stdin.Stat()
	if stat.Mode()&os.ModeCharDevice != 0 {
		// stdin is a terminal — require --message
		fatalHint("invalid_argument",
			"use --message to send a single message, or pipe data via stdin",
			"--message is required (interactive mode not supported)")
	}

	// Read all piped stdin
	var stdinData []byte
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		if len(stdinData) > 0 {
			stdinData = append(stdinData, '\n')
		}
		stdinData = append(stdinData, scanner.Bytes()...)
	}
	if len(stdinData) == 0 {
		fatalCode("invalid_argument", "no data on stdin — use --message or pipe data")
	}

	conn, err := d.DialAddr(target, port)
	if err != nil {
		fatalHint("connection_failed",
			fmt.Sprintf("check that %s is reachable: pilotctl ping %s", target, target),
			"cannot connect to %s port %d", target, port)
	}
	defer conn.Close()

	if _, err := conn.Write(stdinData); err != nil {
		fatalCode("connection_failed", "write failed: %v", err)
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
		response := ""
		if n > 0 {
			response = string(buf[:n])
		}
		if readErr != nil && response == "" && !errors.Is(readErr, io.EOF) {
			fatalCode("connection_failed", "read failed: %v", readErr)
		}
		if jsonOutput {
			output(map[string]interface{}{
				"target":   target.String(),
				"port":     port,
				"sent":     string(stdinData),
				"response": response,
			})
		} else if response != "" {
			fmt.Println(response)
		} else {
			fmt.Fprintf(os.Stderr, "sent %d bytes (no response)\n", len(stdinData))
		}
	case <-time.After(timeout):
		fatalHint("timeout",
			"increase with --timeout, or check if the target is listening on that port",
			"no response within %s", timeout)
	}
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
	p, err := strconv.ParseUint(pos[1], 10, 16)
	if err != nil {
		fatalCode("invalid_argument", "invalid port %q: %v", pos[1], err)
	}
	port := uint16(p)

	data := flagString(flags, "data", "")
	if data == "" {
		fatalCode("invalid_argument", "--data is required")
	}
	timeout := flagDuration(flags, "timeout", 30*time.Second)

	conn, err := d.DialAddr(target, port)
	if err != nil {
		fatalHint("connection_failed",
			fmt.Sprintf("check that %s is reachable: pilotctl ping %s", target, target),
			"cannot connect to %s port %d", target, port)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte(data)); err != nil {
		fatalCode("connection_failed", "write failed: %v", err)
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
		response := ""
		if n > 0 {
			response = string(buf[:n])
		}
		if readErr != nil && response == "" && !errors.Is(readErr, io.EOF) {
			fatalCode("connection_failed", "read failed: %v", readErr)
		}
		if jsonOutput {
			output(map[string]interface{}{
				"target":   target.String(),
				"port":     port,
				"sent":     data,
				"response": response,
			})
		} else if response != "" {
			fmt.Println(response)
		} else {
			fmt.Fprintf(os.Stderr, "sent %d bytes (no response)\n", len(data))
		}
	case <-time.After(timeout):
		fatalHint("timeout",
			fmt.Sprintf("increase with --timeout, or check peer: pilotctl ping %s", target),
			"no response within %s", timeout)
	}
}

func cmdRecv(args []string) {
	flags, pos := parseFlags(args)
	if len(pos) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl recv <port> [--count <n>] [--timeout <dur>]")
	}

	p, err := strconv.ParseUint(pos[0], 10, 16)
	if err != nil {
		fatalCode("invalid_argument", "invalid port %q: %v", pos[0], err)
	}
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
		fatalCode("invalid_argument", "usage: pilotctl send-file <address|hostname> <filepath>")
	}

	d := connectDriver()
	defer d.Close()

	target, err := parseAddrOrHostname(d, args[0])
	if err != nil {
		fatalCode("invalid_argument", "%v", err)
	}

	filePath := args[1]
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			fatalCode("not_found", "file not found: %s", filePath)
		}
		if os.IsPermission(err) {
			fatalCode("internal", "permission denied: %s", filePath)
		}
		fatalCode("internal", "read file: %v", err)
	}

	filename := filepath.Base(filePath)

	client, err := dataexchange.Dial(d, target)
	if err != nil {
		fatalHint("connection_failed",
			fmt.Sprintf("check that %s is reachable: pilotctl ping %s", target, target),
			"cannot connect to %s (data exchange port %d)", target, protocol.PortDataExchange)
	}
	defer client.Close()

	if err := client.SendFile(filename, data); err != nil {
		fatalCode("connection_failed", "send failed: %v", err)
	}

	// Read ACK
	ack, err := client.Recv()
	if err != nil {
		// ACK is best-effort; file was sent successfully
		slog.Debug("send-file ACK read failed", "err", err)
	}

	result := map[string]interface{}{
		"filename":    filename,
		"bytes":       len(data),
		"destination": target.String(),
	}
	if ack != nil {
		result["ack"] = string(ack.Payload)
	}
	outputOK(result)
}

func cmdSendMessage(args []string) {
	flags, pos := parseFlags(args)
	if len(pos) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl send-message <address|hostname> --data <text> [--type text|json|binary]")
	}

	d := connectDriver()
	defer d.Close()

	target, err := parseAddrOrHostname(d, pos[0])
	if err != nil {
		fatalCode("not_found", "%v", err)
	}

	data := flagString(flags, "data", "")
	if data == "" {
		fatalCode("invalid_argument", "--data is required")
	}
	msgType := flagString(flags, "type", "text")

	client, err := dataexchange.Dial(d, target)
	if err != nil {
		fatalHint("connection_failed",
			fmt.Sprintf("check that %s is reachable: pilotctl ping %s", target, target),
			"cannot connect to %s (data exchange port %d)", target, protocol.PortDataExchange)
	}
	defer client.Close()

	switch msgType {
	case "text":
		err = client.SendText(data)
	case "json":
		err = client.SendJSON([]byte(data))
	case "binary":
		err = client.SendBinary([]byte(data))
	default:
		fatalCode("invalid_argument", "unknown type %q (use text, json, or binary)", msgType)
	}
	if err != nil {
		fatalCode("connection_failed", "send: %v", err)
	}

	// Read ACK
	ack, err := client.Recv()
	if err != nil {
		slog.Debug("send-message ACK read failed", "err", err)
	}

	result := map[string]interface{}{
		"target": target.String(),
		"type":   msgType,
		"bytes":  len(data),
	}
	if ack != nil {
		result["ack"] = string(ack.Payload)
	}
	outputOK(result)
}

// ===================== TASK SUBCOMMANDS =====================

func cmdTaskSubmit(args []string) {
	flags, pos := parseFlags(args)
	if len(pos) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl task submit <address|hostname> --task <description>")
	}

	d := connectDriver()
	defer d.Close()

	target, err := parseAddrOrHostname(d, pos[0])
	if err != nil {
		fatalCode("not_found", "%v", err)
	}

	taskDesc := flagString(flags, "task", "")
	if taskDesc == "" {
		fatalCode("invalid_argument", "--task is required")
	}

	client, err := tasksubmit.Dial(d, target)
	if err != nil {
		fatalHint("connection_failed",
			fmt.Sprintf("check that %s is reachable: pilotctl ping %s", target, target),
			"cannot connect to %s (task submit port %d)", target, protocol.PortTaskSubmit)
	}
	defer client.Close()

	resp, err := client.SubmitTask(taskDesc, target.String())
	if err != nil {
		fatalCode("connection_failed", "submit: %v", err)
	}

	// Save task file locally (submitted/)
	if resp.Status == tasksubmit.StatusAccepted {
		info, _ := d.Info()
		localAddr := ""
		if addr, ok := info["address"].(string); ok {
			localAddr = addr
		}
		tf := tasksubmit.NewTaskFile(resp.TaskID, taskDesc, localAddr, target.String())
		if err := daemon.SaveTaskFile(tf, true); err != nil {
			slog.Warn("failed to save submitted task file", "error", err)
		}
	}

	result := map[string]interface{}{
		"target":   target.String(),
		"task_id":  resp.TaskID,
		"task":     taskDesc,
		"status":   resp.Status,
		"message":  resp.Message,
		"accepted": resp.Status == tasksubmit.StatusAccepted,
	}

	outputOK(result)
}

func cmdTaskAccept(args []string) {
	flags, _ := parseFlags(args)

	taskID := flagString(flags, "id", "")
	if taskID == "" {
		fatalCode("invalid_argument", "--id is required")
	}

	// Load task from received/
	tf, err := daemon.LoadTaskFile(taskID)
	if err != nil {
		fatalHint("not_found",
			"check pilotctl task list --type received",
			"task not found: %s", taskID)
	}

	if tf.Status != tasksubmit.TaskStatusNew {
		fatalCode("invalid_state", "task %s is already %s", taskID, tf.Status)
	}

	// Check if task has expired for acceptance (1 minute timeout)
	if tf.IsExpiredForAccept() {
		fatalCode("expired", "task %s has expired (accept deadline was 1 minute after creation)", taskID)
	}

	// Update status to ACCEPTED with time_idle calculation
	if err := daemon.UpdateTaskFileWithTimes(taskID, tasksubmit.TaskStatusAccepted, "Task accepted", "accept", false, ""); err != nil {
		fatalCode("internal_error", "failed to update task status: %v", err)
	}

	// Send status update to submitter
	d := connectDriver()
	defer d.Close()

	fromAddr, err := protocol.ParseAddr(tf.From)
	if err != nil {
		fatalCode("invalid_argument", "invalid from address: %v", err)
	}

	client, err := tasksubmit.Dial(d, fromAddr)
	if err != nil {
		// Still accept locally even if we can't notify submitter
		slog.Warn("could not notify submitter", "error", err)
		outputOK(map[string]interface{}{
			"task_id": taskID,
			"status":  tasksubmit.TaskStatusAccepted,
			"message": "Task accepted (submitter notification failed)",
		})
		return
	}
	defer client.Close()

	if err := client.SendStatusUpdate(taskID, tasksubmit.TaskStatusAccepted, "Task accepted"); err != nil {
		slog.Warn("could not send status update", "error", err)
	}

	outputOK(map[string]interface{}{
		"task_id": taskID,
		"status":  tasksubmit.TaskStatusAccepted,
		"message": "Task accepted",
	})
}

func cmdTaskDecline(args []string) {
	flags, _ := parseFlags(args)

	taskID := flagString(flags, "id", "")
	if taskID == "" {
		fatalCode("invalid_argument", "--id is required")
	}

	justification := flagString(flags, "justification", "")
	if justification == "" {
		fatalCode("invalid_argument", "--justification is required")
	}

	// Load task from received/
	tf, err := daemon.LoadTaskFile(taskID)
	if err != nil {
		fatalHint("not_found",
			"check pilotctl task list --type received",
			"task not found: %s", taskID)
	}

	if tf.Status != tasksubmit.TaskStatusNew {
		fatalCode("invalid_state", "task %s is already %s", taskID, tf.Status)
	}

	// Update status to DECLINED with time_idle calculation
	if err := daemon.UpdateTaskFileWithTimes(taskID, tasksubmit.TaskStatusDeclined, justification, "decline", false, ""); err != nil {
		fatalCode("internal_error", "failed to update task status: %v", err)
	}

	// Remove from queue if present (shouldn't be, but just in case)
	daemon.RemoveFromQueue(taskID)

	// Send status update to submitter
	d := connectDriver()
	defer d.Close()

	fromAddr, err := protocol.ParseAddr(tf.From)
	if err != nil {
		fatalCode("invalid_argument", "invalid from address: %v", err)
	}

	client, err := tasksubmit.Dial(d, fromAddr)
	if err != nil {
		// Still decline locally even if we can't notify submitter
		slog.Warn("could not notify submitter", "error", err)
		outputOK(map[string]interface{}{
			"task_id":       taskID,
			"status":        tasksubmit.TaskStatusDeclined,
			"justification": justification,
			"message":       "Task declined (submitter notification failed)",
		})
		return
	}
	defer client.Close()

	if err := client.SendStatusUpdate(taskID, tasksubmit.TaskStatusDeclined, justification); err != nil {
		slog.Warn("could not send status update", "error", err)
	}

	outputOK(map[string]interface{}{
		"task_id":       taskID,
		"status":        tasksubmit.TaskStatusDeclined,
		"justification": justification,
		"message":       "Task declined",
	})
}

func cmdTaskExecute(args []string) {
	// Get first ACCEPTED task from received/ and mark as EXECUTING
	// This should be the task at the head of the queue
	tasksDir, err := getTasksDir()
	if err != nil {
		fatalCode("internal_error", "failed to get tasks directory: %v", err)
	}

	receivedDir := filepath.Join(tasksDir, "received")
	entries, err := os.ReadDir(receivedDir)
	if err != nil {
		if os.IsNotExist(err) {
			fatalCode("not_found", "no received tasks found")
		}
		fatalCode("internal_error", "failed to read tasks directory: %v", err)
	}

	var taskToExecute *tasksubmit.TaskFile
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(receivedDir, entry.Name()))
		if err != nil {
			continue
		}
		tf, err := tasksubmit.UnmarshalTaskFile(data)
		if err != nil {
			continue
		}
		if tf.Status == tasksubmit.TaskStatusAccepted {
			taskToExecute = tf
			break
		}
	}

	if taskToExecute == nil {
		fatalCode("not_found", "no accepted tasks to execute")
	}

	// Get staged time from queue before removing
	stagedAt := daemon.GetQueueStagedAt(taskToExecute.TaskID)

	// Remove task from queue since we're executing it
	daemon.RemoveFromQueue(taskToExecute.TaskID)

	// Update status to EXECUTING with time_staged calculation
	if err := daemon.UpdateTaskFileWithTimes(taskToExecute.TaskID, tasksubmit.TaskStatusExecuting, "Task execution started", "execute", false, stagedAt); err != nil {
		fatalCode("internal_error", "failed to update task status: %v", err)
	}

	// Send status update to submitter
	d := connectDriver()
	defer d.Close()

	fromAddr, err := protocol.ParseAddr(taskToExecute.From)
	if err == nil {
		client, err := tasksubmit.Dial(d, fromAddr)
		if err == nil {
			_ = client.SendStatusUpdate(taskToExecute.TaskID, tasksubmit.TaskStatusExecuting, "Task execution started")
			client.Close()
		}
	}

	outputOK(map[string]interface{}{
		"task_id":          taskToExecute.TaskID,
		"task_description": taskToExecute.TaskDescription,
		"status":           tasksubmit.TaskStatusExecuting,
		"from":             taskToExecute.From,
	})
}

func cmdTaskSendResults(args []string) {
	flags, _ := parseFlags(args)

	taskID := flagString(flags, "id", "")
	if taskID == "" {
		fatalCode("invalid_argument", "--id is required")
	}

	results := flagString(flags, "results", "")
	filePath := flagString(flags, "file", "")

	if results == "" && filePath == "" {
		fatalCode("invalid_argument", "either --results or --file is required")
	}

	// Load task from received/ to verify it exists and get submitter address
	tf, err := daemon.LoadTaskFile(taskID)
	if err != nil {
		fatalHint("not_found",
			"check pilotctl task list --type received",
			"task not found: %s", taskID)
	}

	if tf.Status != tasksubmit.TaskStatusExecuting && tf.Status != tasksubmit.TaskStatusAccepted {
		fatalCode("invalid_state", "task %s cannot receive results (status: %s)", taskID, tf.Status)
	}

	var resultMsg *tasksubmit.TaskResultMessage

	if filePath != "" {
		// Validate file extension
		ext := strings.ToLower(filepath.Ext(filePath))
		if !tasksubmit.AllowedResultExtensions[ext] {
			fatalCode("invalid_argument", "file type %q not allowed for results", ext)
		}
		if tasksubmit.ForbiddenResultExtensions[ext] {
			fatalCode("invalid_argument", "source code files cannot be sent as results")
		}

		// Read file
		data, err := os.ReadFile(filePath)
		if err != nil {
			fatalCode("internal_error", "failed to read file: %v", err)
		}

		resultMsg = &tasksubmit.TaskResultMessage{
			TaskID:      taskID,
			ResultType:  "file",
			Filename:    filepath.Base(filePath),
			FileData:    data,
			CompletedAt: time.Now().UTC().Format(time.RFC3339),
		}
	} else {
		resultMsg = &tasksubmit.TaskResultMessage{
			TaskID:      taskID,
			ResultType:  "text",
			ResultText:  results,
			CompletedAt: time.Now().UTC().Format(time.RFC3339),
		}
	}

	// Update local status to SUCCEEDED with time_cpu calculation
	if err := daemon.UpdateTaskFileWithTimes(taskID, tasksubmit.TaskStatusSucceeded, "Results sent successfully", "complete", false, ""); err != nil {
		slog.Warn("failed to update local task status", "error", err)
	}

	// Reload task file to get computed time values for polo score calculation
	updatedTf, err := daemon.LoadTaskFile(taskID)
	if err == nil {
		// Include time metadata in the result message for polo score calculation
		resultMsg.TimeIdleMs = updatedTf.TimeIdleMs
		resultMsg.TimeStagedMs = updatedTf.TimeStagedMs
		resultMsg.TimeCpuMs = updatedTf.TimeCpuMs
	}

	// Send results to submitter
	d := connectDriver()
	defer d.Close()

	fromAddr, err := protocol.ParseAddr(tf.From)
	if err != nil {
		fatalCode("invalid_argument", "invalid from address: %v", err)
	}

	client, err := tasksubmit.Dial(d, fromAddr)
	if err != nil {
		fatalHint("connection_failed",
			fmt.Sprintf("check that %s is reachable", tf.From),
			"cannot connect to submitter %s", tf.From)
	}
	defer client.Close()

	if err := client.SendResults(resultMsg); err != nil {
		fatalCode("connection_failed", "failed to send results: %v", err)
	}

	// Also update submitter's copy to SUCCEEDED
	if err := client.SendStatusUpdate(taskID, tasksubmit.TaskStatusSucceeded, "Task completed successfully"); err != nil {
		slog.Warn("could not send status update to submitter", "error", err)
	}

	output := map[string]interface{}{
		"task_id":   taskID,
		"status":    tasksubmit.TaskStatusSucceeded,
		"sent_to":   tf.From,
		"sent_type": resultMsg.ResultType,
	}
	if filePath != "" {
		output["filename"] = filepath.Base(filePath)
		output["file_size"] = len(resultMsg.FileData)
	}

	outputOK(output)
}

func cmdTaskList(args []string) {
	flags, _ := parseFlags(args)
	taskType := flagString(flags, "type", "")

	tasksDir, err := getTasksDir()
	if err != nil {
		fatalCode("internal_error", "failed to get tasks directory: %v", err)
	}

	var tasks []map[string]interface{}

	listTasksInDir := func(dir, category string) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				continue
			}
			tf, err := tasksubmit.UnmarshalTaskFile(data)
			if err != nil {
				continue
			}
			tasks = append(tasks, map[string]interface{}{
				"task_id":     tf.TaskID,
				"description": tf.TaskDescription,
				"status":      tf.Status,
				"from":        tf.From,
				"to":          tf.To,
				"created_at":  tf.CreatedAt,
				"category":    category,
			})
		}
	}

	if taskType == "" || taskType == "received" {
		listTasksInDir(filepath.Join(tasksDir, "received"), "received")
	}
	if taskType == "" || taskType == "submitted" {
		listTasksInDir(filepath.Join(tasksDir, "submitted"), "submitted")
	}

	if len(tasks) == 0 {
		if jsonOutput {
			outputOK(map[string]interface{}{"tasks": []interface{}{}})
		} else {
			fmt.Println("No tasks found")
		}
		return
	}

	if jsonOutput {
		outputOK(map[string]interface{}{"tasks": tasks})
	} else {
		for _, t := range tasks {
			fmt.Printf("[%s] %s (%s) - %s\n  From: %s → To: %s\n",
				t["category"], t["task_id"], t["status"], t["description"], t["from"], t["to"])
		}
	}
}

func cmdTaskQueue(args []string) {
	// Show queued (ACCEPTED) tasks in FIFO order
	tasksDir, err := getTasksDir()
	if err != nil {
		fatalCode("internal_error", "failed to get tasks directory: %v", err)
	}

	receivedDir := filepath.Join(tasksDir, "received")
	entries, err := os.ReadDir(receivedDir)
	if err != nil {
		if os.IsNotExist(err) {
			if jsonOutput {
				outputOK(map[string]interface{}{"queue": []interface{}{}})
			} else {
				fmt.Println("Queue is empty")
			}
			return
		}
		fatalCode("internal_error", "failed to read tasks directory: %v", err)
	}

	var queuedTasks []map[string]interface{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(receivedDir, entry.Name()))
		if err != nil {
			continue
		}
		tf, err := tasksubmit.UnmarshalTaskFile(data)
		if err != nil {
			continue
		}
		if tf.Status == tasksubmit.TaskStatusAccepted {
			queuedTasks = append(queuedTasks, map[string]interface{}{
				"task_id":     tf.TaskID,
				"description": tf.TaskDescription,
				"from":        tf.From,
				"created_at":  tf.CreatedAt,
			})
		}
	}

	if len(queuedTasks) == 0 {
		if jsonOutput {
			outputOK(map[string]interface{}{"queue": []interface{}{}})
		} else {
			fmt.Println("Queue is empty")
		}
		return
	}

	if jsonOutput {
		outputOK(map[string]interface{}{"queue": queuedTasks, "count": len(queuedTasks)})
	} else {
		fmt.Printf("Queued tasks (%d):\n", len(queuedTasks))
		for i, t := range queuedTasks {
			fmt.Printf("  %d. %s: %s\n     From: %s\n", i+1, t["task_id"], t["description"], t["from"])
		}
	}
}

// getTasksDir returns the path to ~/.pilot/tasks directory.
func getTasksDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".pilot", "tasks"), nil
}

func cmdSubscribe(args []string) {
	flags, pos := parseFlags(args)
	if len(pos) < 2 {
		fatalCode("invalid_argument", "usage: pilotctl subscribe <address|hostname> <topic> [--count <n>] [--timeout <dur>]")
	}

	d := connectDriver()
	defer d.Close()

	target, err := parseAddrOrHostname(d, pos[0])
	if err != nil {
		fatalCode("not_found", "%v", err)
	}

	topic := pos[1]
	count := flagInt(flags, "count", 0) // 0 = infinite
	timeout := flagDuration(flags, "timeout", 0)

	client, err := eventstream.Subscribe(d, target, topic)
	if err != nil {
		fatalHint("connection_failed",
			fmt.Sprintf("check that %s is reachable: pilotctl ping %s", target, target),
			"cannot subscribe on %s (event stream port %d)", target, protocol.PortEventStream)
	}
	defer client.Close()

	if !jsonOutput {
		fmt.Fprintf(os.Stderr, "subscribed to %q on %s — waiting for events...\n", topic, target)
	}

	var events []map[string]interface{}
	received := 0

	var deadline <-chan time.Time
	if timeout > 0 {
		deadline = time.After(timeout)
	}

	for {
		if count > 0 && received >= count {
			break
		}

		evtCh := make(chan *eventstream.Event)
		errCh := make(chan error)
		go func() {
			evt, err := client.Recv()
			if err != nil {
				errCh <- err
				return
			}
			evtCh <- evt
		}()

		select {
		case evt := <-evtCh:
			received++
			msg := map[string]interface{}{
				"topic": evt.Topic,
				"data":  string(evt.Payload),
				"bytes": len(evt.Payload),
			}
			events = append(events, msg)

			if jsonOutput {
				if count > 0 && received >= count {
					break // will exit loop and print all
				}
				// Stream each event as NDJSON for unbounded
				if count == 0 {
					b, _ := json.Marshal(msg)
					fmt.Println(string(b))
				}
			} else {
				fmt.Printf("[%s] %s\n", evt.Topic, string(evt.Payload))
			}
		case err := <-errCh:
			if count > 0 && received > 0 {
				// Partial results
				if jsonOutput {
					output(map[string]interface{}{
						"events":  events,
						"timeout": false,
						"error":   err.Error(),
					})
				}
				return
			}
			fatalCode("connection_failed", "recv: %v", err)
		case <-deadline:
			if jsonOutput && count > 0 {
				output(map[string]interface{}{
					"events":  events,
					"timeout": true,
				})
			} else if !jsonOutput {
				fmt.Fprintln(os.Stderr, "timeout")
			}
			return
		}
	}

	if jsonOutput && count > 0 {
		output(map[string]interface{}{
			"events":  events,
			"timeout": false,
		})
	}
}

func cmdPublish(args []string) {
	flags, pos := parseFlags(args)
	if len(pos) < 2 {
		fatalCode("invalid_argument", "usage: pilotctl publish <address|hostname> <topic> --data <message>")
	}

	d := connectDriver()
	defer d.Close()

	target, err := parseAddrOrHostname(d, pos[0])
	if err != nil {
		fatalCode("not_found", "%v", err)
	}

	topic := pos[1]
	data := flagString(flags, "data", "")
	if data == "" {
		fatalCode("invalid_argument", "--data is required")
	}

	// Subscribe first (required by the broker protocol), then publish
	client, err := eventstream.Subscribe(d, target, topic)
	if err != nil {
		fatalHint("connection_failed",
			fmt.Sprintf("check that %s is reachable: pilotctl ping %s", target, target),
			"cannot connect to %s (event stream port %d)", target, protocol.PortEventStream)
	}
	defer client.Close()

	if err := client.Publish(topic, []byte(data)); err != nil {
		fatalCode("connection_failed", "publish failed: %v", err)
	}

	outputOK(map[string]interface{}{
		"target": target.String(),
		"topic":  topic,
		"bytes":  len(data),
	})
}

// ===================== TRUST =====================

func cmdHandshake(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl handshake <node_id|address|hostname> [justification]")
	}
	d := connectDriver()
	defer d.Close()

	var nodeID uint32
	target := args[0]
	if id, err := strconv.ParseUint(target, 10, 32); err == nil {
		nodeID = uint32(id)
	} else if addr, err := protocol.ParseAddr(target); err == nil {
		nodeID = addr.Node
		if !jsonOutput {
			fmt.Fprintf(os.Stderr, "parsed address %s → node %d\n", target, nodeID)
		}
	} else {
		_, resolved, err := resolveHostnameToAddr(d, target)
		if err != nil {
			fatalCode("not_found", "resolve %q: %v", target, err)
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
		status, _ := result["status"].(string)
		if status == "already_trusted" {
			fmt.Printf("already trusted with node %d — ready to communicate\n", nodeID)
		} else {
			fmt.Printf("handshake request sent to node %d\n", nodeID)
			fmt.Printf("  next: node %d must approve — or send a handshake back for auto-approval\n", nodeID)
			fmt.Printf("  check: pilotctl trust\n")
		}
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
		fmt.Printf("trust established with node %d\n", nodeID)
		fmt.Printf("  try: pilotctl ping %d\n", nodeID)
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
		fmt.Println("  requests appear here when another node sends: pilotctl handshake <your-node-id>")
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
		fmt.Println("  establish trust: pilotctl handshake <node_id|hostname> \"reason\"")
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
		fmt.Println("  connect to a peer: pilotctl connect <address|hostname> --message \"hello\"")
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
	if v, ok := info["version"].(string); ok && v != "" {
		fmt.Printf("  Version:     %s\n", v)
	}
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
	if email, ok := info["email"].(string); ok && email != "" {
		fmt.Printf("  Email:       %s\n", email)
	}
	if nets, ok := info["networks"].([]interface{}); ok && len(nets) > 0 {
		fmt.Printf("  Networks:    %d\n", len(nets))
		for _, n := range nets {
			nm, _ := n.(map[string]interface{})
			netID := int(nm["network_id"].(float64))
			addr, _ := nm["address"].(string)
			fmt.Printf("    - network %d: %s\n", netID, addr)
		}
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

func cmdHealth() {
	d := connectDriver()
	defer d.Close()

	health, err := d.Health()
	if err != nil {
		fatalCode("connection_failed", "health: %v", err)
	}

	if jsonOutput {
		output(health)
		return
	}

	uptime := int64(0)
	if v, ok := health["uptime_seconds"].(float64); ok {
		uptime = int64(v)
	}
	hours := uptime / 3600
	mins := (uptime % 3600) / 60
	secs := uptime % 60

	fmt.Printf("Daemon Health\n")
	fmt.Printf("  Status:      %s\n", health["status"])
	fmt.Printf("  Uptime:      %02d:%02d:%02d\n", hours, mins, secs)
	fmt.Printf("  Connections: %d\n", int(health["connections"].(float64)))
	fmt.Printf("  Peers:       %d\n", int(health["peers"].(float64)))
	fmt.Printf("  Bytes Sent:  %s\n", formatBytes(uint64(health["bytes_sent"].(float64))))
	fmt.Printf("  Bytes Recv:  %s\n", formatBytes(uint64(health["bytes_recv"].(float64))))
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
			fmt.Println("  peers appear when you communicate with other nodes")
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
		fatalHint("connection_failed",
			fmt.Sprintf("check that %s is reachable: pilotctl ping %s", target, target),
			"cannot connect to %s echo port", target)
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

	p, err := strconv.ParseUint(pos[0], 10, 16)
	if err != nil {
		fatalCode("invalid_argument", "invalid port %q: %v", pos[0], err)
	}
	port := uint16(p)
	count := flagInt(flags, "count", 0) // 0 = infinite
	timeout := flagDuration(flags, "timeout", 0)

	d := connectDriver()
	defer d.Close()

	if !jsonOutput {
		fmt.Fprintf(os.Stderr, "listening on port %d — waiting for datagrams...\n", port)
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

// ===================== MAILBOX =====================

// cmdReceived lists or clears files received via data exchange (port 1001).
// Files are saved to ~/.pilot/received/ by the daemon's built-in service.
func cmdReceived(args []string) {
	flags, _ := parseFlags(args)

	home, err := os.UserHomeDir()
	if err != nil {
		fatalCode("internal", "cannot determine home directory")
	}
	dir := filepath.Join(home, ".pilot", "received")

	if flagBool(flags, "clear") {
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				fatalCode("not_found", "no received files")
			}
			fatalCode("internal", "read directory: %v", err)
		}
		count := 0
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			os.Remove(filepath.Join(dir, e.Name()))
			count++
		}
		if jsonOutput {
			outputOK(map[string]interface{}{"cleared": count})
		} else {
			fmt.Printf("cleared %d received file(s)\n", count)
		}
		return
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			if jsonOutput {
				output(map[string]interface{}{"files": []interface{}{}, "total": 0})
			} else {
				fmt.Println("no received files")
				fmt.Println("  files appear here when someone sends: pilotctl send-file <your-hostname> <file>")
			}
			return
		}
		fatalCode("internal", "read directory: %v", err)
	}

	var files []map[string]interface{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, map[string]interface{}{
			"name":     e.Name(),
			"bytes":    info.Size(),
			"modified": info.ModTime().Format(time.RFC3339),
			"path":     filepath.Join(dir, e.Name()),
		})
	}

	if jsonOutput {
		output(map[string]interface{}{
			"files": files,
			"total": len(files),
			"dir":   dir,
		})
		return
	}

	if len(files) == 0 {
		fmt.Println("no received files")
		fmt.Println("  files appear here when someone sends: pilotctl send-file <your-hostname> <file>")
		return
	}

	fmt.Printf("Received files (%s):\n\n", dir)
	fmt.Printf("  %-40s  %-10s  %s\n", "NAME", "SIZE", "RECEIVED")
	for _, f := range files {
		fmt.Printf("  %-40s  %-10s  %s\n",
			f["name"], formatBytes(uint64(f["bytes"].(int64))), f["modified"])
	}
	fmt.Printf("\ntotal: %d\n", len(files))
}

// cmdInbox lists or clears messages received via data exchange (port 1001).
// Messages are saved to ~/.pilot/inbox/ by the daemon's built-in service.
func cmdInbox(args []string) {
	flags, _ := parseFlags(args)

	home, err := os.UserHomeDir()
	if err != nil {
		fatalCode("internal", "cannot determine home directory")
	}
	dir := filepath.Join(home, ".pilot", "inbox")

	if flagBool(flags, "clear") {
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				fatalCode("not_found", "inbox is empty")
			}
			fatalCode("internal", "read directory: %v", err)
		}
		count := 0
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			os.Remove(filepath.Join(dir, e.Name()))
			count++
		}
		if jsonOutput {
			outputOK(map[string]interface{}{"cleared": count})
		} else {
			fmt.Printf("cleared %d message(s)\n", count)
		}
		return
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			if jsonOutput {
				output(map[string]interface{}{"messages": []interface{}{}, "total": 0})
			} else {
				fmt.Println("inbox is empty")
				fmt.Println("  messages appear here when someone sends: pilotctl send-message <your-hostname> --data \"hello\"")
			}
			return
		}
		fatalCode("internal", "read directory: %v", err)
	}

	var messages []map[string]interface{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var msg map[string]interface{}
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		messages = append(messages, msg)
	}

	if jsonOutput {
		output(map[string]interface{}{
			"messages": messages,
			"total":    len(messages),
			"dir":      dir,
		})
		return
	}

	if len(messages) == 0 {
		fmt.Println("inbox is empty")
		fmt.Println("  messages appear here when someone sends: pilotctl send-message <your-hostname> --data \"hello\"")
		return
	}

	fmt.Printf("Inbox (%d messages):\n\n", len(messages))
	for _, m := range messages {
		msgType, _ := m["type"].(string)
		from, _ := m["from"].(string)
		ts, _ := m["received_at"].(string)
		data, _ := m["data"].(string)
		preview := data
		if len(preview) > 80 {
			preview = preview[:80] + "..."
		}
		fmt.Printf("  [%s] from %s type=%s\n", ts, from, msgType)
		fmt.Printf("    %s\n", preview)
	}
	fmt.Printf("\nclear with: pilotctl inbox --clear\n")
}

// --- Network commands ---

func cmdNetworkList() {
	d := connectDriver()
	defer d.Close()

	result, err := d.NetworkList()
	if err != nil {
		fatalCode("connection_failed", "network list: %v", err)
	}
	if jsonOutput {
		output(result)
		return
	}
	nets, _ := result["networks"].([]interface{})
	if len(nets) == 0 {
		fmt.Println("no networks")
		return
	}
	fmt.Printf("%-8s %-30s %-10s %s\n", "ID", "NAME", "JOIN RULE", "MEMBERS")
	for _, n := range nets {
		nm, _ := n.(map[string]interface{})
		id := uint16(nm["id"].(float64))
		name, _ := nm["name"].(string)
		rule, _ := nm["join_rule"].(string)
		count := 0
		if members, ok := nm["members"].([]interface{}); ok {
			count = len(members)
		} else if mc, ok := nm["members"].(float64); ok {
			count = int(mc)
		}
		fmt.Printf("%-8d %-30s %-10s %d\n", id, name, rule, count)
	}
}

func cmdNetworkJoin(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl network join <network_id> [--token TOKEN] [--node-id N]")
	}
	netID := parseUint16(args[0], "network_id")
	flags, _ := parseFlags(args[1:])
	token := flagString(flags, "token", "")
	nodeIDStr := flagString(flags, "node-id", "")

	// Admin path: --node-id joins a remote node directly via registry
	if nodeIDStr != "" {
		nodeID := parseNodeID(nodeIDStr)
		adminToken := requireAdminToken()
		rc := connectRegistry()
		defer rc.Close()

		result, err := rc.JoinNetwork(nodeID, netID, token, 0, adminToken)
		if err != nil {
			fatalCode("connection_failed", "network join: %v", err)
		}
		if jsonOutput {
			output(result)
		} else {
			fmt.Printf("joined node %d to network %d\n", nodeID, netID)
		}
		return
	}

	d := connectDriver()
	defer d.Close()

	result, err := d.NetworkJoin(netID, token)
	if err != nil {
		fatalCode("connection_failed", "network join: %v", err)
	}
	if jsonOutput {
		output(result)
	} else {
		fmt.Printf("joined network %d\n", netID)
	}
}

func cmdNetworkLeave(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl network leave <network_id>")
	}
	netID := parseUint16(args[0], "network_id")

	d := connectDriver()
	defer d.Close()

	result, err := d.NetworkLeave(netID)
	if err != nil {
		fatalCode("connection_failed", "network leave: %v", err)
	}
	if jsonOutput {
		output(result)
	} else {
		fmt.Printf("left network %d\n", netID)
	}
}

func cmdNetworkMembers(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl network members <network_id>")
	}
	netID := parseUint16(args[0], "network_id")

	d := connectDriver()
	defer d.Close()

	result, err := d.NetworkMembers(netID)
	if err != nil {
		fatalCode("connection_failed", "network members: %v", err)
	}
	if jsonOutput {
		output(result)
		return
	}
	nodes, _ := result["nodes"].([]interface{})
	if len(nodes) == 0 {
		fmt.Println("no members")
		return
	}
	fmt.Printf("%-12s %-20s %-12s %-10s\n", "NODE ID", "HOSTNAME", "VERSION", "PUBLIC")
	for _, n := range nodes {
		nm, _ := n.(map[string]interface{})
		nodeID := uint32(nm["node_id"].(float64))
		hostname, _ := nm["hostname"].(string)
		ver, _ := nm["version"].(string)
		public := false
		if p, ok := nm["public"].(bool); ok {
			public = p
		}
		vis := "private"
		if public {
			vis = "public"
		}
		if hostname == "" {
			hostname = "-"
		}
		if ver == "" {
			ver = "-"
		}
		fmt.Printf("%-12d %-20s %-12s %-10s\n", nodeID, hostname, ver, vis)
	}
}

func cmdNetworkInvite(args []string) {
	if len(args) < 2 {
		fatalCode("invalid_argument", "usage: pilotctl network invite <network_id> <node_id>")
	}
	netID := parseUint16(args[0], "network_id")
	nodeID := parseNodeID(args[1])

	d := connectDriver()
	defer d.Close()

	result, err := d.NetworkInvite(netID, nodeID)
	if err != nil {
		fatalCode("connection_failed", "network invite: %v", err)
	}
	if jsonOutput {
		output(result)
	} else {
		fmt.Printf("invited node %d to network %d\n", nodeID, netID)
	}
}

func cmdNetworkInvites() {
	d := connectDriver()
	defer d.Close()

	result, err := d.NetworkPollInvites()
	if err != nil {
		fatalCode("connection_failed", "network invites: %v", err)
	}
	if jsonOutput {
		output(result)
		return
	}
	invites, _ := result["invites"].([]interface{})
	if len(invites) == 0 {
		fmt.Println("no pending invites")
		return
	}
	fmt.Printf("%-12s %-12s %s\n", "NETWORK", "INVITER", "TIMESTAMP")
	for _, inv := range invites {
		im, _ := inv.(map[string]interface{})
		netID := uint16(im["network_id"].(float64))
		inviterID := uint32(im["inviter_id"].(float64))
		ts, _ := im["timestamp"].(string)
		fmt.Printf("%-12d %-12d %s\n", netID, inviterID, ts)
	}
	fmt.Println("\naccept: pilotctl network accept <network_id>")
	fmt.Println("reject: pilotctl network reject <network_id>")
}

func cmdNetworkAccept(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl network accept <network_id>")
	}
	netID := parseUint16(args[0], "network_id")

	d := connectDriver()
	defer d.Close()

	result, err := d.NetworkRespondInvite(netID, true)
	if err != nil {
		fatalCode("connection_failed", "network accept: %v", err)
	}
	if jsonOutput {
		output(result)
	} else {
		fmt.Printf("accepted invite to network %d\n", netID)
	}
}

func cmdNetworkReject(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl network reject <network_id>")
	}
	netID := parseUint16(args[0], "network_id")

	d := connectDriver()
	defer d.Close()

	result, err := d.NetworkRespondInvite(netID, false)
	if err != nil {
		fatalCode("connection_failed", "network reject: %v", err)
	}
	if jsonOutput {
		output(result)
	} else {
		fmt.Printf("rejected invite to network %d\n", netID)
	}
}

// --- Enterprise network commands (direct to registry, admin token required) ---

func cmdNetworkCreate(args []string) {
	flags, _ := parseFlags(args)
	name := flagString(flags, "name", "")
	joinRule := flagString(flags, "join-rule", "open")
	token := flagString(flags, "token", "")
	enterprise := flagBool(flags, "enterprise")
	nodeIDStr := flagString(flags, "node-id", "0")
	networkAdminToken := flagString(flags, "network-admin-token", "")
	rulesJSON := flagString(flags, "rules", "")
	rulesFile := flagString(flags, "rules-file", "")

	if name == "" {
		fatalCode("invalid_argument", "usage: pilotctl network create --name <name> [--join-rule open|token|invite] [--token T] [--enterprise] [--node-id N] [--rules '<json>'] [--rules-file path]")
	}

	// Load rules from file if specified
	if rulesFile != "" && rulesJSON == "" {
		data, err := os.ReadFile(rulesFile)
		if err != nil {
			fatalCode("invalid_argument", "cannot read rules file: %v", err)
		}
		rulesJSON = string(data)
	}

	adminToken := requireAdminToken()
	nodeID := parseNodeID(nodeIDStr)

	rc := connectRegistry()
	defer rc.Close()

	var resp map[string]interface{}
	var err error
	if rulesJSON != "" {
		resp, err = rc.CreateManagedNetwork(nodeID, name, joinRule, token, adminToken, enterprise, rulesJSON, networkAdminToken)
	} else if networkAdminToken != "" {
		resp, err = rc.CreateNetwork(nodeID, name, joinRule, token, adminToken, enterprise, networkAdminToken)
	} else {
		resp, err = rc.CreateNetwork(nodeID, name, joinRule, token, adminToken, enterprise)
	}
	if err != nil {
		fatalCode("connection_failed", "network create: %v", err)
	}
	if jsonOutput {
		output(resp)
	} else {
		managed := ""
		if resp["managed"] == true {
			managed = ", managed=true"
		}
		fmt.Printf("created network %v: %s (join_rule=%s, enterprise=%v%s)\n",
			resp["network_id"], name, joinRule, enterprise, managed)
	}
}

func cmdNetworkDelete(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl network delete <network_id>")
	}
	netID := parseUint16(args[0], "network_id")
	adminToken := requireAdminToken()

	rc := connectRegistry()
	defer rc.Close()

	resp, err := rc.DeleteNetwork(netID, adminToken)
	if err != nil {
		fatalCode("connection_failed", "network delete: %v", err)
	}
	if jsonOutput {
		output(resp)
	} else {
		fmt.Printf("deleted network %d\n", netID)
	}
}

func cmdNetworkRename(args []string) {
	if len(args) < 2 {
		fatalCode("invalid_argument", "usage: pilotctl network rename <network_id> <new_name>")
	}
	netID := parseUint16(args[0], "network_id")
	name := args[1]
	adminToken := requireAdminToken()

	rc := connectRegistry()
	defer rc.Close()

	resp, err := rc.RenameNetwork(netID, name, adminToken)
	if err != nil {
		fatalCode("connection_failed", "network rename: %v", err)
	}
	if jsonOutput {
		output(resp)
	} else {
		fmt.Printf("renamed network %d to %q\n", netID, name)
	}
}

func cmdNetworkPromote(args []string) {
	if len(args) < 2 {
		fatalCode("invalid_argument", "usage: pilotctl network promote <network_id> <target_node_id>")
	}
	netID := parseUint16(args[0], "network_id")
	targetNodeID := parseNodeID(args[1])
	adminToken := requireAdminToken()

	rc := connectRegistry()
	defer rc.Close()

	// Use node_id=0 since we're authenticating with admin token, not RBAC
	resp, err := rc.PromoteMember(netID, 0, targetNodeID, adminToken)
	if err != nil {
		fatalCode("connection_failed", "network promote: %v", err)
	}
	if jsonOutput {
		output(resp)
	} else {
		fmt.Printf("promoted node %d to admin in network %d\n", targetNodeID, netID)
	}
}

func cmdNetworkDemote(args []string) {
	if len(args) < 2 {
		fatalCode("invalid_argument", "usage: pilotctl network demote <network_id> <target_node_id>")
	}
	netID := parseUint16(args[0], "network_id")
	targetNodeID := parseNodeID(args[1])
	adminToken := requireAdminToken()

	rc := connectRegistry()
	defer rc.Close()

	resp, err := rc.DemoteMember(netID, 0, targetNodeID, adminToken)
	if err != nil {
		fatalCode("connection_failed", "network demote: %v", err)
	}
	if jsonOutput {
		output(resp)
	} else {
		fmt.Printf("demoted node %d to member in network %d\n", targetNodeID, netID)
	}
}

func cmdNetworkKick(args []string) {
	if len(args) < 2 {
		fatalCode("invalid_argument", "usage: pilotctl network kick <network_id> <target_node_id>")
	}
	netID := parseUint16(args[0], "network_id")
	targetNodeID := parseNodeID(args[1])
	adminToken := requireAdminToken()

	rc := connectRegistry()
	defer rc.Close()

	resp, err := rc.KickMember(netID, 0, targetNodeID, adminToken)
	if err != nil {
		fatalCode("connection_failed", "network kick: %v", err)
	}
	if jsonOutput {
		output(resp)
	} else {
		fmt.Printf("kicked node %d from network %d\n", targetNodeID, netID)
	}
}

func cmdNetworkRole(args []string) {
	if len(args) < 2 {
		fatalCode("invalid_argument", "usage: pilotctl network role <network_id> <node_id>")
	}
	netID := parseUint16(args[0], "network_id")
	nodeID := parseNodeID(args[1])

	rc := connectRegistry()
	defer rc.Close()

	resp, err := rc.GetMemberRole(netID, nodeID)
	if err != nil {
		fatalCode("connection_failed", "network role: %v", err)
	}
	if jsonOutput {
		output(resp)
	} else {
		fmt.Printf("node %d in network %d: role=%v\n", nodeID, netID, resp["role"])
	}
}

func cmdNetworkPolicy(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl network policy <network_id> [--set key=value ...]")
	}
	netID := parseUint16(args[0], "network_id")

	// Check if we're setting or getting
	setArgs := args[1:]
	if len(setArgs) == 0 {
		// GET policy
		rc := connectRegistry()
		defer rc.Close()
		resp, err := rc.GetNetworkPolicy(netID)
		if err != nil {
			fatalCode("connection_failed", "network policy: %v", err)
		}
		output(resp)
		return
	}

	// SET policy
	adminToken := requireAdminToken()
	policy := make(map[string]interface{})
	flags, _ := parseFlags(setArgs)
	if v := flagString(flags, "max-members", ""); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			fatalCode("invalid_argument", "invalid max-members: %v", err)
		}
		policy["max_members"] = float64(n)
	}
	if v := flagString(flags, "description", ""); v != "" {
		policy["description"] = v
	}
	if v := flagString(flags, "allowed-ports", ""); v != "" {
		var ports []interface{}
		for _, p := range strings.Split(v, ",") {
			pv, err := strconv.Atoi(strings.TrimSpace(p))
			if err != nil {
				fatalCode("invalid_argument", "invalid port %q: %v", p, err)
			}
			ports = append(ports, float64(pv))
		}
		policy["allowed_ports"] = ports
	}

	rc := connectRegistry()
	defer rc.Close()
	resp, err := rc.SetNetworkPolicy(netID, policy, adminToken)
	if err != nil {
		fatalCode("connection_failed", "network policy set: %v", err)
	}
	if jsonOutput {
		output(resp)
	} else {
		fmt.Printf("updated policy for network %d\n", netID)
	}
}

func cmdAudit(args []string) {
	adminToken := requireAdminToken()
	flags, _ := parseFlags(args)
	netIDStr := flagString(flags, "network", "0")
	netID := parseUint16(netIDStr, "network_id")

	rc := connectRegistry()
	defer rc.Close()

	resp, err := rc.GetAuditLog(netID, adminToken)
	if err != nil {
		fatalCode("connection_failed", "audit: %v", err)
	}
	if jsonOutput {
		output(resp)
		return
	}
	entries, ok := resp["entries"].([]interface{})
	if !ok || len(entries) == 0 {
		fmt.Println("no audit entries")
		return
	}
	for _, e := range entries {
		entry, ok := e.(map[string]interface{})
		if !ok {
			continue
		}
		ts := entry["timestamp"]
		action := entry["action"]
		nodeID := entry["node_id"]
		netID := entry["network_id"]
		details := entry["details"]

		line := fmt.Sprintf("%-30v  %-30v", ts, action)
		if nodeID != nil && nodeID != float64(0) {
			line += fmt.Sprintf("  node=%v", nodeID)
		}
		if netID != nil && netID != float64(0) {
			line += fmt.Sprintf("  net=%v", netID)
		}
		if details != nil && details != "" {
			line += fmt.Sprintf("  %v", details)
		}
		fmt.Println(line)
	}
}

// --- Provisioning commands ---

func cmdProvision(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl provision <blueprint.json>")
	}
	adminToken := requireAdminToken()

	data, err := os.ReadFile(args[0])
	if err != nil {
		fatalCode("invalid_argument", "read blueprint: %v", err)
	}

	var blueprint map[string]interface{}
	if err := json.Unmarshal(data, &blueprint); err != nil {
		fatalCode("invalid_argument", "parse blueprint: %v", err)
	}

	rc := connectRegistry()
	defer rc.Close()

	resp, err := rc.ProvisionNetwork(blueprint, adminToken)
	if err != nil {
		fatalCode("connection_failed", "provision: %v", err)
	}
	if jsonOutput {
		output(resp)
		return
	}

	fmt.Printf("provisioned network %v (%s)\n", resp["network_id"], resp["name"])
	if actions, ok := resp["actions"].([]interface{}); ok {
		for _, a := range actions {
			fmt.Printf("  - %v\n", a)
		}
	}
}

func cmdIDP(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl idp <get|set> [options]")
	}
	adminToken := requireAdminToken()

	switch args[0] {
	case "get":
		rc := connectRegistry()
		defer rc.Close()
		resp, err := rc.GetIDPConfig(adminToken)
		if err != nil {
			fatalCode("connection_failed", "idp get: %v", err)
		}
		if jsonOutput {
			output(resp)
		} else {
			if resp["configured"] == true {
				fmt.Printf("IdP: %v (%v)\n", resp["idp_type"], resp["url"])
				if v := resp["issuer"]; v != nil && v != "" {
					fmt.Printf("  issuer: %v\n", v)
				}
				if v := resp["tenant_id"]; v != nil && v != "" {
					fmt.Printf("  tenant: %v\n", v)
				}
				if v := resp["client_id"]; v != nil && v != "" {
					fmt.Printf("  client_id: %v\n", v)
				}
			} else {
				fmt.Println("no identity provider configured")
			}
		}

	case "set":
		flags, _ := parseFlags(args[1:])
		idpType := flagString(flags, "type", "")
		url := flagString(flags, "url", "")
		issuer := flagString(flags, "issuer", "")
		clientID := flagString(flags, "client-id", "")
		tenantID := flagString(flags, "tenant-id", "")
		domain := flagString(flags, "domain", "")

		if idpType == "" || url == "" {
			fatalCode("invalid_argument", "usage: pilotctl idp set --type <oidc|saml|entra_id|ldap|webhook> --url <URL> [--issuer URL] [--client-id ID] [--tenant-id ID] [--domain D]")
		}

		rc := connectRegistry()
		defer rc.Close()
		resp, err := rc.SetIDPConfig(idpType, url, issuer, clientID, tenantID, domain, adminToken)
		if err != nil {
			fatalCode("connection_failed", "idp set: %v", err)
		}
		if jsonOutput {
			output(resp)
		} else {
			fmt.Printf("identity provider configured: %s (%s)\n", idpType, resp["status"])
		}

	default:
		fatalCode("invalid_argument", "unknown idp subcommand: %s (use get or set)", args[0])
	}
}

func cmdAuditExport(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl audit-export <get|set|disable> [options]")
	}
	adminToken := requireAdminToken()

	switch args[0] {
	case "get":
		rc := connectRegistry()
		defer rc.Close()
		resp, err := rc.GetAuditExport(adminToken)
		if err != nil {
			fatalCode("connection_failed", "audit-export get: %v", err)
		}
		if jsonOutput {
			output(resp)
		} else {
			if resp["enabled"] == true {
				fmt.Printf("audit export: %v → %v\n", resp["format"], resp["endpoint"])
				if v := resp["exported"]; v != nil {
					fmt.Printf("  exported: %v, dropped: %v\n", v, resp["dropped"])
				}
			} else {
				fmt.Println("audit export not configured")
			}
		}

	case "set":
		flags, _ := parseFlags(args[1:])
		format := flagString(flags, "format", "")
		endpoint := flagString(flags, "endpoint", "")
		token := flagString(flags, "splunk-token", "")
		index := flagString(flags, "index", "")
		source := flagString(flags, "source", "pilot-registry")

		if format == "" || endpoint == "" {
			fatalCode("invalid_argument", "usage: pilotctl audit-export set --format <json|splunk_hec|syslog_cef> --endpoint <URL> [--splunk-token T] [--index I] [--source S]")
		}

		rc := connectRegistry()
		defer rc.Close()
		resp, err := rc.SetAuditExport(format, endpoint, token, index, source, adminToken)
		if err != nil {
			fatalCode("connection_failed", "audit-export set: %v", err)
		}
		if jsonOutput {
			output(resp)
		} else {
			fmt.Printf("audit export configured: %s → %s\n", format, endpoint)
		}

	case "disable":
		rc := connectRegistry()
		defer rc.Close()
		resp, err := rc.SetAuditExport("", "", "", "", "", adminToken)
		if err != nil {
			fatalCode("connection_failed", "audit-export disable: %v", err)
		}
		if jsonOutput {
			output(resp)
		} else {
			fmt.Println("audit export disabled")
		}

	default:
		fatalCode("invalid_argument", "unknown audit-export subcommand: %s (use get, set, or disable)", args[0])
	}
}

func cmdProvisionStatus() {
	adminToken := requireAdminToken()
	rc := connectRegistry()
	defer rc.Close()

	resp, err := rc.GetProvisionStatus(adminToken)
	if err != nil {
		fatalCode("connection_failed", "provision-status: %v", err)
	}
	if jsonOutput {
		output(resp)
		return
	}

	if v := resp["idp_type"]; v != nil {
		fmt.Printf("identity provider: %v\n", v)
	}
	if v := resp["audit_export"]; v != nil {
		fmt.Printf("audit export: %v\n", v)
	}
	if v := resp["webhook_enabled"]; v == true {
		fmt.Println("webhook: enabled")
	}
	fmt.Println()

	networks, ok := resp["networks"].([]interface{})
	if !ok || len(networks) == 0 {
		fmt.Println("no networks provisioned")
		return
	}
	fmt.Printf("%-6s %-20s %-12s %-10s %-8s %s\n", "ID", "Name", "Enterprise", "Members", "Rule", "Pre-Assign")
	for _, n := range networks {
		net, ok := n.(map[string]interface{})
		if !ok {
			continue
		}
		enterprise := "no"
		if net["enterprise"] == true {
			enterprise = "yes"
		}
		preAssign := ""
		if v := net["rbac_pre_assignments"]; v != nil && v != float64(0) {
			preAssign = fmt.Sprintf("%v roles", v)
		}
		fmt.Printf("%-6v %-20v %-12s %-10v %-8v %s\n",
			net["network_id"], net["name"], enterprise,
			net["members"], net["join_rule"], preAssign)
	}
}

// --- Directory sync commands ---

func cmdDirectorySync(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl directory-sync <directory.json> [--network <id>] [--remove-unlisted]")
	}
	adminToken := requireAdminToken()
	flags, pos := parseFlags(args)

	var filePath string
	if len(pos) > 0 {
		filePath = pos[0]
	} else {
		filePath = args[0]
	}

	netIDStr := flagString(flags, "network", "0")
	netID := parseUint16(netIDStr, "network_id")
	removeUnlisted := flagBool(flags, "remove-unlisted")

	data, err := os.ReadFile(filePath)
	if err != nil {
		fatalCode("invalid_argument", "read directory file: %v", err)
	}

	var payload struct {
		NetworkID      uint16                   `json:"network_id"`
		Entries        []map[string]interface{} `json:"entries"`
		RemoveUnlisted bool                     `json:"remove_unlisted"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		fatalCode("invalid_argument", "parse directory file: %v", err)
	}

	if netID == 0 && payload.NetworkID > 0 {
		netID = payload.NetworkID
	}
	if netID == 0 {
		fatalCode("invalid_argument", "network_id required (use --network or set in file)")
	}
	if removeUnlisted {
		payload.RemoveUnlisted = true
	}

	rc := connectRegistry()
	defer rc.Close()

	resp, err := rc.DirectorySync(netID, payload.Entries, payload.RemoveUnlisted, adminToken)
	if err != nil {
		fatalCode("connection_failed", "directory-sync: %v", err)
	}
	if jsonOutput {
		output(resp)
		return
	}

	fmt.Printf("directory sync complete: %v mapped, %v updated, %v disabled, %v unmapped\n",
		resp["mapped"], resp["updated"], resp["disabled"], resp["unmapped"])
	if actions, ok := resp["actions"].([]interface{}); ok {
		for _, a := range actions {
			fmt.Printf("  - %v\n", a)
		}
	}
}

// ===================== SCRIPTORIUM =====================

// cmdScriptorium sends a pre-formatted command message to a configured responder node.
//
// Usage:
//
//	pilotctl scriptorium <command> [body] [--node <address|hostname>]
//
// The target node is read from ~/.pilot/scriptorium.yaml (key: node) unless
// overridden with --node.  The message is sent as JSON:
//
//	{"command":"<command>","body":"<body>"}
func cmdScriptorium(args []string) {
	flags, pos := parseFlags(args)
	if len(pos) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl scriptorium <command> [body] [--node <address|hostname>]")
	}

	cmdName := pos[0]
	body := ""
	if len(pos) > 1 {
		body = strings.Join(pos[1:], " ")
	}

	// Resolve target node: --node flag > ~/.pilot/scriptorium.yaml > error.
	nodeAddr := flagString(flags, "node", "")
	if nodeAddr == "" {
		nodeAddr = loadScriptoriumNode()
	}
	if nodeAddr == "" {
		fatalHint("config_missing",
			"add 'node: <pilot-address>' to ~/.pilot/scriptorium.yaml or pass --node <address>",
			"scriptorium target node not configured")
	}

	// Build JSON payload.
	payload := map[string]string{"command": cmdName, "body": body}
	msgJSON, err := json.Marshal(payload)
	if err != nil {
		fatalCode("internal", "marshal message: %v", err)
	}

	d := connectDriver()
	defer d.Close()

	target, err := parseAddrOrHostname(d, nodeAddr)
	if err != nil {
		fatalCode("not_found", "scriptorium node %q: %v", nodeAddr, err)
	}

	client, err := dataexchange.Dial(d, target)
	if err != nil {
		fatalHint("connection_failed",
			fmt.Sprintf("ensure the node is reachable and trusted: pilotctl ping %s", nodeAddr),
			"cannot connect to scriptorium node %s", nodeAddr)
	}
	defer client.Close()

	if err := client.SendJSON(msgJSON); err != nil {
		fatalCode("connection_failed", "send command: %v", err)
	}

	// Read ACK from the data-exchange layer.
	ack, err := client.Recv()
	if err != nil {
		slog.Debug("scriptorium ACK read failed", "err", err)
	}

	result := map[string]interface{}{
		"command": cmdName,
		"body":    body,
		"node":    target.String(),
	}
	if ack != nil {
		result["ack"] = string(ack.Payload)
	}
	outputOK(result)
}

// loadScriptoriumNode reads the target node address from ~/.pilot/scriptorium.yaml.
// Returns an empty string if the file is absent or contains no node key.
//
// Expected format:
//
//	node: "0:0000.0000.000B"
func loadScriptoriumNode() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(home, ".pilot", "scriptorium.yaml"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "node:") {
			val := strings.TrimSpace(line[5:])
			// Strip surrounding quotes.
			if len(val) >= 2 {
				f, l := val[0], val[len(val)-1]
				if (f == '"' && l == '"') || (f == '\'' && l == '\'') {
					val = val[1 : len(val)-1]
				}
			}
			return val
		}
	}
	return ""
}

// ===================== SERVICE AGENT COMMANDS =====================

// cmdAi sends a natural-language query to the pilot-agent service and waits
// for the AI reply in the local inbox.
//
// Usage:
//
//	pilotctl ai "<query>" [--node <address>] [--timeout <dur>] [--output-file <path>]
func cmdAi(args []string) {
	flags, pos := parseFlags(args)
	outputFile := flagString(flags, "output-file", "")
	timeout := flagDuration(flags, "timeout", 120*time.Second)

	if len(pos) == 0 {
		fatalCode("invalid_argument", "usage: pilotctl ai \"<query>\" [--output-file <path>]")
	}
	query := strings.Join(pos, " ")

	nodeAddr := flagString(flags, "node", "")
	if nodeAddr == "" {
		nodeAddr = loadScriptoriumNode()
	}
	if nodeAddr == "" {
		fatalHint("config_missing",
			"add 'node: <pilot-address>' to ~/.pilot/scriptorium.yaml or pass --node <address>",
			"ai target node not configured")
	}

	fromAddr := sendServiceCommand("ai", query, nodeAddr)
	if !jsonOutput {
		fmt.Fprintf(os.Stderr, "waiting for reply from %s...\n", nodeAddr)
	}

	reply, err := pollInboxForReply(fromAddr, timeout)
	if err != nil {
		if jsonOutput {
			fatalCode("timeout", "no reply received within %v", timeout)
		}
		fmt.Fprintln(os.Stderr, "(no reply — check: pilotctl inbox)")
		os.Exit(1)
	}

	writeServiceAgentReply(reply, outputFile, "pilotctl-ai")
}

// cmdClawdit sends an OpenClaw security audit request to the claw-audit
// service agent and waits for the report in the local inbox.
//
// Usage:
//
//	pilotctl clawdit ["<query>"] [--file <openclaw.json>] [--node <address>]
//	                 [--timeout <dur>] [--output-file <path>]
func cmdClawdit(args []string) {
	flags, pos := parseFlags(args)
	filePath := flagString(flags, "file", "")
	outputFile := flagString(flags, "output-file", "")
	timeout := flagDuration(flags, "timeout", 120*time.Second)

	query := strings.Join(pos, " ")
	if query == "" {
		query = "Run a full security audit of my OpenClaw installation."
	}

	nodeAddr := flagString(flags, "node", "")
	if nodeAddr == "" {
		nodeAddr = loadClawditNode()
	}
	if nodeAddr == "" {
		fatalHint("config_missing",
			"add 'node: <pilot-address>' to ~/.pilot/clawdit.yaml or pass --node <address>",
			"clawdit target node not configured")
	}

	// Build message body — embed config file content when --file is provided.
	body := query
	if filePath != "" {
		fileData, err := os.ReadFile(filePath)
		if err != nil {
			fatalCode("not_found", "cannot read --file %q: %v", filePath, err)
		}
		bodyMap := map[string]interface{}{
			"query":       query,
			"config_file": string(fileData),
		}
		b, _ := json.Marshal(bodyMap)
		body = string(b)
	}

	fromAddr := sendServiceCommand("claw-audit", body, nodeAddr)
	if !jsonOutput {
		fmt.Fprintf(os.Stderr, "waiting for audit report from %s...\n", nodeAddr)
	}

	reply, err := pollInboxForReply(fromAddr, timeout)
	if err != nil {
		if jsonOutput {
			fatalCode("timeout", "no reply received within %v", timeout)
		}
		fmt.Fprintln(os.Stderr, "(no reply — check: pilotctl inbox)")
		os.Exit(1)
	}

	writeServiceAgentReply(reply, outputFile, "claw-audit")
}

// sendServiceCommand dials a service agent node via data-exchange, sends a
// JSON command payload, and returns the node's pilot address (for inbox polling).
func sendServiceCommand(command, body, nodeAddr string) string {
	payload := map[string]string{"command": command, "body": body}
	msgJSON, err := json.Marshal(payload)
	if err != nil {
		fatalCode("internal", "marshal message: %v", err)
	}

	d := connectDriver()
	defer d.Close()

	target, err := parseAddrOrHostname(d, nodeAddr)
	if err != nil {
		fatalCode("not_found", "service agent node %q: %v", nodeAddr, err)
	}

	client, err := dataexchange.Dial(d, target)
	if err != nil {
		fatalHint("connection_failed",
			fmt.Sprintf("ensure the node is reachable and trusted: pilotctl ping %s", nodeAddr),
			"cannot connect to service agent node %s", nodeAddr)
	}
	defer client.Close()

	if err := client.SendJSON(msgJSON); err != nil {
		fatalCode("connection_failed", "send command: %v", err)
	}
	client.Recv() // drain ACK (non-fatal if absent)

	return target.String()
}

// pollInboxForReply watches ~/.pilot/inbox/ for a new message from fromAddr
// and returns its data payload. Returns an error if timeout elapses first.
func pollInboxForReply(fromAddr string, timeout time.Duration) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".pilot", "inbox")

	// Snapshot existing files so we only react to new arrivals.
	existing := make(map[string]bool)
	if entries, err2 := os.ReadDir(dir); err2 == nil {
		for _, e := range entries {
			existing[e.Name()] = true
		}
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		time.Sleep(3 * time.Second)
		entries, err2 := os.ReadDir(dir)
		if err2 != nil {
			continue
		}
		for _, e := range entries {
			if existing[e.Name()] {
				continue
			}
			data, err3 := os.ReadFile(filepath.Join(dir, e.Name()))
			if err3 != nil {
				continue
			}
			var msg map[string]interface{}
			if err3 = json.Unmarshal(data, &msg); err3 != nil {
				continue
			}
			from, _ := msg["from"].(string)
			if fromAddr != "" && from != fromAddr {
				existing[e.Name()] = true // seen, not our node
				continue
			}
			msgData, _ := msg["data"].(string)
			// Unwrap JSON-encoded string if the agent double-serialised.
			var unwrapped string
			if json.Unmarshal([]byte(msgData), &unwrapped) == nil {
				return unwrapped, nil
			}
			return msgData, nil
		}
	}
	return "", fmt.Errorf("timeout waiting for reply from %s", fromAddr)
}

// writeServiceAgentReply prints reply to stdout or saves it to a file.
// If outputFile is "true" (bare --output-file flag), a timestamped filename is used.
func writeServiceAgentReply(reply, outputFile, prefix string) {
	if outputFile == "" {
		if jsonOutput {
			outputOK(map[string]interface{}{"reply": reply})
		} else {
			fmt.Println(reply)
		}
		return
	}
	if outputFile == "true" {
		outputFile = fmt.Sprintf("%s-%s.txt", prefix, time.Now().Format("20060102-150405"))
	}
	if err := os.WriteFile(outputFile, []byte(reply), 0644); err != nil {
		fatalCode("internal", "write output file: %v", err)
	}
	if jsonOutput {
		outputOK(map[string]interface{}{"saved": outputFile, "bytes": len(reply)})
	} else {
		fmt.Printf("saved to %s (%d bytes)\n", outputFile, len(reply))
	}
}

// cmdLs lists all available service agents and their configuration status.
func cmdLs(args []string) {
	type agentInfo struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Usage       string `json:"usage"`
		Config      string `json:"config"`
		Configured  bool   `json:"configured"`
		Node        string `json:"node,omitempty"`
	}

	agents := []agentInfo{
		{
			Name:        "ai",
			Description: "Natural-language assistant — ask anything about your network",
			Usage:       `pilotctl ai "<query>"`,
			Config:      "~/.pilot/scriptorium.yaml",
		},
		{
			Name:        "scriptorium",
			Description: "Intelligence briefs (stockmarket, polymarket, …)",
			Usage:       `pilotctl scriptorium <command> "<body>"`,
			Config:      "~/.pilot/scriptorium.yaml",
		},
		{
			Name:        "clawdit",
			Description: "Security audit of an OpenClaw installation",
			Usage:       `pilotctl clawdit ["<query>"] [--file <path>]`,
			Config:      "~/.pilot/clawdit.yaml",
		},
	}

	// Resolve configured state.
	scriptoriumNode := loadScriptoriumNode()
	clawditNode := loadClawditNode()
	for i := range agents {
		switch agents[i].Name {
		case "ai", "scriptorium":
			if scriptoriumNode != "" {
				agents[i].Configured = true
				agents[i].Node = scriptoriumNode
			}
		case "clawdit":
			if clawditNode != "" {
				agents[i].Configured = true
				agents[i].Node = clawditNode
			}
		}
	}

	if jsonOutput {
		outputOK(map[string]interface{}{"agents": agents})
		return
	}

	fmt.Println("Service Agents:")
	fmt.Println()
	for _, a := range agents {
		status := "  ✗ not configured"
		if a.Configured {
			status = fmt.Sprintf("  ✓ node %s", a.Node)
		}
		fmt.Printf("  %-14s %s\n", a.Name, a.Description)
		fmt.Printf("  %-14s %s\n", "", a.Usage)
		fmt.Printf("  %-14s config: %s%s\n", "", a.Config, status)
		fmt.Println()
	}
}

// cmdTui launches the interactive service-agent TUI.
func cmdTui(args []string) {
	// Locate tui.py: check next to the binary first, then fall back to ~/.pilot/tui.py.
	exe, _ := os.Executable()
	candidates := []string{
		filepath.Join(filepath.Dir(exe), "tui.py"),
	}
	home, err := os.UserHomeDir()
	if err == nil {
		candidates = append(candidates, filepath.Join(home, ".pilot", "tui.py"))
	}

	var tuiPath string
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			tuiPath = p
			break
		}
	}
	if tuiPath == "" {
		fatalHint("not_found",
			"ensure tui.py is installed at ~/.pilot/tui.py or next to the pilotctl binary",
			"TUI not found")
	}

	// Find python3.
	python := "python3"
	if p, err := exec.LookPath("python3"); err == nil {
		python = p
	} else if p, err := exec.LookPath("python"); err == nil {
		python = p
	} else {
		fatalHint("not_found",
			"install Python 3: https://python.org",
			"python3 not found on PATH")
	}

	cmd := exec.Command(python, tuiPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fatalCode("internal", "tui: %v", err)
	}
}

// loadClawditNode reads the target node from ~/.pilot/clawdit.yaml.
func loadClawditNode() string {
	return loadPilotYAMLNode("clawdit.yaml")
}

// loadPilotYAMLNode reads a 'node: <addr>' value from a YAML file in ~/.pilot/.
func loadPilotYAMLNode(filename string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(home, ".pilot", filename))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || !strings.HasPrefix(line, "node:") {
			continue
		}
		val := strings.TrimSpace(line[5:])
		if len(val) >= 2 {
			f, l := val[0], val[len(val)-1]
			if (f == '"' && l == '"') || (f == '\'' && l == '\'') {
				val = val[1 : len(val)-1]
			}
		}
		return val
	}
	return ""
}

func cmdDirectoryStatus(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl directory-status <network_id>")
	}
	adminToken := requireAdminToken()
	netID := parseUint16(args[0], "network_id")

	rc := connectRegistry()
	defer rc.Close()

	resp, err := rc.DirectoryStatus(netID, adminToken)
	if err != nil {
		fatalCode("connection_failed", "directory-status: %v", err)
	}
	if jsonOutput {
		output(resp)
		return
	}

	fmt.Printf("Network %v directory status:\n", resp["network_id"])
	fmt.Printf("  total members: %v\n", resp["total"])
	fmt.Printf("  directory mapped: %v\n", resp["mapped"])
	fmt.Printf("  unmapped: %v\n", resp["unmapped"])
	if v := resp["pre_assignments"]; v != nil && v != float64(0) {
		fmt.Printf("  pre-assignments: %v\n", v)
	}
	if v := resp["last_sync"]; v != nil && v != "" {
		fmt.Printf("  last sync: %v\n", v)
	}
}

// --- Managed network commands ---

func cmdManagedScore(args []string) {
	flags, pos := parseFlags(args)
	if len(pos) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl managed score <peer_node_id> [--net <id>] [--topic T] [--delta N]")
	}
	nodeID := parseNodeID(pos[0])
	netID := uint16(flagInt(flags, "net", 0))
	topic := flagString(flags, "topic", "")
	delta := flagInt(flags, "delta", 1)

	d := connectDriver()
	defer d.Close()

	resp, err := d.ManagedScore(netID, nodeID, delta, topic)
	if err != nil {
		fatalCode("connection_failed", "managed score: %v", err)
	}
	if jsonOutput {
		output(resp)
	} else {
		fmt.Printf("scored peer %d: delta=%d topic=%q\n", nodeID, delta, topic)
	}
}

func cmdManagedStatus(args []string) {
	flags, _ := parseFlags(args)
	netID := uint16(flagInt(flags, "net", 0))

	d := connectDriver()
	defer d.Close()

	resp, err := d.ManagedStatus(netID)
	if err != nil {
		fatalCode("connection_failed", "managed status: %v", err)
	}
	output(resp)
}

func cmdManagedRankings(args []string) {
	flags, _ := parseFlags(args)
	netID := uint16(flagInt(flags, "net", 0))

	d := connectDriver()
	defer d.Close()

	resp, err := d.ManagedRankings(netID)
	if err != nil {
		fatalCode("connection_failed", "managed rankings: %v", err)
	}
	output(resp)
}

func cmdManagedCycle(args []string) {
	flags, _ := parseFlags(args)
	netID := uint16(flagInt(flags, "net", 0))
	force := flagBool(flags, "force")

	if !force {
		fatalCode("invalid_argument", "usage: pilotctl managed cycle --force [--net <id>]")
	}

	d := connectDriver()
	defer d.Close()

	resp, err := d.ManagedForceCycle(netID)
	if err != nil {
		fatalCode("connection_failed", "managed cycle: %v", err)
	}
	if jsonOutput {
		output(resp)
	} else {
		fmt.Printf("cycle complete: pruned=%v filled=%v peers=%v\n",
			resp["pruned"], resp["filled"], resp["peers"])
	}
}

// --- Policy commands ---

func cmdPolicyGet(args []string) {
	flags, _ := parseFlags(args)
	netID := uint16(flagInt(flags, "net", 0))
	if netID == 0 {
		fatalCode("invalid_argument", "usage: pilotctl policy get --net <id>")
	}

	d := connectDriver()
	defer d.Close()

	resp, err := d.PolicyGet(netID)
	if err != nil {
		fatalCode("connection_failed", "policy get: %v", err)
	}
	output(resp)
}

func cmdPolicySet(args []string) {
	flags, _ := parseFlags(args)
	netID := uint16(flagInt(flags, "net", 0))
	file := flagString(flags, "file", "")
	inline := flagString(flags, "inline", "")

	if netID == 0 {
		fatalCode("invalid_argument", "usage: pilotctl policy set --net <id> --file <path> | --inline '<json>'")
	}

	var policyJSON []byte
	if file != "" {
		var err error
		policyJSON, err = os.ReadFile(file)
		if err != nil {
			fatalCode("io_error", "reading policy file: %v", err)
		}
	} else if inline != "" {
		policyJSON = []byte(inline)
	} else {
		fatalCode("invalid_argument", "provide --file or --inline")
	}

	// Validate locally first
	doc, err := policy.Parse(policyJSON)
	if err != nil {
		fatalCode("invalid_argument", "policy validation: %v", err)
	}
	if _, err := policy.Compile(doc); err != nil {
		fatalCode("invalid_argument", "policy compilation: %v", err)
	}

	// Send to registry (admin-token gated)
	reg := connectRegistry()
	defer reg.Close()

	adminToken := flagString(flags, "admin-token", "")
	if adminToken == "" {
		adminToken = getAdminToken()
	}
	_, err = reg.SetExprPolicy(netID, policyJSON, adminToken)
	if err != nil {
		fatalCode("connection_failed", "set policy on registry: %v", err)
	}

	// Also apply locally to daemon if running
	d := connectDriver()
	defer d.Close()

	resp, err := d.PolicySet(netID, policyJSON)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: policy saved to registry but daemon apply failed: %v\n", err)
		return
	}
	if jsonOutput {
		output(resp)
	} else {
		fmt.Printf("policy set on network %d (registry + daemon)\n", netID)
	}
}

func cmdPolicyValidate(args []string) {
	flags, _ := parseFlags(args)
	file := flagString(flags, "file", "")
	inline := flagString(flags, "inline", "")

	var policyJSON []byte
	if file != "" {
		var err error
		policyJSON, err = os.ReadFile(file)
		if err != nil {
			fatalCode("io_error", "reading policy file: %v", err)
		}
	} else if inline != "" {
		policyJSON = []byte(inline)
	} else {
		fatalCode("invalid_argument", "provide --file or --inline")
	}

	doc, err := policy.Parse(policyJSON)
	if err != nil {
		fatalCode("invalid_argument", "validation failed: %v", err)
	}

	cp, err := policy.Compile(doc)
	if err != nil {
		fatalCode("invalid_argument", "compilation failed: %v", err)
	}

	if jsonOutput {
		output(map[string]interface{}{
			"valid":   true,
			"version": doc.Version,
			"rules":   len(doc.Rules),
			"events":  countEventTypes(cp),
		})
	} else {
		fmt.Printf("valid policy: %d rules\n", len(doc.Rules))
		for _, r := range doc.Rules {
			fmt.Printf("  - %s (on %s): %d actions\n", r.Name, r.On, len(r.Actions))
		}
	}
}

func cmdPolicyTest(args []string) {
	flags, _ := parseFlags(args)
	file := flagString(flags, "file", "")
	eventJSON := flagString(flags, "event", "")

	if file == "" || eventJSON == "" {
		fatalCode("invalid_argument", "usage: pilotctl policy test --file <path> --event '<json>'")
	}

	policyJSON, err := os.ReadFile(file)
	if err != nil {
		fatalCode("io_error", "reading policy file: %v", err)
	}

	doc, err := policy.Parse(policyJSON)
	if err != nil {
		fatalCode("invalid_argument", "policy: %v", err)
	}
	cp, err := policy.Compile(doc)
	if err != nil {
		fatalCode("invalid_argument", "policy: %v", err)
	}

	var event map[string]interface{}
	if err := json.Unmarshal([]byte(eventJSON), &event); err != nil {
		fatalCode("invalid_argument", "event JSON: %v", err)
	}

	// JSON unmarshaling puts numbers as float64; expr env expects int.
	for k, v := range event {
		if f, ok := v.(float64); ok {
			event[k] = int(f)
		}
	}

	eventType, _ := event["type"].(string)
	if eventType == "" {
		fatalCode("invalid_argument", "event must have a 'type' field (connect, dial, datagram, cycle, join, leave)")
	}
	delete(event, "type")

	dirs, err := cp.Evaluate(policy.EventType(eventType), event)
	if err != nil {
		fatalCode("invalid_argument", "evaluation: %v", err)
	}

	if jsonOutput {
		results := make([]map[string]interface{}, 0, len(dirs))
		for _, d := range dirs {
			results = append(results, map[string]interface{}{
				"type":   directiveTypeName(d.Type),
				"rule":   d.Rule,
				"params": d.Params,
			})
		}
		output(map[string]interface{}{"directives": results})
	} else {
		fmt.Printf("event type: %s → %d directives\n", eventType, len(dirs))
		for _, d := range dirs {
			fmt.Printf("  %s (from rule %q)\n", directiveTypeName(d.Type), d.Rule)
		}
	}
}

func countEventTypes(cp *policy.CompiledPolicy) map[string]bool {
	events := map[string]bool{}
	for _, et := range []policy.EventType{
		policy.EventConnect, policy.EventDial, policy.EventDatagram,
		policy.EventCycle, policy.EventJoin, policy.EventLeave,
	} {
		if cp.HasRulesFor(et) {
			events[string(et)] = true
		}
	}
	return events
}

func directiveTypeName(dt policy.DirectiveType) string {
	switch dt {
	case policy.DirectiveAllow:
		return "allow"
	case policy.DirectiveDeny:
		return "deny"
	case policy.DirectiveScore:
		return "score"
	case policy.DirectiveTag:
		return "tag"
	case policy.DirectiveEvict:
		return "evict"
	case policy.DirectiveEvictWhere:
		return "evict_where"
	case policy.DirectivePrune:
		return "prune"
	case policy.DirectiveFill:
		return "fill"
	case policy.DirectiveWebhook:
		return "webhook"
	case policy.DirectiveLog:
		return "log"
	default:
		return "unknown"
	}
}

func cmdMemberTagsSet(args []string) {
	flags, _ := parseFlags(args)
	netID := parseUint16(flagString(flags, "net", "0"), "net")
	nodeID := flagString(flags, "node", "0")
	tagsStr := flagString(flags, "tags", "")

	if netID == 0 || nodeID == "0" || tagsStr == "" {
		fatalCode("invalid_argument", "usage: pilotctl member-tags set --net <id> --node <id> --tags tag1,tag2")
	}

	nid, err := strconv.ParseUint(nodeID, 10, 32)
	if err != nil {
		fatalCode("invalid_argument", "invalid node ID: %s", nodeID)
	}

	tags := strings.Split(tagsStr, ",")

	// If admin token is available, go directly to registry (no daemon needed)
	if adminToken := getAdminToken(); adminToken != "" {
		rc := connectRegistry()
		defer rc.Close()

		result, err := rc.SetMemberTags(netID, uint32(nid), tags, adminToken)
		if err != nil {
			fatalCode("connection_failed", "member-tags set: %v", err)
		}
		if jsonOutput {
			output(result)
			return
		}
		fmt.Printf("Member tags set for node %d in network %d: %s\n", uint32(nid), netID, strings.Join(tags, ", "))
		return
	}

	d := connectDriver()
	defer d.Close()

	result, err := d.MemberTagsSet(netID, uint32(nid), tags)
	if err != nil {
		fatalCode("connection_failed", "member-tags set: %v", err)
	}

	if jsonOutput {
		output(result)
		return
	}
	fmt.Printf("Member tags set for node %d in network %d: %s\n", uint32(nid), netID, strings.Join(tags, ", "))
}

func cmdMemberTagsGet(args []string) {
	flags, _ := parseFlags(args)
	netID := parseUint16(flagString(flags, "net", "0"), "net")
	nodeID := flagString(flags, "node", "0")

	if netID == 0 {
		fatalCode("invalid_argument", "usage: pilotctl member-tags get --net <id> [--node <id>]")
	}

	nid, err := strconv.ParseUint(nodeID, 10, 32)
	if err != nil {
		fatalCode("invalid_argument", "invalid node ID: %s", nodeID)
	}

	d := connectDriver()
	defer d.Close()

	result, err := d.MemberTagsGet(netID, uint32(nid))
	if err != nil {
		fatalCode("connection_failed", "member-tags get: %v", err)
	}

	if jsonOutput {
		output(result)
		return
	}

	if uint32(nid) != 0 {
		if tags, ok := result["tags"].([]interface{}); ok {
			tagStrs := make([]string, len(tags))
			for i, t := range tags {
				tagStrs[i] = fmt.Sprint(t)
			}
			fmt.Printf("Node %d in network %d: %s\n", uint32(nid), netID, strings.Join(tagStrs, ", "))
		} else {
			fmt.Printf("Node %d in network %d: (no tags)\n", uint32(nid), netID)
		}
	} else {
		if members, ok := result["members"].(map[string]interface{}); ok {
			for mid, tags := range members {
				fmt.Printf("  node %s: %v\n", mid, tags)
			}
		}
	}
}
