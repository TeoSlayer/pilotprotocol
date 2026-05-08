// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/driver"
	"github.com/TeoSlayer/pilotprotocol/internal/eventstream"
	"github.com/TeoSlayer/pilotprotocol/internal/trustedagents"
	policylang "github.com/TeoSlayer/pilotprotocol/internal/policy"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
	registry "github.com/TeoSlayer/pilotprotocol/pkg/registry/client"
	"github.com/TeoSlayer/pilotprotocol/internal/dataexchange"
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
			"error":   msg,
		})
		fmt.Fprintln(os.Stderr, string(b))
	} else {
		fmt.Fprintf(os.Stderr, "error: %s\n", msg)
	}
	os.Exit(1)
}

// classifyDaemonError inspects an error string from the daemon and, when it
// recognizes a transient or operator-friendly failure mode, returns a more
// actionable hint to the user. Returns "" if no specific guidance applies —
// callers fall back to whatever default hint they had.
//
// Currently recognized patterns:
//   - "pending queue full ... key exchange pending" — the encrypted tunnel
//     to the peer is mid-handshake. The packet was queued; waiting a moment
//     and retrying typically succeeds.
//   - "dial timeout"/"dial: daemon: dial timeout" — the SYN went out but no
//     SYN-ACK came back. Often means the relay path is mid-convergence
//     after a beacon roll, or the peer is offline.
func classifyDaemonError(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "pending queue full") || strings.Contains(s, "key exchange pending"):
		return "tunnel handshake in progress — the packet was queued. Wait a few seconds and retry; the SYN will go out as soon as the encrypted session keys are derived."
	case strings.Contains(s, "dial timeout"):
		return "no reply from peer. Check reachability with `pilotctl ping <peer>`; if relay is fresh after a beacon roll it can take ~30s for endpoints to converge."
	}
	return ""
}

// fatalHint is like fatalCode but adds an actionable hint telling the user what to do next.
func fatalHint(code, hint, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if jsonOutput {
		b, _ := json.Marshal(map[string]string{
			"status":  "error",
			"code":    code,
			"message": msg,
			"error":   msg,
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

// fmtDuration formats a duration as a compact human-readable string
// ("3s", "2m5s", "1h4m", "2d3h") for --trace output.
func fmtDuration(d time.Duration) string {
	d = d.Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		m := int(d.Minutes())
		s := int(d.Seconds()) % 60
		if s == 0 {
			return fmt.Sprintf("%dm", m)
		}
		return fmt.Sprintf("%dm%ds", m, s)
	}
	if d < 24*time.Hour {
		h := int(d.Hours())
		m := int(d.Minutes()) % 60
		if m == 0 {
			return fmt.Sprintf("%dh", h)
		}
		return fmt.Sprintf("%dh%dm", h, m)
	}
	days := int(d.Hours()) / 24
	h := int(d.Hours()) % 24
	if h == 0 {
		return fmt.Sprintf("%dd", days)
	}
	return fmt.Sprintf("%dd%dh", days, h)
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

// maybeAutoHandshake gates any client-initiated tunnel operation
// (send-message, send-file, connect, ping, publish, etc.)
// based on the peer's visibility and our trust state. Three branches:
//
//  1. **Already trusted**: pass silently (one IPC fast-path, ~5ms).
//  2. **Peer in embedded `internal/trustedagents` list** (curated service
//     agents): print "establishing handshake with Trusted Agent <name>",
//     fire Driver.Handshake, then block on Driver.WaitForTrust until the
//     peer's accept arrives or 5s elapses. Trust formation on cold first
//     contact takes ~700–2400ms (request dial + accept dial back); blocking
//     here serialises trust-then-data so service agents don't drop our
//     payload before peer-side trust is finalised.
//  3. **Otherwise**: registry lookup. If the peer is **Public**, allow the
//     tunnel — public daemons accept all comers by design. If the peer is
//     **Private**, refuse client-side with `trust_required`: a private
//     peer's daemon will silently drop our SYN anyway (daemon.go:2223),
//     so starting a tunnel just produces a timeout. Refusing upfront
//     gives the user a clear, immediate signal and a handshake hint.
//
// Skip with --no-auto-handshake. Pre-#99 daemons don't have SubHandshakeWait;
// we treat the IPC error as "wait unsupported" and proceed best-effort.
func maybeAutoHandshake(d *driver.Driver, addr protocol.Addr, skip bool) {
	if skip {
		return
	}

	// Branch 1 — already trusted. Fast path: one IPC roundtrip, no network.
	if resp, err := d.WaitForTrust(addr.Node, 0); err == nil {
		if trusted, _ := resp["trusted"].(bool); trusted {
			return
		}
	}

	// Branch 2 — peer is in the embedded trusted-agents allowlist.
	if name, ok := trustedagents.IsTrusted(addr.Node); ok {
		if !jsonOutput {
			fmt.Fprintf(os.Stderr, "establishing handshake with Trusted Agent %s (%s)...\n", name, addr)
		}
		if _, err := d.Handshake(addr.Node, "auto-handshake: trusted agent "+name); err != nil {
			if !jsonOutput {
				fmt.Fprintf(os.Stderr, "  handshake send failed: %v — continuing\n", err)
			}
			return
		}
		resp, err := d.WaitForTrust(addr.Node, 5000)
		if err != nil {
			if !jsonOutput {
				fmt.Fprintf(os.Stderr, "  wait-for-trust unsupported on this daemon; continuing\n")
			}
			return
		}
		if trusted, _ := resp["trusted"].(bool); trusted {
			if !jsonOutput {
				fmt.Fprintf(os.Stderr, "  trust established with %s\n", name)
			}
		} else {
			if !jsonOutput {
				fmt.Fprintf(os.Stderr, "  trust not established within 5s — continuing (peer may drop)\n")
			}
		}
		return
	}

	// Branch 3 — unknown peer, not trusted. Refuse if private.
	rc, err := registry.Dial(getRegistry())
	if err != nil {
		// Registry unreachable — be conservative and refuse rather than
		// silently let an untrusted tunnel attempt go through to a peer
		// we can't characterise.
		fatalHint("trust_required",
			fmt.Sprintf("run: pilotctl handshake %s", addr),
			"cannot verify peer visibility (registry unreachable: %v); refusing tunnel to untrusted node", err)
	}
	defer rc.Close()
	info, lookupErr := rc.Lookup(addr.Node)
	if lookupErr != nil {
		fatalHint("trust_required",
			fmt.Sprintf("run: pilotctl handshake %s", addr),
			"cannot look up peer %s (%v); refusing tunnel to untrusted node", addr, lookupErr)
	}
	pub, _ := info["public"].(bool)
	if !pub {
		fatalHint("trust_required",
			fmt.Sprintf("run: pilotctl handshake %s", addr),
			"refusing tunnel to private node %s without trust", addr)
	}
	// Public peer, no trust needed — proceed.
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
  pilotctl rotate-key
  pilotctl set-public
  pilotctl set-private
  pilotctl deregister

Discovery commands:
  pilotctl find <hostname>
  pilotctl set-hostname <hostname>
  pilotctl clear-hostname
  pilotctl set-tags <tag1> [tag2] ...
  pilotctl clear-tags

Communication commands:
  pilotctl connect <address|hostname> [port] [--message <msg>] [--timeout <dur>]
  pilotctl send <address|hostname> <port> --data <msg> [--timeout <dur>]
  pilotctl recv <port> [--count <n>] [--timeout <dur>]
  pilotctl send-file <address|hostname> <filepath>
  pilotctl send-message <address|hostname> --data <text> [--type text|json|binary]
  pilotctl subscribe <address|hostname> <topic> [--count <n>] [--timeout <dur>]
  pilotctl publish <address|hostname> <topic> --data <message>

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

Service Agents:
  pilotctl send-message list-agents --data "list all agents"

Diagnostic commands:
  pilotctl info
  pilotctl health
  pilotctl peers [--search <query>] [--show-endpoints]
  pilotctl ping <address|hostname> [--count <n>] [--timeout <dur>]
  pilotctl traceroute <address> [--timeout <dur>]
  pilotctl bench <address|hostname> [size_mb] [--timeout <dur>]
  pilotctl listen <port> [--count <n>] [--timeout <dur>]
  pilotctl broadcast <network_id> <message>
  pilotctl updates [--count <n>] [--scope <scope>]   read https://teoslayer.github.io/pilot-changelog/feed.xml

Agent tool discovery:
  pilotctl context
  pilotctl skills [status]            show where the daemon installs SKILL.md per detected agent tool
  pilotctl skills paths               print only the install paths (shell-friendly)
  pilotctl skills check               run one reconcile pass right now

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

Companion binaries:
  daemon start / start --foreground exec the separately-shipped
  pilot-daemon binary; gateway start / map exec pilot-gateway. They
  are discovered (in order): $PILOT_DAEMON_BIN / $PILOT_GATEWAY_BIN,
  next to the pilotctl executable, then $PATH.
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
	extrasOnly := false

dispatch:
	switch cmd {

	case "extras":
		if len(cmdArgs) == 0 {
			cmdExtrasHelp()
			return
		}
		extrasOnly = true
		cmd = cmdArgs[0]
		cmdArgs = cmdArgs[1:]
		goto dispatch

	case "version":
		fmt.Println(version)
		return

	case "updates":
		cmdUpdates(cmdArgs)
		return

	case "skills":
		cmdSkills(cmdArgs)
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

	// Gateway (extras-only — use 'pilotctl extras gateway' or pilot-gateway binary)
	case "gateway":
		if !extrasOnly {
			fatalHint("invalid_argument",
				"use 'pilotctl extras gateway <subcommand>' or the pilot-gateway binary",
				"gateway commands are not in the core CLI")
		}
		if len(cmdArgs) < 1 {
			fatalHint("invalid_argument",
				"available: start, stop, map, unmap, list",
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
		if !extrasOnly {
			fatalHint("invalid_argument", "use 'pilotctl extras set-tags'", "set-tags is not in the core CLI")
		}
		cmdSetTags(cmdArgs)
	case "clear-tags":
		if !extrasOnly {
			fatalHint("invalid_argument", "use 'pilotctl extras clear-tags'", "clear-tags is not in the core CLI")
		}
		cmdClearTags()
	case "set-webhook":
		cmdSetWebhook(cmdArgs)
	case "clear-webhook":
		cmdClearWebhook()

	// Communication
	case "connect":
		cmdConnect(cmdArgs)
	case "send":
		cmdSend(cmdArgs)
	case "dgram":
		cmdDgram(cmdArgs)
	case "recv":
		cmdRecv(cmdArgs)
	case "send-file":
		cmdSendFile(cmdArgs)
	case "send-message":
		cmdSendMessage(cmdArgs)
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
	case "trusted":
		cmdTrusted(cmdArgs)

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
				"available: status, cycle, reconcile",
				"usage: pilotctl managed <subcommand>")
		}
		switch cmdArgs[0] {
		case "status":
			cmdManagedStatus(cmdArgs[1:])
		case "cycle":
			cmdManagedCycle(cmdArgs[1:])
		case "reconcile":
			cmdManagedReconcile(cmdArgs[1:])
		default:
			fatalHint("invalid_argument",
				"available: status, cycle, reconcile",
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
	case "deprovision":
		cmdDeprovision(cmdArgs)
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
		cmdInfo(cmdArgs)
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
		"version": "1.3",
		"note":    "Core commands cover everything an agent needs. Use 'pilotctl extras <cmd>' for operator/admin operations. 'pilot-gateway' is a separate installed binary.",

		// ── Core agent commands ──────────────────────────────────────────────
		"commands": map[string]interface{}{
			// Setup & identity
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
			"version": map[string]interface{}{
				"args":        []string{},
				"description": "Print the installed binary version",
				"returns":     "version string",
			},

			// Daemon lifecycle
			"daemon start": map[string]interface{}{
				"args":        []string{"[--registry <addr>]", "[--beacon <addr>]", "[--listen <addr>]", "[--identity <path>]", "[--email <addr>]", "[--hostname <name>]", "[--log-level <level>]", "[--public]", "[--foreground]", "[--socket <path>]"},
				"description": "Start the daemon as a background process. Blocks until registered, then exits",
				"returns":     "node_id, address, pid, socket, hostname, log_file",
			},
			"daemon stop": map[string]interface{}{
				"args":        []string{},
				"description": "Stop the running daemon",
				"returns":     "pid, forced (bool)",
			},
			"daemon status": map[string]interface{}{
				"args":        []string{"[--check]"},
				"description": "Check if daemon is running and responsive. --check: silent, exits 0/1",
				"returns":     "running (bool), responsive (bool), pid, node_id, address, hostname, uptime_secs, peers, connections",
			},

			// Registry / discovery
			"register": map[string]interface{}{
				"args":        []string{"[listen_addr]"},
				"description": "Register this node with the registry",
				"returns":     "node_id, address, public_key",
			},
			"deregister": map[string]interface{}{
				"args":        []string{},
				"description": "Deregister this node from the registry",
				"returns":     "status",
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
				"description": "Set this node's hostname",
				"returns":     "hostname, node_id",
			},
			"set-public": map[string]interface{}{
				"args":        []string{},
				"description": "Make this node's endpoint publicly visible",
				"returns":     "status",
			},
			"set-private": map[string]interface{}{
				"args":        []string{},
				"description": "Hide this node's endpoint",
				"returns":     "status",
			},
			"rotate-key": map[string]interface{}{
				"args":        []string{},
				"description": "Rotate this node's Ed25519 identity key",
				"returns":     "node_id, address, new public_key",
			},

			// Trust
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
			"pending": map[string]interface{}{
				"args":        []string{},
				"description": "List pending inbound handshake requests",
				"returns":     "pending [{node_id, justification, received_at}]",
			},
			"trust": map[string]interface{}{
				"args":        []string{},
				"description": "List all trusted peers",
				"returns":     "trusted [{node_id, mutual, network, approved_at}]",
			},
			"untrust": map[string]interface{}{
				"args":        []string{"<node_id>"},
				"description": "Revoke trust for a peer",
				"returns":     "node_id",
			},

			// Networks (agent self-management)
			"network list": map[string]interface{}{
				"args":        []string{},
				"description": "List networks this node belongs to",
				"returns":     "networks [{id, name, role, members}], total",
			},
			"network join": map[string]interface{}{
				"args":        []string{"<network_id>"},
				"description": "Join a network",
				"returns":     "network_id, status",
			},
			"network leave": map[string]interface{}{
				"args":        []string{"<network_id>"},
				"description": "Leave a network",
				"returns":     "network_id, status",
			},
			"network members": map[string]interface{}{
				"args":        []string{"<network_id>"},
				"description": "List members of a network",
				"returns":     "members [{node_id, role, joined_at}], total",
			},
			"network invite": map[string]interface{}{
				"args":        []string{"<network_id>", "<target_node_id>"},
				"description": "Invite another node to a network",
				"returns":     "network_id, target_node_id, status",
			},
			"network invites": map[string]interface{}{
				"args":        []string{},
				"description": "List pending network invitations for this node",
				"returns":     "invites [{network_id, network_name, invited_by, invited_at}]",
			},
			"network accept": map[string]interface{}{
				"args":        []string{"<network_id>"},
				"description": "Accept a network invitation",
				"returns":     "network_id, status",
			},
			"network reject": map[string]interface{}{
				"args":        []string{"<network_id>"},
				"description": "Reject a network invitation",
				"returns":     "network_id, status",
			},
			"network create": map[string]interface{}{
				"args":        []string{"<name>", "[--managed]", "[--policy <file>]"},
				"description": "Create a new network. Use --managed for policy-governed networks",
				"returns":     "network_id, name, managed (bool)",
			},

			// Messaging
			"send-message": map[string]interface{}{
				"args":        []string{"<address|hostname>", "--data <text>", "[--type text|json|binary]"},
				"description": "Send a typed message to a node via data exchange (port 1001). Default type: text",
				"returns":     "target, type, bytes, ack",
			},
			"send-file": map[string]interface{}{
				"args":        []string{"<address|hostname>", "<filepath>"},
				"description": "Send a file to a node via data exchange (port 1001)",
				"returns":     "filename, bytes, destination, ack",
			},
			"inbox": map[string]interface{}{
				"args":        []string{"[--clear]"},
				"description": "List received messages (~/.pilot/inbox/). --clear to delete all",
				"returns":     "messages [{type, from, data, received_at}], total, dir",
			},
			"received": map[string]interface{}{
				"args":        []string{"[--clear]"},
				"description": "List received files (~/.pilot/received/). --clear to delete all",
				"returns":     "files [{name, bytes, modified, path}], total, dir",
			},

			// Pub/Sub
			"subscribe": map[string]interface{}{
				"args":        []string{"<address|hostname>", "<topic>", "[--count <n>]", "[--timeout <dur>]"},
				"description": "Subscribe to a topic on a node's event stream (port 1002). Use * for all topics. Streams NDJSON without --count",
				"returns":     "events [{topic, data, bytes}], timeout (bool)",
			},
			"publish": map[string]interface{}{
				"args":        []string{"<address|hostname>", "<topic>", "--data <message>"},
				"description": "Publish an event to a topic on a node's event stream (port 1002)",
				"returns":     "target, topic, bytes",
			},

			// Diagnostics
			"info": map[string]interface{}{
				"args":        []string{},
				"description": "Show daemon status: node_id, address, uptime, peers, connections, encryption",
				"returns":     "node_id, address, hostname, uptime_secs, connections, peers, encrypt, bytes_sent, bytes_recv, conn_list, peer_list",
			},
			"ping": map[string]interface{}{
				"args":        []string{"<address|hostname>", "[--count <n>]", "[--timeout <dur>]"},
				"description": "Ping a node via echo port (port 7). Default 4 pings",
				"returns":     "target, results [{seq, bytes, rtt_ms, error}], timeout (bool)",
			},
		},

		// ── pilot-gateway binary ─────────────────────────────────────────────
		"pilot_gateway": map[string]interface{}{
			"binary":      "pilot-gateway",
			"description": "IP gateway — bridges standard TCP/IP applications to Pilot Protocol addresses. Separate binary installed alongside pilotctl.",
			"commands": map[string]interface{}{
				"start": map[string]interface{}{
					"args":        []string{"[--subnet <cidr>]", "[--ports <list>]", "[<pilot-addr>...]"},
					"description": "Start the IP gateway",
					"returns":     "pid, subnet, mappings [{local_ip, pilot_addr}]",
				},
				"stop": map[string]interface{}{
					"args":        []string{},
					"description": "Stop the running gateway",
					"returns":     "pid",
				},
				"map": map[string]interface{}{
					"args":        []string{"<pilot-addr>", "[local-ip]"},
					"description": "Add a Pilot-address → local-IP mapping",
					"returns":     "local_ip, pilot_addr",
				},
				"unmap": map[string]interface{}{
					"args":        []string{"<local-ip>"},
					"description": "Remove a mapping and release the loopback alias",
					"returns":     "unmapped",
				},
				"list": map[string]interface{}{
					"args":        []string{},
					"description": "List active gateway mappings",
					"returns":     "mappings [{local_ip, pilot_addr}], total",
				},
			},
		},

		// ── Extras (operator / admin) ────────────────────────────────────────
		// Invoke as: pilotctl extras <command> [args...]
		"extras": map[string]interface{}{
			"description": "Operator and admin commands. All invoked as: pilotctl extras <command> [args]. Not intended for autonomous agent use.",
			"commands": map[string]interface{}{
				// Network admin
				"network delete":  map[string]interface{}{"args": []string{"<network_id>"}, "description": "Delete a network (admin)"},
				"network rename":  map[string]interface{}{"args": []string{"<network_id>", "<new_name>"}, "description": "Rename a network (admin)"},
				"network promote": map[string]interface{}{"args": []string{"<network_id>", "<node_id>"}, "description": "Promote a member to admin"},
				"network demote":  map[string]interface{}{"args": []string{"<network_id>", "<node_id>"}, "description": "Demote an admin to member"},
				"network kick":    map[string]interface{}{"args": []string{"<network_id>", "<node_id>"}, "description": "Remove a member from a network"},
				"network role":    map[string]interface{}{"args": []string{"<network_id>", "<node_id>"}, "description": "Get a member's role"},
				"network policy":  map[string]interface{}{"args": []string{"<network_id>", "[--set <json>]"}, "description": "Get or set network policy"},
				// Policy engine
				"policy get":      map[string]interface{}{"args": []string{"<network_id>"}, "description": "Get the active policy for a managed network"},
				"policy set":      map[string]interface{}{"args": []string{"<network_id>", "--file <path>|--expr <expr>"}, "description": "Set the active policy"},
				"policy validate": map[string]interface{}{"args": []string{"--file <path>|--expr <expr>"}, "description": "Validate a policy expression locally"},
				"policy test":     map[string]interface{}{"args": []string{"--file <path>", "--input <json>"}, "description": "Test a policy against sample input"},
				// Managed networks
				"managed status":    map[string]interface{}{"args": []string{"<network_id>"}, "description": "Status of a managed network (cycle count, last run, member count)"},
				"managed cycle":     map[string]interface{}{"args": []string{"<network_id>"}, "description": "Force a policy evaluation cycle"},
				"managed reconcile": map[string]interface{}{"args": []string{"<network_id>"}, "description": "Reconcile member state against registry"},
				// Member tags
				"member-tags get": map[string]interface{}{"args": []string{"<network_id>", "<node_id>"}, "description": "Get tags for a network member"},
				"member-tags set": map[string]interface{}{"args": []string{"<network_id>", "<node_id>", "--tags <csv>"}, "description": "Set tags for a network member (requires admin token)"},
				// Enterprise / provisioning
				"audit":            map[string]interface{}{"args": []string{"<network_id>", "[--limit <n>]"}, "description": "Fetch audit log for a network (requires admin token)"},
				"provision":        map[string]interface{}{"args": []string{"--file <blueprint>"}, "description": "Provision a new network from a blueprint (requires admin token)"},
				"deprovision":      map[string]interface{}{"args": []string{"<network_id>"}, "description": "Delete a managed network and its data (requires admin token)"},
				"provision-status": map[string]interface{}{"args": []string{"<network_id>"}, "description": "Check provisioning job status (requires admin token)"},
				"idp":              map[string]interface{}{"args": []string{"[--set <json>]"}, "description": "Get or set IdP configuration (requires admin token)"},
				"audit-export":     map[string]interface{}{"args": []string{"[--set <json>]"}, "description": "Get or set audit export config (requires admin token)"},
				"directory-sync":   map[string]interface{}{"args": []string{"<network_id>", "--file <csv>"}, "description": "Sync directory entries into a managed network (requires admin token)"},
				"directory-status": map[string]interface{}{"args": []string{"<network_id>"}, "description": "Check last directory sync status (requires admin token)"},
				// Node config (setup-time, not runtime agent ops)
				"set-tags":       map[string]interface{}{"args": []string{"<tag1>", "[tag2...]"}, "description": "Set discovery tags (max 3) for registry filtering"},
				"clear-tags":     map[string]interface{}{"args": []string{}, "description": "Clear all discovery tags"},
				"clear-hostname": map[string]interface{}{"args": []string{}, "description": "Clear this node's hostname"},
				"set-webhook":    map[string]interface{}{"args": []string{"<url>"}, "description": "Set webhook URL for event push notifications"},
				"clear-webhook":  map[string]interface{}{"args": []string{}, "description": "Clear the webhook URL"},
				// Low-level / plumbing
				"connect":    map[string]interface{}{"args": []string{"<address|hostname>", "[port]", "[--message <msg>]"}, "description": "Open a raw stream connection"},
				"send":       map[string]interface{}{"args": []string{"<address|hostname>", "<port>", "--data <msg>"}, "description": "Send a single raw message to a port"},
				"recv":       map[string]interface{}{"args": []string{"<port>", "[--count <n>]"}, "description": "Accept and print incoming stream messages"},
				"dgram":      map[string]interface{}{"args": []string{"<address|hostname>", "<port>", "--data <msg>"}, "description": "Send a UDP-style datagram"},
				"listen":     map[string]interface{}{"args": []string{"<port>", "[--count <n>]"}, "description": "Listen for incoming datagrams"},
				"broadcast":  map[string]interface{}{"args": []string{"<network_id>", "<message>"}, "description": "Broadcast a datagram to all network members"},
				// Connection management
				"connections": map[string]interface{}{"args": []string{}, "description": "List active daemon connections"},
				"disconnect":  map[string]interface{}{"args": []string{"<conn_id>"}, "description": "Close a connection by ID"},
				// Diagnostics
				"health":     map[string]interface{}{"args": []string{}, "description": "Compact health summary (subset of info)"},
				"peers":      map[string]interface{}{"args": []string{"[--search <query>]"}, "description": "List connected peers"},
				"traceroute": map[string]interface{}{"args": []string{"<address>"}, "description": "Trace path to a node"},
				"bench":      map[string]interface{}{"args": []string{"<address|hostname>", "[size_mb]"}, "description": "Throughput benchmark via echo port"},
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

func cmdExtrasHelp() {
	fmt.Println("pilotctl extras <command> [args...]")
	fmt.Println()
	fmt.Println("Operator and admin commands. Run 'pilotctl context' for the full list.")
	fmt.Println()
	fmt.Println("Network admin:  network delete/rename/promote/demote/kick/role/policy")
	fmt.Println("Policy engine:  policy get/set/validate/test")
	fmt.Println("Managed nets:   managed status/cycle/reconcile")
	fmt.Println("Member tags:    member-tags get/set")
	fmt.Println("Enterprise:     audit provision deprovision idp audit-export provision-status directory-sync directory-status")
	fmt.Println("Node config:    set-tags clear-tags clear-hostname set-webhook clear-webhook")
	fmt.Println("Low-level:      connect send recv dgram listen broadcast")
	fmt.Println("Connections:    connections disconnect")
	fmt.Println("Diagnostics:    health peers traceroute bench")
}

// ===================== DAEMON LIFECYCLE =====================

// findCompanionBinary locates a sibling binary distributed alongside
// pilotctl. Discovery order:
//
//  1. If $envVar is set, use that path verbatim.
//  2. Look next to the running pilotctl executable (os.Executable()).
//  3. Fall back to PATH lookup via exec.LookPath.
//
// Returns a clear error mentioning the env override and where pilotctl
// looked. This is the binary discovery contract for the daemon and
// gateway exec paths; it removes the need for cmd/pilotctl to import
// the L11 plugin packages and serve as a second composition root.
func findCompanionBinary(name, envVar string) (string, error) {
	if v := os.Getenv(envVar); v != "" {
		return v, nil
	}
	self, err := os.Executable()
	if err == nil {
		// Resolve symlinks so the sibling lookup follows e.g. Homebrew
		// shims. If EvalSymlinks fails we fall back to the raw path —
		// not fatal.
		if resolved, err2 := filepath.EvalSymlinks(self); err2 == nil {
			self = resolved
		}
		candidate := filepath.Join(filepath.Dir(self), name)
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate, nil
		}
	}
	if path, err := exec.LookPath(name); err == nil {
		return path, nil
	}
	siblingHint := ""
	if self != "" {
		siblingHint = fmt.Sprintf(" (expected sibling at %s)", filepath.Join(filepath.Dir(self), name))
	}
	return "", fmt.Errorf("%s not found%s or in PATH; set %s to override", name, siblingHint, envVar)
}

// daemonBinaryPath resolves the pilot-daemon binary.
func daemonBinaryPath() string {
	path, err := findCompanionBinary("pilot-daemon", "PILOT_DAEMON_BIN")
	if err != nil {
		fatalCode("internal", "%v", err)
	}
	return path
}

// gatewayBinaryPath resolves the pilot-gateway binary.
func gatewayBinaryPath() string {
	path, err := findCompanionBinary("pilot-gateway", "PILOT_GATEWAY_BIN")
	if err != nil {
		fatalCode("internal", "%v", err)
	}
	return path
}

// buildDaemonArgs translates pilotctl-style flags into pilot-daemon CLI
// args, applying defaults from ~/.pilot/config.json when CLI flags are
// unset. This keeps existing pilotctl invocations working unchanged —
// the only difference is that the daemon runs in a separate
// `pilot-daemon` process rather than re-execing pilotctl.
func buildDaemonArgs(args []string) (daemonArgs []string, socketPath string) {
	flags, _ := parseFlags(args)

	cfg := loadConfig()

	socketPath = flagString(flags, "socket", "")
	if socketPath == "" {
		socketPath = getSocket()
	}

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

	daemonArgs = []string{
		"--registry", registryAddr,
		"--beacon", beaconAddr,
		"--listen", listenAddr,
		"--socket", socketPath,
		"--identity", identityPath,
		"--log-level", logLevel,
		"--log-format", logFormat,
	}
	// pilot-daemon's encrypt flag defaults to true; pass `=false`
	// only when --no-encrypt was supplied.
	if !encrypt {
		daemonArgs = append(daemonArgs, "--encrypt=false")
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
	return daemonArgs, socketPath
}

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

	daemonArgs, socketPath := buildDaemonArgs(args)

	// Clean up stale socket
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

	daemonBin := daemonBinaryPath()

	// --foreground: replace the current process so signal/lifetime
	// handling matches what the user expects from systemd unit files
	// or shell wrappers.
	if flagBool(flags, "foreground") {
		// syscall.Exec needs argv[0] to be the binary name. Pass the
		// full env unchanged.
		execArgs := append([]string{daemonBin}, daemonArgs...)
		if err := syscall.Exec(daemonBin, execArgs, os.Environ()); err != nil {
			fatalCode("internal", "exec %s: %v", daemonBin, err)
		}
		return
	}

	// Fork: spawn the daemon detached, redirect output to the log
	// file, then poll the socket until the daemon is ready.
	os.MkdirAll(configDir(), 0700)
	logFile, err := os.OpenFile(logFilePath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		fatalCode("internal", "open log file: %v", err)
	}

	proc := exec.Command(daemonBin, daemonArgs...)
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

// runDaemonInternal handles the legacy `pilotctl _daemon-run` hidden
// subcommand, which earlier pilotctl builds used to exec themselves
// for the forked daemon process. The composition root has moved to
// cmd/daemon/main.go; this entry point now exec's pilot-daemon so old
// pilotctl-managed PID files (which point at a `pilotctl _daemon-run`
// process) keep working until the next daemon restart cycles them
// out. The `_daemon-run` flag set is identical to pilot-daemon's, so
// we forward args verbatim apart from translating --no-encrypt.
func runDaemonInternal(args []string) {
	translated := make([]string, 0, len(args))
	for _, a := range args {
		if a == "--no-encrypt" || a == "-no-encrypt" {
			translated = append(translated, "--encrypt=false")
			continue
		}
		translated = append(translated, a)
	}
	daemonBin := daemonBinaryPath()
	execArgs := append([]string{daemonBin}, translated...)
	if err := syscall.Exec(daemonBin, execArgs, os.Environ()); err != nil {
		fatalCode("internal", "exec %s: %v", daemonBin, err)
	}
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

// cmdGatewayStart exec's pilot-gateway in the foreground. The flags
// pilotctl already accepted (--subnet, --ports, plus positional
// addresses) map 1:1 onto pilot-gateway flags + the `run` subcommand,
// so we translate and replace the current process. The gateway runs
// as long as pilotctl's caller chooses; SIGINT/SIGTERM tear it down
// the same as before.
//
// The PID-file pattern from the in-process implementation is dropped:
// pilot-gateway is the canonical CLI for these operations and it
// already manages its own lifetime. `pilotctl gateway stop` now
// degrades to the documented "find and kill" path described in its
// help text.
func cmdGatewayStart(args []string) {
	flags, pos := parseFlags(args)

	subnet := flagString(flags, "subnet", "10.4.0.0/16")
	portsStr := flagString(flags, "ports", "")

	gwArgs := []string{"--socket", getSocket(), "--subnet", subnet}
	if portsStr != "" {
		gwArgs = append(gwArgs, "--ports", portsStr)
	}
	gwArgs = append(gwArgs, "run")
	gwArgs = append(gwArgs, pos...)

	gwBin := gatewayBinaryPath()
	execArgs := append([]string{gwBin}, gwArgs...)
	if err := syscall.Exec(gwBin, execArgs, os.Environ()); err != nil {
		fatalCode("internal", "exec %s: %v", gwBin, err)
	}
}

// cmdGatewayStop is now a thin wrapper. The previous in-process
// implementation tracked its own PID file; with pilot-gateway running
// as a separate process pilotctl can't reach into it without
// duplicating that bookkeeping. Surface a clear hint instead.
func cmdGatewayStop() {
	fatalHint("not_running",
		"send SIGTERM to the pilot-gateway process directly (e.g. pkill -TERM pilot-gateway)",
		"pilotctl no longer tracks the gateway process; run pilot-gateway directly")
}

// cmdGatewayMap exec's `pilot-gateway map`. This is a transient
// add-mapping path: pilot-gateway will spin up, register the mapping,
// and exit.
func cmdGatewayMap(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl gateway map <pilot-addr> [local-ip]")
	}
	gwBin := gatewayBinaryPath()
	gwArgs := []string{"--socket", getSocket(), "map"}
	gwArgs = append(gwArgs, args...)
	execArgs := append([]string{gwBin}, gwArgs...)
	if err := syscall.Exec(gwBin, execArgs, os.Environ()); err != nil {
		fatalCode("internal", "exec %s: %v", gwBin, err)
	}
}

// cmdGatewayUnmap is no longer routable from pilotctl: pilot-gateway
// owns its in-memory mapping table and there's no IPC for outside
// processes to mutate it. Emit a clear error pointing the caller at
// pilot-gateway directly.
func cmdGatewayUnmap(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl gateway unmap <local-ip>")
	}
	fatalHint("not_supported",
		"restart pilot-gateway without the mapping, or extend pilot-gateway with an unmap subcommand",
		"unmap is owned by the pilot-gateway process and has no remote control path")
}

// cmdGatewayList is no longer accurate from pilotctl: the in-process
// implementation only ever reported an empty list because it spun up
// a fresh gateway per call. Surface the architectural reality: the
// gateway process holds the mapping table.
func cmdGatewayList() {
	if jsonOutput {
		outputOK(map[string]interface{}{
			"mappings": []map[string]interface{}{},
			"total":    0,
			"note":     "mappings live inside the pilot-gateway process; run pilot-gateway with the desired mappings",
		})
		return
	}
	fmt.Println("no mappings")
	fmt.Println("note: mappings live inside the pilot-gateway process; run pilot-gateway with the desired mappings")
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
		fatalCode("invalid_argument", "usage: pilotctl lookup <node_id> [--show-endpoints]")
	}
	flags, pos := parseFlags(args)
	if len(pos) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl lookup <node_id> [--show-endpoints]")
	}
	showEndpoints := flagBool(flags, "show-endpoints")
	nodeID := parseNodeID(pos[0])
	rc := connectRegistry()
	defer rc.Close()
	resp, err := rc.Lookup(nodeID)
	if err != nil {
		fatalCode("connection_failed", "lookup: %v", err)
	}
	if !showEndpoints {
		redactPeerEndpoints(resp)
	}
	output(resp)
}

// redactPeerEndpoints walks a registry/daemon response and drops any
// IP-bearing fields. Operates in-place; safe to call on nil/non-map types.
// Removed keys: endpoint, real_addr, lan_addrs, public_addr, ip, addr.
// Recurses into nested maps and into peer_list / nodes / data sub-objects.
func redactPeerEndpoints(v interface{}) {
	switch x := v.(type) {
	case map[string]interface{}:
		for _, k := range []string{"endpoint", "real_addr", "lan_addrs", "public_addr", "stun_addr", "observed_addr"} {
			delete(x, k)
		}
		for _, vv := range x {
			redactPeerEndpoints(vv)
		}
	case []interface{}:
		for _, vv := range x {
			redactPeerEndpoints(vv)
		}
	}
}

func cmdRotateKey(args []string) {
	_ = args
	d := connectDriver()
	defer d.Close()
	resp, err := d.RotateKey()
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
	maybeAutoHandshake(d, target, flagBool(flags, "no-auto-handshake"))

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
			hint := classifyDaemonError(err)
			if hint == "" {
				hint = fmt.Sprintf("check that %s is reachable: pilotctl ping %s", target, target)
			}
			fatalHint("connection_failed", hint,
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
	maybeAutoHandshake(d, target, flagBool(flags, "no-auto-handshake"))
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

func cmdDgram(args []string) {
	flags, pos := parseFlags(args)
	if len(pos) < 2 {
		fatalCode("invalid_argument", "usage: pilotctl dgram <address|hostname> <port> --data <msg>")
	}

	d := connectDriver()
	defer d.Close()

	target, err := parseAddrOrHostname(d, pos[0])
	if err != nil {
		fatalCode("not_found", "%v", err)
	}
	maybeAutoHandshake(d, target, flagBool(flags, "no-auto-handshake"))
	p, err := strconv.ParseUint(pos[1], 10, 16)
	if err != nil {
		fatalCode("invalid_argument", "invalid port %q: %v", pos[1], err)
	}
	port := uint16(p)

	data := flagString(flags, "data", "")
	if data == "" {
		fatalCode("invalid_argument", "--data is required")
	}

	if err := d.SendTo(target, port, []byte(data)); err != nil {
		fatalCode("connection_failed", "sendto: %v", err)
	}

	if jsonOutput {
		outputOK(map[string]interface{}{
			"target": target.String(),
			"port":   port,
			"bytes":  len(data),
		})
	} else {
		fmt.Printf("sent %d byte(s) to %s port %d\n", len(data), target, port)
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

	// Auto-handshake to peers in the embedded trusted-agents list.
	// Best-effort: warns on stderr and continues if handshake fails.
	// (send-file uses positional args — no flag map; pass false.)
	maybeAutoHandshake(d, target, false)

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

	// Reject files that would exceed the data-exchange frame cap before
	// opening the connection — keeps the failure path clean and avoids
	// streaming a quarter-gigabyte just to have the receiver close.
	if len(data) > dataexchange.MaxFrameSize {
		fatalCode("invalid_argument",
			"file too large: %d bytes (max %d)", len(data), dataexchange.MaxFrameSize)
	}

	filename := filepath.Base(filePath)

	client, err := dataexchange.Dial(d, target)
	if err != nil {
		hint := classifyDaemonError(err)
		if hint == "" {
			hint = fmt.Sprintf("check that %s is reachable: pilotctl ping %s", target, target)
		}
		fatalHint("connection_failed", hint,
			"cannot connect to %s (data exchange port %d)", target, protocol.PortDataExchange)
	}
	defer client.Close()

	if err := client.SendFile(filename, data); err != nil {
		fatalCode("connection_failed", "send failed: %v", err)
	}

	// Read ACK
	ack, err := client.Recv()
	if err != nil {
		// Sender wrote all bytes but never got the receiver's ACK back
		// (likely receiver crashed or restarted mid-transfer). That's
		// not a silent success — surface as a loud error so callers
		// don't mistake it for full delivery.
		fatalCode("connection_failed",
			"send wrote all bytes but no ACK from receiver: %v", err)
	}

	result := map[string]interface{}{
		"filename":    filename,
		"bytes":       len(data),
		"destination": target.String(),
	}
	if ack != nil {
		ackText := string(ack.Payload)
		result["ack"] = ackText
		// Receiver-side errors arrive as a TEXT frame whose body starts
		// with "ERR " — surface them as a real failure instead of
		// claiming success (e.g. disk-full, save permission denied).
		if strings.HasPrefix(ackText, "ERR ") {
			fatalCode("internal", "receiver rejected file: %s", ackText)
		}
	}
	outputOK(result)
}

func cmdSendMessage(args []string) {
	flags, pos := parseFlags(args)
	if len(pos) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl send-message <address|hostname> --data <text> [--type text|json|binary] [--trace]")
	}

	// --trace (or PILOTCTL_TRACE_TIME=1) prints per-step timings to stderr:
	// IPC connect, hostname resolve, auto-handshake, dial, send, ACK recv.
	traceTime := os.Getenv("PILOTCTL_TRACE_TIME") != "" || flagBool(flags, "trace")
	t0 := time.Now()
	tracef := func(label string) {
		if traceTime {
			fmt.Fprintf(os.Stderr, "TRACE %-22s %12.3fms\n", label, float64(time.Since(t0).Microseconds())/1000.0)
		}
	}

	d := connectDriver()
	tracef("connectDriver")
	defer d.Close()

	target, err := parseAddrOrHostname(d, pos[0])
	tracef("parseAddrOrHostname")
	if err != nil {
		fatalCode("not_found", "%v", err)
	}

	data := flagString(flags, "data", "")
	if data == "" {
		fatalCode("invalid_argument", "--data is required")
	}
	msgType := flagString(flags, "type", "text")

	// Auto-handshake to peers in the embedded trusted-agents list.
	// Best-effort: warns on stderr and continues if handshake fails.
	maybeAutoHandshake(d, target, flagBool(flags, "no-auto-handshake"))
	tracef("maybeAutoHandshake")

	client, err := dataexchange.Dial(d, target)
	tracef("dataexchange.Dial")
	if err != nil {
		hint := classifyDaemonError(err)
		if hint == "" {
			hint = fmt.Sprintf("check that %s is reachable: pilotctl ping %s", target, target)
		}
		fatalHint("connection_failed", hint,
			"cannot connect to %s (data exchange port %d)", target, protocol.PortDataExchange)
	}
	defer client.Close()

	innerType := map[string]uint32{
		"text":   dataexchange.TypeText,
		"json":   dataexchange.TypeJSON,
		"binary": dataexchange.TypeBinary,
	}[msgType]
	if innerType == 0 && msgType != "text" {
		fatalCode("invalid_argument", "unknown type %q (use text, json, or binary)", msgType)
	}

	var sentAtNs int64
	var sendErr error
	if traceTime {
		// TypeTrace frame embeds sent_at_ns; receiver echoes back full timing.
		sentAtNs, sendErr = client.SendTrace(innerType, []byte(data))
	} else {
		sendStart := time.Now()
		switch msgType {
		case "text":
			sendErr = client.SendText(data)
		case "json":
			sendErr = client.SendJSON([]byte(data))
		case "binary":
			sendErr = client.SendBinary([]byte(data))
		}
		sentAtNs = sendStart.UnixNano()
	}
	tracef("client.Send")
	if sendErr != nil {
		fatalCode("connection_failed", "send: %v", sendErr)
	}

	// Read ACK
	ack, err := client.Recv()
	ackRecvAtNs := time.Now().UnixNano()
	tracef("client.Recv")
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
	if traceTime {
		result["total_ms"] = float64(time.Duration(ackRecvAtNs-sentAtNs).Microseconds()) / 1000.0
		// Parse timing fields from the TypeJSON ACK if present.
		if ack != nil && ack.Type == dataexchange.TypeJSON {
			var timing map[string]interface{}
			if json.Unmarshal(ack.Payload, &timing) == nil {
				ns := func(key string) int64 {
					if v, ok := timing[key].(float64); ok {
						return int64(v)
					}
					return 0
				}
				recvNs := ns("received_at_ns")
				inboxNs := ns("inbox_written_at_ns")
				ackSentNs := ns("ack_sent_at_ns")
				if recvNs > 0 {
					result["to_receiver_ms"] = float64(time.Duration(recvNs-sentAtNs).Microseconds()) / 1000.0
					result["receiver_process_ms"] = float64(time.Duration(inboxNs-recvNs).Microseconds()) / 1000.0
					result["return_trip_ms"] = float64(time.Duration(ackRecvAtNs-ackSentNs).Microseconds()) / 1000.0
					result["inner_ack"] = timing["inner_ack"]
				}
			}
		}
	}
	outputOK(result)
	tracef("outputOK")
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
	maybeAutoHandshake(d, target, flagBool(flags, "no-auto-handshake"))

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
	maybeAutoHandshake(d, target, flagBool(flags, "no-auto-handshake"))

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
		peerWinStr := "—"
		if peerWin >= 0 {
			peerWinStr = formatBytes(uint64(peerWin))
		}
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
			peerWinStr,
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

func cmdInfo(args []string) {
	flags, _ := parseFlags(args)
	showEndpoints := flagBool(flags, "show-endpoints")

	d := connectDriver()
	defer d.Close()

	info, err := d.Info()
	if err != nil {
		fatalCode("connection_failed", "info: %v", err)
	}

	// Privacy: strip per-peer endpoints + STUN-discovered own addresses
	// from the JSON dump unless the operator explicitly opts in via
	// --show-endpoints. The summary counters (peers, encrypted_peers)
	// stay; only the IP-bearing fields are redacted.
	if !showEndpoints {
		redactPeerEndpoints(info)
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
		// Tag synthetic emails so users (and agents inspecting the output)
		// can tell at a glance whether this node has a real identity.
		// Synthetic emails are auto-derived from the public-key fingerprint
		// and end with @nodes.pilotprotocol.network. To replace one, run
		// `pilotctl set-email <your-real-address>`.
		if strings.HasSuffix(email, "@nodes.pilotprotocol.network") {
			fmt.Printf("  Email:       %s  (auto-generated; optional — `pilotctl set-email <addr>` to set your own)\n", email)
		} else {
			fmt.Printf("  Email:       %s\n", email)
		}
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

	printSkillInstallSummary()

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
	// Privacy default: peer real IPs are hidden. Opt in with --show-endpoints
	// (ops/debug only). Search by node_id always works; search by endpoint
	// fragment only works when endpoints are visible.
	showEndpoints := flagBool(flags, "show-endpoints")

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
		match := strings.Contains(nodeIDStr, searchLower)
		if !match && showEndpoints {
			// only consult endpoint when the user has explicitly asked
			// to see it; never let a search prompt leak IP existence.
			endpoint, _ := peer["endpoint"].(string)
			match = strings.Contains(strings.ToLower(endpoint), searchLower)
		}
		if match {
			filtered = append(filtered, p)
		}
	}

	// Redact endpoint unless the operator opted in.
	if !showEndpoints {
		redacted := make([]interface{}, 0, len(filtered))
		for _, p := range filtered {
			peer, _ := p.(map[string]interface{})
			if peer == nil {
				continue
			}
			cp := make(map[string]interface{}, len(peer))
			for k, v := range peer {
				if k == "endpoint" || k == "real_addr" || k == "lan_addrs" || k == "public_addr" {
					continue
				}
				cp[k] = v
			}
			redacted = append(redacted, cp)
		}
		filtered = redacted
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
	if showEndpoints {
		fmt.Printf("%-10s  %-30s  %-20s  %s\n", "NODE ID", "ENDPOINT", "ENCRYPTED", "AUTH")
	} else {
		fmt.Printf("%-10s  %-20s  %s\n", "NODE ID", "ENCRYPTED", "AUTH")
	}
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
		if showEndpoints {
			fmt.Printf("%-10d  %-30s  %-20s  %s\n", int(peer["node_id"].(float64)), peer["endpoint"], encStr, authStr)
		} else {
			fmt.Printf("%-10d  %-20s  %s\n", int(peer["node_id"].(float64)), encStr, authStr)
		}
	}
}

func cmdPing(args []string) {
	flags, pos := parseFlags(args)
	if len(pos) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl ping <address|hostname> [--count <n>] [--timeout <dur>] [--trace]")
	}

	count := flagInt(flags, "count", 4)
	timeout := flagDuration(flags, "timeout", 30*time.Second)

	// --trace (or PILOTCTL_TRACE_TIME=1) prints per-step timing to stderr:
	// startup overhead, IPC connect, hostname lookup, and per-packet
	// dial/echo split so you can see where latency actually lives.
	traceTime := os.Getenv("PILOTCTL_TRACE_TIME") != "" || flagBool(flags, "trace")
	t0 := time.Now()
	tracef := func(label string) {
		if traceTime {
			fmt.Fprintf(os.Stderr, "TRACE %-22s %12.3fms\n", label, float64(time.Since(t0).Microseconds())/1000.0)
		}
	}

	d := connectDriver()
	tracef("connectDriver")
	defer d.Close()

	target, err := parseAddrOrHostname(d, pos[0])
	tracef("parseAddrOrHostname")
	if err != nil {
		fatalCode("not_found", "%v", err)
	}
	maybeAutoHandshake(d, target, flagBool(flags, "no-auto-handshake"))
	tracef("maybeAutoHandshake")

	if !jsonOutput {
		fmt.Printf("PING %s\n", target)
	}

	var results []map[string]interface{}
	overall := time.NewTimer(timeout)
	defer overall.Stop()
	// Per-attempt budget so a single dial against a ghost peer cannot
	// blow past the user's --timeout. Split evenly across remaining count
	// with a 10s floor so legitimate cold-start handshakes have room
	// even when the daemon is in the post-restart "trust resync +
	// inbound key-exchange storm" window: 7+ trusted peers can be
	// concurrently establishing crypto state for ~30-60 s after a
	// fresh start, and the dial's encrypted-SYN write competes with
	// those handlers for the relay socket. The previous 4 s floor
	// occasionally expired mid-handshake on the first ping after
	// startup; 10 s covers it without making bad dials feel sluggish.
	perAttempt := timeout / time.Duration(count)
	if perAttempt < 10*time.Second {
		perAttempt = 10 * time.Second
	}

	for i := 0; i < count; i++ {
		select {
		case <-overall.C:
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
		// Bound DialAddr by perAttempt — a goroutine + timer cap is the
		// minimum-invasive way without plumbing context through Driver.
		type dialResult struct {
			conn *driver.Conn
			err  error
		}
		ch := make(chan dialResult, 1)
		go func() {
			c, e := d.DialAddr(target, protocol.PortEcho)
			ch <- dialResult{c, e}
		}()
		var conn *driver.Conn
		select {
		case dr := <-ch:
			conn, err = dr.conn, dr.err
		case <-time.After(perAttempt):
			err = fmt.Errorf("dial timeout after %s", perAttempt)
			conn = nil
			// Drain the goroutine asynchronously so it doesn't leak FDs;
			// the daemon-side dial will eventually fail.
			go func() {
				if dr := <-ch; dr.conn != nil {
					dr.conn.Close()
				}
			}()
		}
		dialElapsed := time.Since(start)
		if err != nil {
			r := map[string]interface{}{"seq": i, "error": err.Error()}
			results = append(results, r)
			if !jsonOutput {
				fmt.Printf("seq=%d error: %v\n", i, err)
			}
			time.Sleep(time.Second)
			continue
		}

		// Build payload. In trace mode embed [TRCE][8-byte sent_at_ns] so the
		// echo service can stamp its receive time and reflect it back.
		var pktPayload []byte
		var sentAtNs int64
		if traceTime {
			pktPayload = make([]byte, 12)
			copy(pktPayload[0:4], "TRCE")
			sentAtNs = time.Now().UnixNano()
			binary.BigEndian.PutUint64(pktPayload[4:12], uint64(sentAtNs))
		} else {
			pktPayload = []byte(fmt.Sprintf("ping-%d", i))
		}

		echoStart := time.Now()
		conn.Write(pktPayload)

		conn.SetReadDeadline(time.Now().Add(perAttempt))
		buf := make([]byte, 1024)
		n, readErr := conn.Read(buf)
		recvAtNs := time.Now().UnixNano()
		conn.Close()
		echoElapsed := time.Since(echoStart)

		rtt := time.Since(start)
		r := map[string]interface{}{
			"seq":    i,
			"rtt_ms": float64(rtt.Microseconds()) / 1000.0,
		}
		if traceTime {
			r["dial_ms"] = float64(dialElapsed.Microseconds()) / 1000.0
			r["echo_ms"] = float64(echoElapsed.Microseconds()) / 1000.0
		}
		err = readErr
		if err != nil {
			r["error"] = err.Error()
			if !jsonOutput {
				fmt.Printf("seq=%d error: %v\n", i, err)
			}
		} else {
			r["bytes"] = n
			// Parse TRCE response: [TRCE][sent_at_ns][server_recv_at_ns]
			var serverRecvNs int64
			if traceTime && n >= 20 && string(buf[0:4]) == "TRCE" {
				serverRecvNs = int64(binary.BigEndian.Uint64(buf[12:20]))
				toServer := time.Duration(serverRecvNs - sentAtNs)
				fromServer := time.Duration(recvAtNs - serverRecvNs)
				r["to_server_ms"] = float64(toServer.Microseconds()) / 1000.0
				r["from_server_ms"] = float64(fromServer.Microseconds()) / 1000.0
			}
			if !jsonOutput {
				if traceTime && serverRecvNs > 0 {
					toServer := time.Duration(serverRecvNs - sentAtNs)
					fromServer := time.Duration(recvAtNs - serverRecvNs)
					fmt.Printf("seq=%d bytes=%d time=%v  [dial=%v →srv=%v ←srv=%v]\n",
						i, n, rtt,
						dialElapsed.Round(time.Microsecond),
						toServer.Round(time.Microsecond),
						fromServer.Round(time.Microsecond))
				} else if traceTime {
					fmt.Printf("seq=%d bytes=%d time=%v  [dial=%v echo=%v]\n", i, n, rtt, dialElapsed.Round(time.Microsecond), echoElapsed.Round(time.Microsecond))
				} else {
					fmt.Printf("seq=%d bytes=%d time=%v\n", i, n, rtt)
				}
			}
		}
		results = append(results, r)

		if i < count-1 {
			time.Sleep(time.Second)
		}
	}

	// Exit non-zero if every attempt failed (rc lets shell scripts
	// distinguish "ping worked" from "all attempts failed under
	// partition").
	allFailed := len(results) > 0
	for _, r := range results {
		if _, hasErr := r["error"]; !hasErr {
			allFailed = false
			break
		}
	}
	if jsonOutput {
		output(map[string]interface{}{
			"target":  target.String(),
			"results": results,
			"timeout": false,
		})
	}
	if allFailed {
		os.Exit(1)
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
	maybeAutoHandshake(d, target, flagBool(flags, "no-auto-handshake"))

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
	flags, positional := parseFlags(args)
	if len(positional) < 2 {
		fatalCode("usage", "usage: pilotctl broadcast <network_id> <message> [--port <port>]")
	}
	netID64, err := strconv.ParseUint(positional[0], 10, 16)
	if err != nil {
		fatalCode("usage", "invalid network_id: %v", err)
	}
	netID := uint16(netID64)
	message := positional[1]

	port := uint16(1000)
	if v := flagString(flags, "port", ""); v != "" {
		p, err := strconv.ParseUint(v, 10, 16)
		if err != nil {
			fatalCode("usage", "invalid --port: %v", err)
		}
		port = uint16(p)
	}

	token := requireAdminToken()

	d := connectDriver()
	defer d.Close()

	if err := d.Broadcast(netID, port, []byte(message), token); err != nil {
		fatalCode("broadcast_failed", "%v", err)
	}

	if jsonOutput {
		output(map[string]interface{}{
			"network_id": netID,
			"port":       port,
			"bytes":      len(message),
		})
	} else {
		fmt.Printf("broadcast on network %d port %d (%d bytes)\n", netID, port, len(message))
	}
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
	traceTime := flagBool(flags, "trace")

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

	// Inbox filenames are {type}-{ts-ms}-{seq}.json. Plain alpha order
	// groups by type (binary<json<text), which inverts chronological order
	// whenever message types are mixed. Sort by the timestamp+seq portion
	// so the display order matches the receive order.
	sort.Slice(entries, func(i, j int) bool {
		ni := entries[i].Name()
		nj := entries[j].Name()
		di := strings.Index(ni, "-")
		dj := strings.Index(nj, "-")
		if di < 0 || dj < 0 {
			return ni < nj
		}
		return ni[di:] < nj[dj:]
	})

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
	now := time.Now()
	for _, m := range messages {
		msgType, _ := m["type"].(string)
		from, _ := m["from"].(string)
		ts, _ := m["received_at"].(string)
		data, _ := m["data"].(string)
		bytes, _ := m["bytes"].(float64)

		var tsLine string
		if traceTime {
			t, err := time.Parse(time.RFC3339Nano, ts)
			if err == nil {
				ago := now.Sub(t)
				tsLine = fmt.Sprintf("%s  (%s ago, %d bytes)", ts, fmtDuration(ago), int(bytes))
			} else {
				tsLine = ts
			}
		} else {
			tsLine = ts
		}

		preview := data
		if len(preview) > 80 {
			preview = preview[:80] + "..."
		}
		fmt.Printf("  [%s] from %s type=%s\n", tsLine, from, msgType)
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
	// Member counts are admin-only at the registry. Without admin_token
	// the registry omits the `members` field; render "—" so the column
	// stays aligned and it's clear the count is hidden by policy rather
	// than broken.
	fmt.Printf("%-8s %-30s %-10s %s\n", "ID", "NAME", "JOIN RULE", "MEMBERS")
	for _, n := range nets {
		nm, _ := n.(map[string]interface{})
		id := uint16(nm["id"].(float64))
		name, _ := nm["name"].(string)
		rule, _ := nm["join_rule"].(string)
		memberStr := "—"
		if members, ok := nm["members"].([]interface{}); ok {
			memberStr = fmt.Sprintf("%d", len(members))
		} else if mc, ok := nm["members"].(float64); ok {
			memberStr = fmt.Sprintf("%d", int(mc))
		}
		fmt.Printf("%-8d %-30s %-10s %s\n", id, name, rule, memberStr)
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

func cmdDeprovision(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl deprovision <network-name>")
	}
	name := args[0]
	adminToken := requireAdminToken()

	rc := connectRegistry()
	defer rc.Close()

	// Look up network by name
	resp, err := rc.ListNetworks()
	if err != nil {
		fatalCode("connection_failed", "list networks: %v", err)
	}
	nets, _ := resp["networks"].([]interface{})
	var netID uint16
	found := false
	for _, n := range nets {
		nm, _ := n.(map[string]interface{})
		nname, _ := nm["name"].(string)
		if nname == name {
			netID = uint16(nm["id"].(float64))
			found = true
			break
		}
	}
	if !found {
		fatalCode("not_found", "network %q not found", name)
	}

	delResp, err := rc.DeleteNetwork(netID, adminToken)
	if err != nil {
		fatalCode("connection_failed", "delete network %q (id=%d): %v", name, netID, err)
	}
	if jsonOutput {
		output(delResp)
		return
	}
	fmt.Printf("deprovisioned network %q (id=%d)\n", name, netID)
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

func cmdManagedReconcile(args []string) {
	flags, _ := parseFlags(args)
	netID := uint16(flagInt(flags, "net", 0))
	if netID == 0 {
		fatalCode("invalid_argument", "usage: pilotctl managed reconcile --net <id>")
	}

	d := connectDriver()
	defer d.Close()

	resp, err := d.ManagedReconcile(netID)
	if err != nil {
		fatalCode("connection_failed", "managed reconcile: %v", err)
	}
	if jsonOutput {
		output(resp)
	} else {
		fmt.Printf("reconciled: peers=%v\n", resp["peers"])
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
	doc, err := policylang.Parse(policyJSON)
	if err != nil {
		fatalCode("invalid_argument", "policy validation: %v", err)
	}
	if _, err := policylang.Compile(doc); err != nil {
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

	doc, err := policylang.Parse(policyJSON)
	if err != nil {
		fatalCode("invalid_argument", "validation failed: %v", err)
	}

	cp, err := policylang.Compile(doc)
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

	doc, err := policylang.Parse(policyJSON)
	if err != nil {
		fatalCode("invalid_argument", "policy: %v", err)
	}
	cp, err := policylang.Compile(doc)
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

	dirs, err := cp.Evaluate(policylang.EventType(eventType), event)
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

func countEventTypes(cp *policylang.CompiledPolicy) map[string]bool {
	events := map[string]bool{}
	for _, et := range []policylang.EventType{
		policylang.EventConnect, policylang.EventDial, policylang.EventDatagram,
		policylang.EventCycle, policylang.EventJoin, policylang.EventLeave,
	} {
		if cp.HasRulesFor(et) {
			events[string(et)] = true
		}
	}
	return events
}

func directiveTypeName(dt policylang.DirectiveType) string {
	switch dt {
	case policylang.DirectiveAllow:
		return "allow"
	case policylang.DirectiveDeny:
		return "deny"
	case policylang.DirectiveTag:
		return "tag"
	case policylang.DirectiveEvict:
		return "evict"
	case policylang.DirectiveEvictWhere:
		return "evict_where"
	case policylang.DirectivePrune:
		return "prune"
	case policylang.DirectiveFill:
		return "fill"
	case policylang.DirectiveWebhook:
		return "webhook"
	case policylang.DirectiveLog:
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
