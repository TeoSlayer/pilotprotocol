# pilotctl Reference

> **Auto-generated** from `pilotctl --help`. Do not edit by hand — CI regenerates
> on every PR via `scripts/gen-cli-reference.sh` and fails if the committed copy
> differs from a fresh `pilotctl --help` capture (PILOT-54).
>
> Source: [`cmd/pilotctl/main.go`](../cmd/pilotctl/main.go).

```text
pilotctl — Pilot Protocol CLI

Global flags:
  --json                        Output structured JSON (for agent/programmatic use)

Getting started:
  pilotctl quickstart             3-command getting-started flow

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
  pilotctl send-message <address|hostname> --data <text> [--type text|json|binary] [--count <n>] [--reuse-conn] [--wait <dur>]
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
  pilotctl peers [--search <query>]
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
```
