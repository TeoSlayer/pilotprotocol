# Docs Audit — pilotctl Command Compliance

This file records every non-compliant CLI example found across formal docs and blog posts as of 2026-05-02. Items are grouped by severity, then by file. Use the checkboxes to track remediation progress.

Severity legend:
- 🔴 **Critical** — command does not exist or will fail at runtime
- 🟡 **Warning** — command exists but uses stale/renamed syntax
- 🔵 **Info** — minor inconsistency (version string, cosmetic wording)

---

## Formal Docs (`web/src/pages/docs/`)

These are high priority because they affect first-time user discoverability and are linked from the main navigation.

### `plain/docs/trust.astro`

- [ ] 🔴 **Critical** — `pilotctl trusts` → should be `pilotctl trust`
- [ ] 🟡 **Warning** — `pilotctl status` → should be `pilotctl daemon status` or `pilotctl info`

### `diagnostics.astro`

- [ ] 🔴 **Critical** — `pilotctl bench other-agent 50 --timeout 120s` → `--timeout` flag does not exist; correct syntax is `pilotctl bench <addr> [size_mb]`

### `go-sdk.astro`

- [ ] 🔵 **Info** — `SetTags` documented as "max 10 tags" → inconsistent with `cli-reference.astro` (max 3) and `python-sdk` docs (max 3); one source is wrong

### `tags.astro`

- [ ] 🔴 **Critical** — "Maximum 10 tags per node" → `cli-reference.astro` and python-sdk both say max 3; resolve the discrepancy
- [ ] 🔴 **Critical** — Python example shows `import pilot` and `pilot.Client()` → correct import is `from pilotprotocol import Driver`
- [ ] 🟡 **Warning** — `pilotctl set-tags` shown as a top-level command → must be `pilotctl extras set-tags`

### `integration.astro`

- [ ] 🟡 **Warning** — Docker example uses `FROM golang:1.21-alpine` → should be `golang:1.25` (current project requirement)

### `configuration.astro`

- [ ] 🔵 **Info** — Missing env vars table entries: `PILOT_HOME`, `PILOT_EMAIL`, `PILOT_RC` — all three are referenced in other docs and blog posts but absent from the configuration reference

### `cli-reference.astro`

- [ ] 🔴 **Critical** — `ai` command listed → not implemented; falls through to "unknown command" error
- [ ] 🔴 **Critical** — `clawdit` command listed → not implemented; falls through to "unknown command" error
- [ ] 🔴 **Critical** — `scriptorium` command listed → not implemented; falls through to "unknown command" error

### `tasks.astro`

- [ ] 🟡 **Warning** — `pilotctl enable-tasks` → should be `pilotctl extras enable-tasks`
- [ ] 🟡 **Warning** — `pilotctl disable-tasks` → should be `pilotctl extras disable-tasks`
- [ ] 🟡 **Warning** — `pilotctl task submit` (and other `task` subcommands) → should be `pilotctl extras task submit`

### `gateway.astro`

- [ ] 🟡 **Warning** — `pilotctl gateway start` / `pilotctl gateway stop` → should be `pilotctl extras gateway start` / `pilotctl extras gateway stop` (or the `pilot-gateway` binary)

---

## Blog Posts — By Pattern

These are lower priority than formal docs but affect SEO content and reader trust. Items are grouped by the recurring pattern rather than individual files to make bulk-fix easier.

---

### Pattern 1 — Old trust commands 🟡 Warning

| What the blog says | What it should say |
|---|---|
| `pilotctl trust <addr>` | `pilotctl handshake <addr>` |
| `pilotctl revoke <addr>` | `pilotctl untrust <addr>` |
| `pilotctl trust request ... --justification/--reason "..."` | `pilotctl handshake <addr> "justification"` |
| `pilotctl trust approve <addr>` | `pilotctl approve <node_id>` |
| `pilotctl trust list-pending` | `pilotctl pending` |
| `pilotctl trust add <hostname>` | `pilotctl handshake <hostname>` |
| `pilotctl trust remove <hostname>` | `pilotctl untrust <hostname>` |

Affected files:

- [ ] 🟡 `why-autonomous-agents-need-private-discovery.astro`
- [ ] 🟡 `cross-company-agent-collaboration-without-shared-infrastructure.astro`
- [ ] 🟡 `distributed-rag-without-central-knowledge-base.astro`
- [ ] 🟡 `claude-agent-teams-over-pilot.astro`
- [ ] 🟡 `clawhub-to-live-network-openclaw-discovery.astro`
- [ ] 🟡 `connect-agents-across-aws-gcp-azure-without-vpn.astro`
- [ ] 🟡 `federated-learning-p2p-communication.astro`
- [ ] 🟡 `hipaa-compliant-agent-communication.astro`
- [ ] 🟡 `peer-to-peer-agent-communication-no-server.astro`
- [ ] 🟡 `contributing-codebase-tour.astro`
- [ ] 🟡 `connecting-mcp-servers-across-agents.astro`
- [ ] 🟡 `building-custom-pilot-skills-openclaw.astro`
- [ ] 🟡 `secure-research-collaboration-share-models-not-data.astro`
- [ ] 🟡 `secure-ai-agent-communication-zero-trust.astro`

---

### Pattern 2 — Old discovery / lookup commands 🟡 Warning

| What the blog says | What it should say |
|---|---|
| `pilotctl resolve <addr>` | `pilotctl lookup <addr>` |
| `pilotctl search --tag X` | `pilotctl peers --search "X"` |
| `pilotctl find-by-tag X` | `pilotctl peers --search "X"` |
| `pilotctl discover --tag X` | `pilotctl peers --search "X"` |
| `pilotctl status [--json]` | `pilotctl daemon status` or `pilotctl info` |

Affected files:

- [ ] 🟡 `why-autonomous-agents-need-private-discovery.astro`
- [ ] 🟡 `clawhub-to-live-network-openclaw-discovery.astro`
- [ ] 🟡 `openclaw-task-delegation-polo-reputation.astro`
- [ ] 🟡 `openclaw-meets-pilot-agent-networking-one-command.astro`
- [ ] 🟡 `build-agent-swarm-self-organizes.astro`
- [ ] 🟡 `how-626-agents-autonomously-adopted-pilot.astro`
- [ ] 🟡 `connect-agents-across-aws-gcp-azure-without-vpn.astro`
- [ ] 🟡 `federated-learning-p2p-communication.astro`
- [ ] 🟡 `chain-ai-models-across-machines.astro`
- [ ] 🟡 `lightweight-swarm-communication-drones-robots.astro`
- [ ] 🟡 `building-custom-pilot-skills-openclaw.astro`
- [ ] 🟡 `openclaw-agents-behind-nat-zero-config.astro`
- [ ] 🟡 `peer-to-peer-agent-communication-no-server.astro`
- [ ] 🟡 `preferential-attachment-ai-networks-trust-graph.astro`
- [ ] 🟡 `build-openclaw-agent-self-organizes-pilot.astro`

---

### Pattern 3 — Old event pub/sub (missing address argument) 🔴 Critical

| What the blog says | What it should say |
|---|---|
| `pilotctl events publish --topic "X" --data "Y"` | `pilotctl publish <addr> <topic> --data "Y"` |
| `pilotctl events subscribe --topic "X"` | `pilotctl subscribe <addr> <topic>` |
| `pilotctl subscribe "topic"` (no address) | `pilotctl subscribe <addr> <topic>` |
| `pilotctl publish "topic" "data"` (no address) | `pilotctl publish <addr> <topic> --data "data"` |

Affected files:

- [ ] 🔴 `multi-agent-pipelines-openclaw-encrypted-tunnels.astro`
- [ ] 🔴 `claude-agent-teams-over-pilot.astro`
- [ ] 🔴 `scaling-openclaw-fleets-thousands-agents.astro`
- [ ] 🔴 `mcp-plus-pilot-tools-and-network.astro`
- [ ] 🔴 `replace-webhooks-with-persistent-agent-tunnels.astro`
- [ ] 🔴 `move-beyond-rest-persistent-connections-for-agents.astro`
- [ ] 🔴 `replace-message-broker-twelve-lines-go.astro`
- [ ] 🔴 `distributed-monitoring-without-prometheus.astro`
- [ ] 🔴 `build-multi-agent-network-five-minutes.astro`
- [ ] 🔴 `secure-research-collaboration-share-models-not-data.astro`

---

### Pattern 4 — Old data transfer syntax 🔴 Critical

| What the blog says | What it should say |
|---|---|
| `pilotctl data send <addr> <file>` | `pilotctl send-file <addr> <filepath>` |
| `pilotctl send <addr> "message"` (bare string) | `pilotctl send <addr> <port> --data "message"` |
| `pilotctl send <addr> --file <file>` | `pilotctl send-file <addr> <filepath>` |

Affected files:

- [ ] 🔴 `multi-agent-pipelines-openclaw-encrypted-tunnels.astro`
- [ ] 🔴 `claude-agent-teams-over-pilot.astro`
- [ ] 🔴 `build-multi-agent-network-five-minutes.astro`
- [ ] 🔴 `how-ai-agents-discover-each-other.astro`
- [ ] 🔴 `connect-agents-across-aws-gcp-azure-without-vpn.astro`
- [ ] 🔴 `secure-ai-agent-communication-zero-trust.astro`
- [ ] 🔴 `openclaw-agents-behind-nat-zero-config.astro`
- [ ] 🔴 `building-custom-pilot-skills-openclaw.astro`

---

### Pattern 5 — Old network join syntax 🟡 Warning

| What the blog says | What it should say |
|---|---|
| `pilotctl join 1` | `pilotctl network join 1` |
| `pilotctl join --network 1` | `pilotctl network join 1` |

Affected files:

- [ ] 🟡 `cross-company-agent-collaboration-without-shared-infrastructure.astro`
- [ ] 🟡 `chain-ai-models-across-machines.astro`
- [ ] 🟡 `lightweight-swarm-communication-drones-robots.astro`
- [ ] 🟡 `replace-webhooks-with-persistent-agent-tunnels.astro`
- [ ] 🟡 `connect-agents-across-aws-gcp-azure-without-vpn.astro`
- [ ] 🟡 `federated-learning-p2p-communication.astro`
- [ ] 🟡 `hipaa-compliant-agent-communication.astro`

---

### Pattern 6 — Old tag management and visibility commands 🟡 Warning

| What the blog says | What it should say |
|---|---|
| `pilotctl tag add <tags>` | `pilotctl extras set-tags <tags>` |
| `pilotctl tags set <tags>` | `pilotctl extras set-tags <tags>` |
| `pilotctl set-tags <tags>` (top-level) | `pilotctl extras set-tags <tags>` |
| `pilotctl set-visibility public` | `pilotctl set-public` |
| `pilotctl set-visibility private` | `pilotctl set-private` |

Affected files:

- [ ] 🟡 `clawhub-to-live-network-openclaw-discovery.astro`
- [ ] 🟡 `build-openclaw-agent-self-organizes-pilot.astro`
- [ ] 🟡 `openclaw-meets-pilot-agent-networking-one-command.astro`
- [ ] 🟡 `connect-agents-across-aws-gcp-azure-without-vpn.astro`
- [ ] 🟡 `build-ai-agent-marketplace-discovery-reputation.astro`
- [ ] 🟡 `why-autonomous-agents-need-private-discovery.astro`
- [ ] 🟡 `private-agent-network-company.astro`
- [ ] 🟡 `secure-research-collaboration-share-models-not-data.astro`

---

### Pattern 7 — Stale install method 🟡 Warning

| What the blog says | What it should say |
|---|---|
| `go install github.com/TeoSlayer/pilotprotocol/cmd/pilotctl@latest` | `curl -fsSL https://pilotprotocol.network/install.sh \| sh` |
| `go install .../cmd/pilot-daemon@latest` | `curl -fsSL https://pilotprotocol.network/install.sh \| sh` |

Affected files:

- [ ] 🟡 `build-multi-agent-network-five-minutes.astro`
- [ ] 🟡 `build-openclaw-agent-self-organizes-pilot.astro` (also uses `cmd/pilot-daemon`)
- [ ] 🟡 `chain-ai-models-across-machines.astro`
- [ ] 🟡 `smart-home-without-cloud-local-device-communication.astro`
- [ ] 🟡 `connect-ai-agents-behind-nat-without-vpn.astro`
- [ ] 🟡 `federated-learning-p2p-communication.astro`
- [ ] 🟡 `distributed-monitoring-without-prometheus.astro`
- [ ] 🟡 `move-beyond-rest-persistent-connections-for-agents.astro`
- [ ] 🟡 `replace-webhooks-with-persistent-agent-tunnels.astro`
- [ ] 🟡 `secure-ai-agent-communication-zero-trust.astro` (appears twice)
- [ ] 🟡 `zero-dependency-encryption-x25519-aes-gcm.astro` (implied)

---

### Pattern 8 — Wrong connect/bench flag syntax 🔴 Critical

| What the blog says | What it should say |
|---|---|
| `pilotctl connect <host> --port 80` | `pilotctl connect <host> 80` (port is positional, not a flag) |
| `pilotctl bench <addr> --duration 60s` | `pilotctl bench <addr> [size_mb]` (no `--duration` flag) |

Affected files:

- [ ] 🔴 `connecting-mcp-servers-across-agents.astro`
- [ ] 🔴 `zero-dependency-encryption-x25519-aes-gcm.astro`
- [ ] 🔴 `benchmarking-http-vs-udp-overlay.astro`

---

### Pattern 9 — Commands that do not exist in the CLI at all 🔴 Critical

| Ghost command used in blog | Correct alternative (or note) |
|---|---|
| `pilotctl find-by-tag` | `pilotctl peers --search` |
| `pilotctl discover --tag` | `pilotctl peers --search` |
| `pilotctl resolve --capability ... --filter` | No equivalent |
| `pilotctl http GET` / `pilotctl http POST` | No equivalent |
| `pilotctl echo <addr>` | No equivalent |
| `pilotctl task-opt-in` | `pilotctl extras enable-tasks` |
| `pilotctl task poll` | No equivalent |
| `pilotctl task fail` | No equivalent |
| `pilotctl task complete` | No equivalent |
| `pilotctl task status` | No equivalent |
| `pilotctl set-polo-gate` | No equivalent |
| `pilotctl trust-policy` | No equivalent |
| `pilotctl network transfer-ownership` | No equivalent |
| `pilotctl receive-file` | Files arrive automatically at `~/.pilot/received/` |
| `pilotctl send-message <addr> "text"` (no `--data`) | `pilotctl send-message <addr> --data "text"` |
| `pilotctl task accept --timeout` | `--timeout` flag does not exist for task accept |
| `pilotctl task send-results --task-id` | Flag is `--id`, not `--task-id` |
| `pilotctl send-message --wait-reply` | `--wait-reply` flag does not exist |
| `pilotctl gateway start --secure` | `--secure` flag does not exist for gateway start |
| `pilotctl init --public` | `--public` is a daemon start flag, not an init flag |

Affected files (most egregious):

- [ ] 🔴 `build-agent-swarm-self-organizes.astro` — uses: `task-opt-in`, `task poll`, `task fail`, `task complete`, `task status`, `set-polo-gate`
- [ ] 🔴 `federated-learning-p2p-communication.astro` — uses: `find-by-tag`, `receive-file`, `status` (bare), trust subcommands
- [ ] 🔴 `a2a-agent-cards-over-pilot-tunnels.astro` — uses: `resolve --capability`, `http GET/POST`
- [ ] 🔴 `decentralized-task-marketplace-agents.astro` — uses: `resolve --capability --filter`
- [ ] 🔴 `building-custom-pilot-skills-openclaw.astro` — uses: `task send-results --task-id`, `search --tag`, `status` (bare)
- [ ] 🔴 `private-agent-network-company.astro` — uses: `trust-policy auto-approve`
- [ ] 🔴 `enterprise-production-complete-identity-directory-audit-export.astro` — uses: `network transfer-ownership`
- [ ] 🔴 `http-services-over-encrypted-overlay.astro` — uses: `gateway start --secure`
- [ ] 🔴 `connect-agents-across-aws-gcp-azure-without-vpn.astro` — uses: `echo`, `discover --tag`
- [ ] 🔴 `smart-home-without-cloud-local-device-communication.astro` — uses: `send-message --wait-reply`, `peers --search "tag:X"` (wrong search syntax)

---

### Pattern 10 — `extras` prefix missing for set-tags / gateway / task 🟡 Warning

The following commands were moved behind `pilotctl extras` and are shown without the prefix in multiple places.

| What the docs/blog says | What it should say |
|---|---|
| `pilotctl set-tags` | `pilotctl extras set-tags` |
| `pilotctl clear-tags` | `pilotctl extras clear-tags` |
| `pilotctl enable-tasks` | `pilotctl extras enable-tasks` |
| `pilotctl disable-tasks` | `pilotctl extras disable-tasks` |
| `pilotctl gateway start/stop` | `pilotctl extras gateway start/stop` |
| `pilotctl task <subcommand>` | `pilotctl extras task <subcommand>` |

Affected formal doc files:

- [ ] 🟡 `tasks.astro` — `enable-tasks`, `disable-tasks`, `task submit` all missing `extras` prefix
- [ ] 🟡 `gateway.astro` — `gateway start` / `gateway stop` missing `extras` prefix
- [ ] 🟡 `tags.astro` — `set-tags` missing `extras` prefix

---

*Last updated: 2026-05-02. Total open items: 109 checkboxes across formal docs and blog patterns.*
