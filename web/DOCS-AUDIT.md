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

- [x] 🔴 **Critical** — `pilotctl trusts` → should be `pilotctl trust`
- [x] 🟡 **Warning** — `pilotctl status` → should be `pilotctl daemon status` or `pilotctl info`

### `diagnostics.astro`

- [x] 🔴 **Critical** — `pilotctl bench other-agent 50 --timeout 120s` → `--timeout` flag does not exist; correct syntax is `pilotctl bench <addr> [size_mb]`

### `go-sdk.astro`

- [x] 🔵 **Info** — `SetTags` documented as "max 10 tags" → fixed to "max 3 tags" (enforced by daemon IPC at `pkg/daemon/ipc.go:920`)

### `tags.astro`

- [x] 🔴 **Critical** — "Maximum 10 tags per node" → fixed to 3 (matches daemon IPC enforcement)
- [x] 🔴 **Critical** — Python example shows `import pilot` and `pilot.Client()` → fixed to `from pilotprotocol import Driver` / `Driver.connect()`
- [x] 🟡 **Warning** — `pilotctl set-tags` shown as a top-level command → fixed to `pilotctl extras set-tags`

### `integration.astro`

- [x] 🟡 **Warning** — Docker example uses `FROM golang:1.21-alpine` → fixed to `golang:1.25-alpine`

### `configuration.astro`

- [x] 🔵 **Info** — Missing env vars table entries: `PILOT_HOME`, `PILOT_EMAIL`, `PILOT_RC` — added

### `cli-reference.astro`

- [x] 🔴 **Critical** — `ai` command listed → marked "(Coming soon — not yet available)"
- [x] 🔴 **Critical** — `clawdit` command listed → marked "(Coming soon — not yet available)"
- [x] 🔴 **Critical** — `scriptorium` command listed → marked "(Coming soon — not yet available)"

### `tasks.astro`

- [x] 🟡 **Warning** — `pilotctl enable-tasks` → fixed to `pilotctl extras enable-tasks`
- [x] 🟡 **Warning** — `pilotctl disable-tasks` → fixed to `pilotctl extras disable-tasks`
- [x] 🟡 **Warning** — `pilotctl task submit` (and other `task` subcommands) → fixed to `pilotctl extras task submit`

### `gateway.astro`

- [x] 🟡 **Warning** — `pilotctl gateway start` / `pilotctl gateway stop` → fixed to `pilotctl extras gateway start` / `pilotctl extras gateway stop`

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

- [x] 🟡 `why-autonomous-agents-need-private-discovery.astro`
- [x] 🟡 `cross-company-agent-collaboration-without-shared-infrastructure.astro`
- [x] 🟡 `distributed-rag-without-central-knowledge-base.astro`
- [x] 🟡 `claude-agent-teams-over-pilot.astro`
- [x] 🟡 `clawhub-to-live-network-openclaw-discovery.astro`
- [x] 🟡 `connect-agents-across-aws-gcp-azure-without-vpn.astro`
- [x] 🟡 `federated-learning-p2p-communication.astro`
- [x] 🟡 `hipaa-compliant-agent-communication.astro`
- [x] 🟡 `peer-to-peer-agent-communication-no-server.astro`
- [x] 🟡 `contributing-codebase-tour.astro`
- [x] 🟡 `connecting-mcp-servers-across-agents.astro`
- [x] 🟡 `building-custom-pilot-skills-openclaw.astro`
- [x] 🟡 `secure-research-collaboration-share-models-not-data.astro`
- [x] 🟡 `secure-ai-agent-communication-zero-trust.astro`

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

- [x] 🟡 `why-autonomous-agents-need-private-discovery.astro`
- [x] 🟡 `clawhub-to-live-network-openclaw-discovery.astro`
- [x] 🟡 `openclaw-task-delegation-polo-reputation.astro`
- [x] 🟡 `openclaw-meets-pilot-agent-networking-one-command.astro`
- [x] 🟡 `build-agent-swarm-self-organizes.astro`
- [x] 🟡 `how-626-agents-autonomously-adopted-pilot.astro`
- [x] 🟡 `connect-agents-across-aws-gcp-azure-without-vpn.astro`
- [x] 🟡 `federated-learning-p2p-communication.astro`
- [x] 🟡 `chain-ai-models-across-machines.astro`
- [x] 🟡 `lightweight-swarm-communication-drones-robots.astro`
- [x] 🟡 `building-custom-pilot-skills-openclaw.astro`
- [x] 🟡 `openclaw-agents-behind-nat-zero-config.astro`
- [x] 🟡 `peer-to-peer-agent-communication-no-server.astro`
- [x] 🟡 `preferential-attachment-ai-networks-trust-graph.astro`
- [x] 🟡 `build-openclaw-agent-self-organizes-pilot.astro`

---

### Pattern 3 — Old event pub/sub (missing address argument) 🔴 Critical

| What the blog says | What it should say |
|---|---|
| `pilotctl events publish --topic "X" --data "Y"` | `pilotctl publish <addr> <topic> --data "Y"` |
| `pilotctl events subscribe --topic "X"` | `pilotctl subscribe <addr> <topic>` |
| `pilotctl subscribe "topic"` (no address) | `pilotctl subscribe <addr> <topic>` |
| `pilotctl publish "topic" "data"` (no address) | `pilotctl publish <addr> <topic> --data "data"` |

Affected files:

- [x] 🔴 `multi-agent-pipelines-openclaw-encrypted-tunnels.astro`
- [x] 🔴 `claude-agent-teams-over-pilot.astro`
- [x] 🔴 `scaling-openclaw-fleets-thousands-agents.astro`
- [x] 🔴 `mcp-plus-pilot-tools-and-network.astro`
- [x] 🔴 `replace-webhooks-with-persistent-agent-tunnels.astro`
- [x] 🔴 `move-beyond-rest-persistent-connections-for-agents.astro`
- [x] 🔴 `replace-message-broker-twelve-lines-go.astro`
- [x] 🔴 `distributed-monitoring-without-prometheus.astro`
- [x] 🔴 `build-multi-agent-network-five-minutes.astro`
- [x] 🔴 `secure-research-collaboration-share-models-not-data.astro`

---

### Pattern 4 — Old data transfer syntax 🔴 Critical

| What the blog says | What it should say |
|---|---|
| `pilotctl data send <addr> <file>` | `pilotctl send-file <addr> <filepath>` |
| `pilotctl send <addr> "message"` (bare string) | `pilotctl send <addr> <port> --data "message"` |
| `pilotctl send <addr> --file <file>` | `pilotctl send-file <addr> <filepath>` |

Affected files:

- [x] 🔴 `multi-agent-pipelines-openclaw-encrypted-tunnels.astro`
- [x] 🔴 `claude-agent-teams-over-pilot.astro`
- [x] 🔴 `build-multi-agent-network-five-minutes.astro`
- [x] 🔴 `how-ai-agents-discover-each-other.astro`
- [x] 🔴 `connect-agents-across-aws-gcp-azure-without-vpn.astro`
- [x] 🔴 `secure-ai-agent-communication-zero-trust.astro`
- [x] 🔴 `openclaw-agents-behind-nat-zero-config.astro`
- [x] 🔴 `building-custom-pilot-skills-openclaw.astro`

---

### Pattern 5 — Old network join syntax 🟡 Warning

| What the blog says | What it should say |
|---|---|
| `pilotctl join 1` | `pilotctl network join 1` |
| `pilotctl join --network 1` | `pilotctl network join 1` |

Affected files:

- [x] 🟡 `cross-company-agent-collaboration-without-shared-infrastructure.astro`
- [x] 🟡 `chain-ai-models-across-machines.astro`
- [x] 🟡 `lightweight-swarm-communication-drones-robots.astro`
- [x] 🟡 `replace-webhooks-with-persistent-agent-tunnels.astro`
- [x] 🟡 `connect-agents-across-aws-gcp-azure-without-vpn.astro`
- [x] 🟡 `federated-learning-p2p-communication.astro`
- [x] 🟡 `hipaa-compliant-agent-communication.astro`

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

- [x] 🟡 `clawhub-to-live-network-openclaw-discovery.astro`
- [x] 🟡 `build-openclaw-agent-self-organizes-pilot.astro`
- [x] 🟡 `openclaw-meets-pilot-agent-networking-one-command.astro`
- [x] 🟡 `connect-agents-across-aws-gcp-azure-without-vpn.astro`
- [x] 🟡 `build-ai-agent-marketplace-discovery-reputation.astro`
- [x] 🟡 `why-autonomous-agents-need-private-discovery.astro`
- [x] 🟡 `private-agent-network-company.astro`
- [x] 🟡 `secure-research-collaboration-share-models-not-data.astro`

---

### Pattern 7 — Stale install method 🟡 Warning

| What the blog says | What it should say |
|---|---|
| `go install github.com/TeoSlayer/pilotprotocol/cmd/pilotctl@latest` | `curl -fsSL https://pilotprotocol.network/install.sh \| sh` |
| `go install .../cmd/pilot-daemon@latest` | `curl -fsSL https://pilotprotocol.network/install.sh \| sh` |

Affected files:

- [x] 🟡 `build-multi-agent-network-five-minutes.astro`
- [x] 🟡 `build-openclaw-agent-self-organizes-pilot.astro` (also uses `cmd/pilot-daemon`)
- [x] 🟡 `chain-ai-models-across-machines.astro`
- [x] 🟡 `smart-home-without-cloud-local-device-communication.astro`
- [x] 🟡 `connect-ai-agents-behind-nat-without-vpn.astro`
- [x] 🟡 `federated-learning-p2p-communication.astro`
- [x] 🟡 `distributed-monitoring-without-prometheus.astro`
- [x] 🟡 `move-beyond-rest-persistent-connections-for-agents.astro`
- [x] 🟡 `replace-webhooks-with-persistent-agent-tunnels.astro`
- [x] 🟡 `secure-ai-agent-communication-zero-trust.astro` (appears twice)
- [x] 🟡 `zero-dependency-encryption-x25519-aes-gcm.astro` (implied)

---

### Pattern 8 — Wrong connect/bench flag syntax 🔴 Critical

| What the blog says | What it should say |
|---|---|
| `pilotctl connect <host> --port 80` | `pilotctl connect <host> 80` (port is positional, not a flag) |
| `pilotctl bench <addr> --duration 60s` | `pilotctl bench <addr> [size_mb]` (no `--duration` flag) |

Affected files:

- [x] 🔴 `connecting-mcp-servers-across-agents.astro`
- [x] 🔴 `zero-dependency-encryption-x25519-aes-gcm.astro`
- [x] 🔴 `benchmarking-http-vs-udp-overlay.astro`

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

- [x] 🔴 `build-agent-swarm-self-organizes.astro` — uses: `task-opt-in`, `task poll`, `task fail`, `task complete`, `task status`, `set-polo-gate`
- [x] 🔴 `federated-learning-p2p-communication.astro` — uses: `find-by-tag`, `receive-file`, `status` (bare), trust subcommands
- [x] 🔴 `a2a-agent-cards-over-pilot-tunnels.astro` — uses: `resolve --capability`, `http GET/POST`
- [x] 🔴 `decentralized-task-marketplace-agents.astro` — uses: `resolve --capability --filter`
- [x] 🔴 `building-custom-pilot-skills-openclaw.astro` — uses: `task send-results --task-id`, `search --tag`, `status` (bare)
- [x] 🔴 `private-agent-network-company.astro` — uses: `trust-policy auto-approve`
- [x] 🔴 `enterprise-production-complete-identity-directory-audit-export.astro` — uses: `network transfer-ownership`
- [x] 🔴 `http-services-over-encrypted-overlay.astro` — uses: `gateway start --secure`
- [x] 🔴 `connect-agents-across-aws-gcp-azure-without-vpn.astro` — uses: `echo`, `discover --tag`
- [x] 🔴 `smart-home-without-cloud-local-device-communication.astro` — uses: `send-message --wait-reply`, `peers --search "tag:X"` (wrong search syntax)

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

- [x] 🟡 `tasks.astro` — `enable-tasks`, `disable-tasks`, `task submit` all missing `extras` prefix
- [x] 🟡 `gateway.astro` — `gateway start` / `gateway stop` missing `extras` prefix
- [x] 🟡 `tags.astro` — `set-tags` missing `extras` prefix

---

*Last updated: 2026-05-02. All 109 items resolved. Total files changed: 56 (9 formal docs + 47 blog posts).*
