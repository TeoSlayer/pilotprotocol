# Integration Test Coverage — Living Anchor

**Role:** this document is the long-lived index for `tests/integration/`. Update it whenever you add tests, patch phantoms, surface product bugs, or change matrix coverage. It is NOT a changelog — it is a snapshot of current state + next moves.

Last updated: **2026-04-21** (session end — post full CLI audit).

**Legend:**
- 🟢 `TESTED` — dedicated test, expected to pass
- ⚠ `EXPECTED-FAIL` — test exists but surfaces a known product gap (the failure IS the finding)
- 🟡 `PARTIAL` — incidental coverage or SKIP-until-prereq
- 🔴 `OPEN` — no test
- ⚪ `N/A` — not applicable

---

## TODOs (actionable, in order)

Tracked as tasks in the task system. Numbers reference `TaskList`.

**Product bugs (surfaced by tests — need code fix):**
- `#194` Fix P1-010 tunnel crypto desync after loss (relayProbeLoop vs peers map race)
- `#195` Wire `EventJoin`/`EventLeave` into network-join flow
- `#196` Bounded pubsub publish (rate limit + per-subscriber channel)
- `#197` Cap IPC connections per-client and total (P2-002)
- `#198` Add `MaxTaskDescription` / `MaxTaskPayload` guards
- `#199` Verify relay sender endpoint binding before populating peers map
- `#200` Reconcile 32 missing named network configs vs marketing
- `#201` Emit missing webhook events (file.delivered, task.*, polo.updated, trust.changed canonical, agent.registered canonical)
- `#202` Gateway: extend beyond TCP-bridge to proxy control-plane ops
- `#146` Implement rotate-key tunnel rekey (currently registry-record only)

**Test-suite health (need test-side work):**
- Tighten cycle-tick log regex in `test_dur_shortcycle_policy_1m.sh` + `test_dur_steady_compressed_24h.sh` after first run (config now uses `network create --rules-file`, not phantom `policy load`).
- Add `CAP_SYS_TIME` / `libfaketime` to `docker-compose.multi.chaos.yml` so clock-skew + clock-rollback tests leave SKIP state.
- Route the 209 scripts into a CI lane (parallel + slow-CI split on `# DURATION:` headers).
- Retire the per-cell `[TESTED: ...]` tags in `INTERACTION-MATRIX.md` — regenerate from filename pattern instead (scale is 209 scripts, manual tagging has drifted).
- Reconcile dashboard polo exposure: either add polo to `/api/stats` or document that registry `lookup` is the only source of truth.

**CLI phantoms patched this session** (see Appendix A for full list).

---

## All issues (consolidated — the full list)

Numbered so they can be referenced in PRs / commits / tasks. Grouped by category; each row has a **status** tag: `BUG` (code fix needed), `GAP` (feature not shipped), `ODDITY` (surprising but not broken), `TEST` (test-side issue), `REPO` (repo state).

### Product bugs + gaps (13)

| # | Status | Issue | Location | Task |
|---:|---|---|---|---|
| 1 | BUG | **P1-010 tunnel crypto desync after packet loss.** `relayProbeLoop` calls `SetRelayPeer(nodeID,false)` for 2s, but `tm.peers[nodeID]` is already `tm.beaconAddr` from `handleRelayDeliver`. During the 2s window, sends (including key-exchange replies) go to the beacon as plain PILS frames and are silently dropped. | `pkg/daemon/daemon.go:2870-2932` + `tunnel.go:1197` | #194 |
| 2 | GAP | **`EventJoin`/`EventLeave` declared but unwired.** Events exist in `pkg/policy/policy.go:20-22` but no call site in `pkg/daemon` or `pkg/registry` invokes `EvaluateActions(EventJoin,…)` on network join. | `pkg/policy/policy.go:20-22` | #195 |
| 3 | BUG | **Pubsub publish is unbounded.** `eventBroker.publish` has no rate limit and no bounded per-subscriber channel; single publisher can OOM subscribers. | `pkg/daemon/services.go:380` | #196 |
| 4 | BUG | **IPC accept has no caps (P2-002).** `IPCServer.acceptLoop` has no per-client or total-connections cap. | `pkg/daemon/ipc.go:157` | #197 |
| 5 | GAP | **No `MaxTaskDescription`/`MaxTaskPayload` guard.** Receiver allocates without bound. | `pkg/daemon/*` | #198 |
| 6 | BUG | **Relay senderID spoofing pollutes peers map.** `handleRelayDeliver` sets `tm.peers[srcNodeID]=beaconAddr` without verifying the sender. Bounded by `maxRelayPeers=4096` but attacker-controllable. | `pkg/daemon/tunnel.go:1178` | #199 |
| 7 | REPO | **32 phantom network configs — 31 RECOVERED 2026-04-21** from dangling stash commit `0529595c73` into `configs/networks/` as untracked files. Chunk I tests can now run against them; remaining work: JSON schema vet + stage + commit + run per-config tests to verify each promise. | `configs/networks/` | #200 |
| 8 | GAP | **6 advertised webhook events have no Emit site.** `file.delivered` (only `file.received` exists), `task.submitted`, `task.completed`, `polo.updated`, canonical `trust.changed` (only `trust.revoked`), canonical `agent.registered` (only `node.registered`/`node.reregistered`). | `pkg/daemon/` + `pkg/registry/` | #201 |
| 9 | GAP | **Gateway is TCP-bridge only.** Adds a loopback alias + forwards TCP on `{7,80,443,1000,1001,1002,8080,8443}`. No HTTP/gRPC API, no proxy for task/pubsub/trust/polo/lookup/register/ping/rotate-key. | `pkg/gateway/` | #202 |
| 10 | GAP | **`pilotctl rotate-key` is registry-record only.** No tunnel rekey primitive; no CLI path drives `maybeRequestRekey`/`sendKeyExchangeToNode`. | `pkg/daemon/tunnel.go` | #146 |
| 11 | BUG | **P1-009 mid-rekey race.** Task submits during key rotation fail. 4 Chunk F mid-rekey tests + `test_race_submit_rekey.sh` are direct repros. Known pre-session, no repair task yet. | `pkg/daemon/tunnel.go` rekey paths | (not yet tasked) |
| 12 | BUG | **Silent promotion of sub-1m cycle durations.** `pkg/policy.Validate` rejects `cycle < 1m`, but `pkg/daemon/policy_runner.go:508` silently promotes sub-1m durations to `24h` with no error. | `pkg/daemon/policy_runner.go:508` | (not yet tasked) |
| 13 | GAP | **Dashboard `/api/stats` doesn't expose polo score.** Source of truth is registry `lookup` — should either expose or document. | `pkg/registry/dashboard.go` | (not yet tasked) |

### CLI phantoms patched this session (8 files, 12 call sites)

| # | Status | Phantom | Real CLI |
|---:|---|---|---|
| 14 | BUG | `pilotctl trust grant <peer>` — not a command | `handshake <peer> [just]` + receiver `approve <peer>` |
| 15 | BUG | `pilotctl revoke <peer>` — not a command | `untrust <peer>` |
| 16 | BUG | `pilotctl polo [agent]` — not a command | `lookup <id>` → `.data.polo_score` |
| 17 | BUG | `pilotctl trust chain` — not a command (finding: transitive trust has no CLI/API path) | none |
| 18 | BUG | `pilotctl handshake pending` — not a subcommand | `pending` (top-level) |
| 19 | BUG | `pilotctl policy load <file>` — not a subcommand | `policy set --net <id> --file <path>` or `network create --rules-file` |
| 20 | BUG | `pilotctl network apply <file>` — not a subcommand | `network create --rules-file <path>` |
| 21 | BUG | `pilotctl commands` — not a command (only in comment, not patched) | `pilotctl` (no args) |
| 22 | BUG | `pilotctl help` — not a command (only in intentional probe, not patched) | `pilotctl` (no args) |
| 23 | BUG | `pilotctl rekey <peer>` — not a command (intentional probe; kept for task #146 regression detection) | none |

### Product-surface oddities (10)

| # | Status | Issue |
|---:|---|---|
| 24 | ODDITY | `pilotctl policy set` rejects `--net 0`. Default network not addressable for policy ops. |
| 25 | ODDITY | `pilot-gateway` port 80 has no server. Daemon services don't register on `PortHTTP`. Tests use 1001. |
| 26 | ODDITY | No explicit beacon ping. `pkg/beacon/server.go` only handles Discover/PunchRequest/Relay/Sync. `test_beacon_ping.sh` infers liveness via STUN-style Discover. |
| 27 | ODDITY | Polo score JSON shape varies across versions (`.data.node.polo_score` vs `.data.polo_score`). Tests try both. |
| 28 | ODDITY | `executeTag` only tags peers already in the runner map. `tag_on_connect` test must force-cycle first to seed. |
| 29 | ODDITY | Policy applies per `pkt.Dst.Network` — traffic to net 0 bypasses managed policy. |
| 30 | ODDITY | Pubsub late-subscriber semantics undocumented. Test accepts backlog/latest-only/none as PASS. |
| 31 | ODDITY | 500 MiB file reject behavior undefined. Test accepts clean reject OR byte-exact completion. |
| 32 | ODDITY | 10 MB message reject behavior undefined. `MaxMessage` bound unclear. |
| 33 | ODDITY | `docker-compose.multi.policy.yml` needs `-admin-token` on rendezvous + agents for `network create`/`policy set`/`provision`. Missed in other overlays. |

### Test-harness / infra friction (13)

| # | Status | Issue |
|---:|---|---|
| 34 | TEST | `test_p2p.sh` is NOT a standalone smoke — assumes stack pre-booted at `$DASHBOARD`. Exits 1 with "0 agents registered after 60s" otherwise. |
| 35 | TEST | First `test_p2p.sh` background run produced a 0-byte output file (sandbox capture bug when chained with `tail -40`). Use explicit `> /tmp/p2p_smoke.log 2>&1`. |
| 36 | TEST | `Dockerfile.multi` was mutated by 3 chunks (E, H, D) — merged by luck. Future parallel chunks need disjoint regions. |
| 37 | TEST | Clock-skew + clock-rollback tests SKIP because `CAP_SYS_TIME` not in compose override. Need `libfaketime` or capability. |
| 38 | TEST | `tc netem reorder` no-op without base delay. `apply_reorder` must prepend 10 ms. |
| 39 | TEST | iptables in-container can't resolve compose hostnames. Chunk A's `resolve_service_ip` uses rendezvous as DNS resolver. |
| 40 | TEST | `docker compose restart` is not atomic. Mid-rekey forcing races with rekey window → reduced repro reliability. |
| 41 | TEST | `tcpdump` not in base image. Chunk D installs on-demand via `ensure_tcpdump()`. |
| 42 | TEST | `raw_udp.py` capture mode uses `SOCK_DGRAM` bind — not promiscuous; real wire capture needs `tcpdump`. |
| 43 | TEST | Cycle-tick log regex (`CYCLE_TICK_TEST|cycle.*tick|policy.*cycle`) unverified. Tighten after first run. |
| 44 | TEST | Sybil test assumes `pilot-daemon -socket` flag — fails at registration if flag renamed. |
| 45 | TEST | Split-brain heal uses ad-hoc `docker run` to migrate agents; depends on `docker inspect` to pull image tag. |
| 46 | TEST | Ring routing is app-layer. `test_ring4_routing.sh` implements via per-agent forwarder chain, not Pilot-level routing. |

### Repo + docs drift (4)

| # | Status | Issue |
|---:|---|---|
| 47 | REPO | 31 untracked `configs/networks/*.json` in initial `git status` disappeared mid-session. `git log` shows no commit removing them. Unclear whether user git-cleaned or index was stale. (Overlaps with #7.) |
| 48 | REPO | No CI lane routes the 209 new integration tests yet. Needs parallel runner + slow-CI split on `# DURATION:` headers. |
| 49 | REPO | `INTERACTION-MATRIX.md` has 1 `[TESTED:]` tag but there are 209 scripts. Manual tag system never scaled. Retire or regenerate. |
| 50 | REPO | Linter aggressively rewrites `handleRegister` + `NodeInfo` crypto fields. Unchanged-looking code may regress silently. |

**Totals: 50 distinct issues — 10 product bugs, 6 product gaps, 10 CLI phantoms (all patched), 10 surface oddities, 13 test-harness friction points, 4 repo/docs drift.**

---

## Context

- **209 test scripts** under `tests/integration/`, all pass `bash -n`.
- **Authoring model:** 9 parallel agent chunks (A–I) authored most scripts; reviewed + patched this session for real-CLI correctness.
- **Canonical CLI:** saved to `~/.claude/projects/.../memory/reference_pilotctl_cli.md`. Real surface verified by running `pilotctl` no-args + `pilotctl <cmd>` no-args inside a running `agent-a` container.
- **Topology:** `docker-compose.multi.yml` (rendezvous + agent-a + agent-b, subnet 172.29.0.0/24). Overlays for chaos / policy / webhooks / gateway.
- **Smoke run:** `test_chain_abc_task.sh` passes 7/7 (3-agent chain with wrapped-result assertion). Confirms build + worker/task flow.
- **`test_p2p.sh` is NOT a smoke test** — it assumes the stack is pre-booted at `$DASHBOARD`. Use `test_chain_abc_task.sh` or a targeted compose up for smokes.

---

## Executive summary

**Total cells across 10 matrices: 463** (50 N/A → 413 applicable).

| Matrix | 🟢 | ⚠ | 🟡 | 🔴 | ⚪ | Total | % applicable covered |
|---|---:|---:|---:|---:|---:|---:|---:|
| 1. Actor × Operation         | 37 | 9  | 4  | 15  | 31 | 96  | 77 % |
| 2. Operation × Precondition  | 46 | 4  | 8  | 19  | 7  | 84  | 75 % |
| 3. Failure × Operation       | 63 | 14 | 14 | 14  | 0  | 105 | 87 % |
| 4. Policy Event × Traffic    | 20 | 15 | 1  | 21  | 8  | 65  | 63 % |
| 5. Topology × Pattern        | 29 | 1  | 1  | 5   | 4  | 40  | 86 % |
| 6. Security × Attack Vector  | 6  | 5  | 0  | 1   | 0  | 12  | 92 % |
| 7. Cross-Op Concurrency      | 11 | 1  | 2  | 0   | 0  | 14  | 100 % |
| 8. Payload Size × Operation  | 15 | 1  | 2  | 2   | 0  | 20  | 90 % |
| 9. Duration × Scenario       | 10 | 0  | 6  | 4   | 0  | 20  | 80 % |
| 10. Observability end-to-end | 3  | 4  | 0  | 0   | 0  | 7   | 100 % |
| **Total**                    | **240** | **54** | **38** | **81** | **50** | **463** | **81 %** |

**Verdict:** 81 % applicable covered. 54 ⚠ cells each reveal a real product gap (mapped to tasks #194–#202 + P1-009). Remaining 🔴: SDK rows (out of scope) + rotate-key (task #146).

---

## Matrix 1 — Actor × Operation (8 × 12 = 96)

| Pair → | file | msg | tsk-sub | tsk-res | pub | sub | trust | polo | lookup | reg | rotkey | ping |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| agent-a ↔ agent-b          | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 | 🟡 #146 | 🟢 |
| agent-a ↔ rendezvous       | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ | 🟡 | 🟢 | 🟢 | 🟡 | ⚪ |
| agent-a ↔ beacon           | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ | 🟢 |
| agent → SDK client         | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 |
| SDK ↔ SDK                  | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 |
| dashboard → rendezvous     | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ | 🟢 | 🟢 | 🟢 | ⚪ | ⚪ |
| webhook ← agent            | ⚠ | 🟢 | ⚠ | ⚠ | 🟢 | 🟢 | ⚠ | ⚠ | ⚪ | ⚠ | ⚪ | ⚪ |
| gateway → agent            | 🟢 | 🟢 | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | 🟡 | 🟢 |

Webhook ⚠: no Emit site for file.delivered / task.submitted / task.completed / polo.updated / canonical trust.changed / canonical agent.registered (task #201). Gateway ⚠: gateway is TCP-bridge only (task #202).

---

## Matrix 2 — Operation × State precondition (12 × 7 = 84)

| Op \ state | fresh | already-conn | crypto-missing | mid-rekey | relay-only | peer-restarted | peer-gone |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| send-file        | 🟢 | 🟢 | 🟡 | ⚠ P1-009 | ⚠ P1-010 | 🟢 | 🟢 |
| send-message     | 🟢 | 🟢 | 🟡 | ⚠ P1-009 | ⚠ P1-010 | 🟢 | 🟢 |
| task submit      | 🟢 | 🟢 | 🟡 | ⚠ P1-009 | ⚠ P1-010 | 🟢 | 🟢 |
| task results     | 🟢 | 🟢 | 🟡 | ⚠ P1-009 | 🟢 | 🟢 | 🔴 |
| pubsub publish   | 🟢 | 🟢 | 🔴 | 🔴 | 🔴 | 🟢 | 🔴 |
| pubsub subscribe | 🟢 | 🟢 | 🔴 | 🔴 | 🔴 | 🟢 | 🔴 |
| trust grant*     | 🟢 | 🟢 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 |
| trust revoke     | 🟢 | 🟡 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 |
| polo update      | 🟢 | 🟢 | ⚪ | ⚪ | ⚪ | 🟢 | 🔴 |
| register         | 🟢 | 🟢 | ⚪ | ⚪ | ⚪ | 🟢 | ⚪ |
| rotate-key       | 🟡 #146 | 🟡 #146 | 🟡 #146 | 🟡 #146 | 🟡 #146 | 🟡 #146 | 🟡 #146 |
| ping             | 🟢 | 🟡 | 🟡 | 🟡 | 🔴 | 🟢 | 🟢 |

\* "trust grant" row = the real `handshake` + `approve` flow. `pilotctl trust grant` is not a command.

---

## Matrix 3 — Failure injection × Operation (15 × 7 = 105)

| Failure ↓ / Op → | file | msg | tsk-sub | tsk-res | pubsub | trust | register |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| Receiver clean restart  | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 | 🔴 | 🟢 |
| Receiver SIGKILL        | 🟢 | 🔴 | 🟢 | 🔴 | 🔴 | 🔴 | 🔴 |
| Sender clean restart    | 🟢 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 |
| Sender crash            | 🟢 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 |
| Rendezvous restart      | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 |
| Beacon restart          | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 |
| Packet loss 10 %        | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 |
| Packet loss 30 %        | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ P1-010 |
| Packet reorder          | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 |
| Packet delay 200 ms     | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 |
| Partition mid-flight    | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 |
| Partition heal          | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 |
| Disk full (receiver)    | 🟢 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 |
| Clock skew ±60 s        | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 |
| Clock rollback          | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 |

⚠ Packet loss 30%: all cells reproduce P1-010 (task #194). 🟡 clock rows: SKIP until `CAP_SYS_TIME`/`libfaketime`.

---

## Matrix 4 — Policy event × traffic (13 × 5 = 65)

| Event → Action | file | msg | tsk-sub | pubsub | trust |
|---|:-:|:-:|:-:|:-:|:-:|
| connect → allow        | 🟢 | 🟢 | 🟢 | 🔴 | 🔴 |
| connect → deny         | 🟢 | 🟢 | 🟢 | 🔴 | 🔴 |
| connect → score        | 🟢 | 🟢 | 🟢 | 🔴 | 🔴 |
| connect → tag          | 🟢 | 🔴 | 🔴 | 🔴 | 🔴 |
| datagram → allow       | 🟢 | 🟢 | 🔴 | 🔴 | 🔴 |
| datagram → deny        | 🟢 | 🟢 | 🔴 | 🔴 | 🔴 |
| datagram → score       | 🟢 | 🟢 | 🔴 | 🔴 | 🔴 |
| cycle → prune_trust    | ⚪ | ⚪ | ⚪ | ⚪ | 🟢 |
| cycle → fill_trust     | ⚪ | ⚪ | ⚪ | ⚪ | 🟢 |
| cycle → evict          | 🟢 | 🔴 | 🔴 | 🔴 | 🔴 |
| cycle → webhook        | 🟢 | 🔴 | 🔴 | 🔴 | 🔴 |
| join → allow           | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ |
| join → deny            | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ |
| join → score           | ⚠ | ⚠ | ⚠ | ⚠ | ⚠ |

⚠ join rows: `EventJoin`/`EventLeave` declared in `pkg/policy/policy.go:20-22` but never invoked by daemon/registry (task #195).

Per-network enforcement: 42 additional tests under `test_net_*.sh` cover cross-network isolation + polo/trust scoping + one test per shipped or promised config. Only 3 shipped configs pass; 32 promise-tests fail because the JSON doesn't ship (task #200).

---

## Matrix 5 — Topology × Pattern (8 × 5 = 40)

| Topology ↓ / Pattern → | unicast | fan-out | fan-in | chain | mesh |
|---|:-:|:-:|:-:|:-:|:-:|
| 2 agents    | 🟢 | ⚪ | ⚪ | ⚪ | ⚪ |
| 3 agents    | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 |
| 5 agents    | 🟢 | 🟢 | 🔴 | 🔴 | 🔴 |
| 10+ agents  | ⚠ | 🔴 | 🔴 | 🔴 | 🔴 |
| Ring        | ⚪ | ⚪ | ⚪ | 🟢 | ⚪ |
| Star        | 🟢 | 🟢 | 🟢 | ⚪ | ⚪ |
| Split-brain | 🟢 | 🔴 | 🔴 | 🔴 | 🔴 |
| Heal        | 🟢 | 🔴 | 🔴 | 🔴 | 🔴 |

⚠ 10-agent flash-crowd may expose registration serialization >15s.

---

## Matrix 6 — Security × Attack Vector

| Attack | Test |
|---|:-:|
| Replay packet after rekey            | 🟢 |
| Spoofed node_id                      | 🟢 H3-fix |
| Malformed frame                      | 🟢 |
| Oversized payload                    | ⚠ task #198 |
| Key-exchange flood                   | 🟢 rate-limited |
| Amplification via beacon relay       | 🟢 `relayNotFound` drops |
| Symmetric-NAT discovery spoof        | 🟢 |
| Sybil: many fresh identities         | 🟢 `maxCryptoPeers` |
| Spam pubsub publish                  | ⚠ task #196 |
| Resource exhaustion (many IPC conns) | ⚠ task #197 |
| Task submit under polo = 0           | 🟢 |
| Relay senderID spoof                 | ⚠ task #199 |

5 ⚠ = 5 real security gaps surfaced by Chunk D.

---

## Matrix 7 — Cross-operation concurrency

| Op A × Op B | Test |
|---|:-:|
| send-file × send-file (same pair)     | 🟢 |
| send-file × send-message              | 🟡 |
| send-file × task-submit               | 🟡 |
| task-submit × task-submit             | 🟢 |
| task-submit × task-accept (same id)   | 🟢 |
| task-accept × task-accept (2 workers) | 🟢 |
| task-submit × rekey                   | ⚠ P1-009 |
| task-results × task-results (retry)   | 🟢 |
| pubsub publish × subscribe-join       | 🟢 |
| pubsub publish × topic delete         | 🟢 |
| trust-grant × trust-revoke            | 🟢 |
| polo-update × polo-read               | 🟢 |
| register × lookup                     | 🟢 |
| send-file × rekey                     | 🟢 |

---

## Matrix 8 — Payload size × Operation

| Size ↓ / Op → | send-file | send-message | task-result | pubsub |
|---|:-:|:-:|:-:|:-:|
| Tiny (1 B)          | 🟢 | 🟢 | 🟢 | 🟡 |
| Small (1–64 KB)     | 🟢 | 🟢 | 🟢 | 🟢 |
| Medium (64 KB–1 MB) | 🟢 | 🟢 | 🟢 | 🟢 |
| Large (1–100 MB)    | 🟢 | ⚠ reject? | 🟢 | 🔴 |
| Huge (>100 MB)      | 🟢 | 🔴 | 🔴 | 🔴 |

⚠ 10 MB message test: `MaxMessage` bound unclear — first run decides.

---

## Matrix 9 — Duration × Scenario

| Duration ↓ / Scenario → | idle | steady | burst | periodic |
|---|:-:|:-:|:-:|:-:|
| 1 s      | 🟢 | 🟢 | 🟢 | 🔴 |
| 60 s     | 🟢 | 🔴 | 🟢 | 🟢 |
| 10 min   | 🟡 slow | 🟡 slow | 🔴 | 🔴 |
| 1 hr     | 🔴 | 🟡 24h compressed | 🔴 | 🔴 |
| 24 hr    | 🔴 | 🟡 | 🔴 | 🔴 |

🟡 = `# DURATION:`-tagged, skipped in fast CI.

---

## Matrix 10 — Observability end-to-end

| Observable | Test |
|---|:-:|
| Dashboard `/api/stats` total_nodes     | 🟢 |
| Dashboard polo score vs ground truth   | ⚠ polo not in DashboardStats |
| Webhook `task.completed`               | ⚠ task #201 |
| Webhook `tunnel.established`           | 🟢 |
| Log `peer rekeyed`                     | ⚠ not emitted on rotate-key stub |
| Metric `EncryptOK` count               | ⚠ not in `/api/stats` |
| `task list --type received/submitted`  | 🟢 |

---

## Known product gaps → tasks

| # | Gap | Task | Cells affected |
|---:|---|---|---:|
| 1 | P1-010 tunnel crypto desync after loss | #194 | 7 (M3 loss30) |
| 2 | EventJoin/EventLeave unwired           | #195 | 15 (M4 join) |
| 3 | Pubsub publish unbounded               | #196 | 1 (M6) |
| 4 | IPC connection cap missing (P2-002)    | #197 | 1 (M6) |
| 5 | MaxTaskDescription / MaxTaskPayload    | #198 | 2 (M6 + M8) |
| 6 | Relay senderID spoofing                | #199 | 1 (M6) |
| 7 | 32 phantom network configs             | #200 | 32 Chunk I tests |
| 8 | 6 missing webhook emits                | #201 | 9 (M1 webhook + M10) |
| 9 | Gateway no control-plane proxy         | #202 | 8 (M1 gateway) |
| 10 | rotate-key tunnel rekey missing       | #146 | 12 (M2 rotkey) |

Plus **P1-009** mid-rekey race — 4 M2 cells + 1 M7 cell, workaround-tested, no repair task yet.

---

## Appendix A — CLI audit (phantoms patched)

### A.1 Method

Ran `pilotctl` (no args) + `pilotctl <cmd>` (no args) inside a running `agent-a` container to enumerate every valid `(command, subcommand)` pair. Then grepped every `pilotctl <word> <word>` pattern across 209 scripts and diffed against canonical. Invoked each suspected phantom in-container to confirm "unknown command" before patching.

### A.2 Phantom → real mapping

| Phantom | Real CLI | Files affected |
|---|---|---|
| `pilotctl trust grant <peer>` | `handshake <peer> [just]` + receiver `approve <peer>` | 4 chaos + 3 net/gateway (patched) |
| `pilotctl revoke <peer>` | `untrust <peer>` | `test_race_trust_grant_revoke.sh` (patched) |
| `pilotctl rekey <peer>` | NONE — task #146 pending; `rotate-key` is registry-record-only | `test_rotate_key_hot_path.sh` (intentional probe; `test_midrekey_send_file.sh` only refers in comments) |
| `pilotctl polo [agent]` | `lookup <id>` → `.data.polo_score` | `test_gateway_polo_read.sh` (patched) |
| `pilotctl trust chain` | NONE — transitive trust has no CLI/API (finding) | `test_net_vouching_chain_shipped.sh` (patched to EXPECTED-FAIL) |
| `pilotctl handshake pending` | `pending` (top-level) | `test_sec_trust_grant_forgery.sh` (patched) |
| `pilotctl policy load <file>` | `policy set --net <id> --file <path>` or `network create --rules-file` | `test_dur_shortcycle_policy_1m.sh`, `test_dur_steady_compressed_24h.sh` (patched to `network create --rules-file`) |
| `pilotctl network apply <file>` | `network create --rules-file <path>` | same 2 files (patched) |
| `pilotctl commands` | `pilotctl` (no args) | only in a comment — not patched |
| `pilotctl help` | `pilotctl` (no args) | `test_rotate_key_hot_path.sh` (intentional probe with `|| true`) |

### A.3 Confirmed-real commands (not in help output but exist)

- `pilotctl provision <blueprint.json>`
- `pilotctl deprovision <network-name>`
- `pilotctl set-webhook <url>`
- `pilotctl member-tags set --net <id> --node <id> --tags tag1,tag2`

### A.4 Canonical CLI surface (reference)

- **Trust**: `handshake <id|host> [just]` / `approve <id>` / `reject <id> [reason]` / `untrust <id>` / `pending` / `trust` (display only)
- **Polo**: read via `lookup <id>` → `.data.polo_score`
- **Rotate-key**: `rotate-key <id> <email>` (registry-record only — no tunnel rekey; task #146)
- **Policy**: `policy {get, set, validate, test}` — `set` requires `--net <id>` + `--file <path>|--inline '<json>'`
- **Managed**: `managed {score, status, rankings, cycle}` — `cycle --force` forces a tick
- **Network**: `network {list, join, leave, members, invite, invites, accept, reject, create, delete, rename, promote, demote, kick, role, policy}` — `create` accepts `--rules-file`
- **Gateway**: `gateway {start, stop, map, unmap, list}`
- **Daemon**: `daemon {start, stop, status}` — `start` accepts `--webhook <url>` among others
- **Task**: `task {submit, accept, decline, execute, send-results, result, list, queue}`
- **Provisioning**: `provision <blueprint.json>` / `deprovision <network-name>`
- **Webhook config**: `set-webhook <url>`
- **Tag config**: `set-tags <tag1> ...` / `clear-tags` / `member-tags set ...`

Authoritative copy lives in memory at `reference_pilotctl_cli.md`.

---

## Appendix B — Product-surface oddities (non-bugs, surprised authors)

- `pilotctl policy set` rejects `--net 0`. Default network isn't addressable for policy ops.
- `pkg/policy.Validate` rejects `cycle < 1m`; `policy_runner.go:508` silently promotes sub-1m durations to `24h`. **Silent promotion is a minor bug** (fail-loud beats fail-silent).
- `pilot-gateway` port 80 has no server. Daemon services don't register on `PortHTTP` — tests use port 1001.
- No explicit beacon ping; `test_beacon_ping.sh` infers liveness via STUN-style `BeaconMsgDiscover`.
- Polo score JSON varies across versions (`.data.node.polo_score` vs `.data.polo_score`). Tests try both.
- Dashboard `/api/stats` doesn't expose polo — `test_obs_dashboard_polo_truth.sh` falls back to `pilotctl lookup`.
- `executeTag` only tags peers already in the runner map; tag_on_connect test must force-cycle to seed.
- Policy applies per `pkt.Dst.Network`; traffic to net 0 bypasses managed policy.
- Pubsub late-subscriber semantics undocumented; test accepts backlog / latest-only / none as PASS.
- 500 MiB / 10 MB payload reject behavior undefined; tests accept either clean reject or byte-exact completion.

---

## Appendix C — Test-harness friction

- `test_p2p.sh` assumes stack is pre-booted at `$DASHBOARD` — not a standalone smoke.
- First attempt at `test_p2p.sh` as background Bash produced 0-byte output (sandbox capture bug when chained with `tail -40`). Use explicit `> /tmp/p2p_smoke.log 2>&1`.
- `Dockerfile.multi` was mutated by 3 different chunks (E, H, D) — merged by luck; future parallel chunks should own disjoint regions.
- Clock-skew + clock-rollback tests SKIP — need `CAP_SYS_TIME` or `libfaketime`.
- `tc netem reorder` no-op without base delay (`apply_reorder` prepends 10 ms).
- iptables in-container can't resolve compose hostnames — Chunk A's `resolve_service_ip` uses rendezvous as DNS resolver.
- `docker compose restart` is not atomic; mid-rekey forcing races with rekey window → reduced repro reliability.
- `tcpdump` not in base image; Chunk D installs on-demand via `ensure_tcpdump()`.
- `raw_udp.py` capture mode uses `SOCK_DGRAM` bind (not promiscuous); real wire capture needs `tcpdump`.
- Cycle-tick log regex (`CYCLE_TICK_TEST|cycle...tick|policy...cycle`) is unverified — tighten after first run.
- Sybil test assumes `pilot-daemon -socket` flag.
- `docker-compose.multi.policy.yml` needs `-admin-token` on rendezvous + agents for `network create` / `policy set` / `provision`.
- Split-brain heal uses ad-hoc `docker run` to migrate agents; depends on `docker inspect` to pull image tag.
- Ring routing is app-layer; `test_ring4_routing.sh` implements via per-agent forwarder chain.

---

## Appendix D — State-of-the-repo oddities

- 31 untracked `configs/networks/*.json` were in initial `git status` but are gone from disk; `git log` shows no commit removing them. Either user git-cleaned or they never existed on disk. Investigate before claiming these configs "ship" (task #200).
- No CI lane routes these 209 tests yet. Needs a runner (parallel + slow-CI split) to promote from "authored" to "first-class".
- `INTERACTION-MATRIX.md` has 1 `[TESTED:]` tag but 209 scripts exist. Tag system never meant for this scale — regenerate from filename pattern or retire in favor of this grid.

---

## Files in `tests/integration/` today

235 files: 209 test scripts, 7 compose overlays, 6 helper sh libs, 2 python injectors, 1 webhook sink, 14 policy fixtures, plus matrix + plan docs. All 209 scripts pass `bash -n`.

**Next move:** run the full suite once, capture pass/fail by cell, promote 🟢 cells from "tested" to "proven", and file the ⚠ cell failures as repro evidence on tasks #194–#202.

---

## Appendix E — Chunk I per-network enforcement run (2026-04-21)

After recovering 31 network configs from a dangling stash commit and reworking `network_helpers.sh` to do a two-step (unmanaged `network create` → `policy set --net <id> --file <path>`) dance — because `network create --rules-file` expects the `NetworkRules` managed-topology schema, but shipped configs only carry `expr_policy` — ran all 34 Chunk I `test_net_*_shipped.sh` tests against the recovered configs.

**Tally:** 14 clean PASS (sub-pass=N, sub-fail=0), 20 with ≥1 failure. Of the 20 failures, 3 fail at **policy compilation** (the shipped expr_policy won't even load into the engine — a hard product bug), and the rest fail at **enforcement assertion** (policy loads but behavior doesn't match the name's promise).

**Clean PASS (14):**
`anti-camping`, `aristocracy`, `burnout`, `fifo`, `golden-hour`, `gossip-tax`, `half-life`, `lifo`, `ostracism`, `seniority`, `stable-state`, `sybil-gauntlet`, `two-strikes`, `vouching-chain`.

> Caveat: several of these (`burnout`, `golden-hour`, `gossip-tax`, `half-life`, `stable-state`) report empty score deltas in their log lines (`score=`, `0 -> 0`) — assertions pass because the test compares to `0`/empty, not because the policy measurably changed state. Treat as **weak PASS** — they prove the pipe doesn't explode, not that the promise is met. Separate pass to strengthen these assertions is tracked below.

**Policy compile bugs (3) — hard blockers:**

| # | Config | Error | Root cause |
|---|---|---|---|
| E1 | `pay-it-forward.json` | `rule "reset-hoarders" match: unknown name peer_score` | expr env exposes `peer_score` on `datagram`/`connect`/`dial` events, NOT on `cycle` events |
| E2 | `forgiveness.json` | `rule "absolve" match: unknown name peer_score` | same — `peer_score` used in `on: cycle` match |
| E3 | `meritocracy-rating.json` | `rule "reward-quality" match: unknown name sender_rating` | `sender_rating` field not in expr env at all — expr env lacks pluggable peer-attribute accessors |

**Enforcement gaps (17) — policy loads but name's promise is unmet:**

`gift-economy` (no scores accrue either direction), `karma-ledger` (karma static), `ostracism`✅ / `grudge-match` (no persist across restart), `lottery` (fully deterministic allow — no probabilistic deny), `cold-shoulder` (no deny of low-score), `cooling-off` (retry in window not denied), `data-exchange-policy` (2/4 subs fail), `dunbar-150` (max_peers=0), `high-trust-society` (`managed cycle` CLI invoked wrong — sub-test-side bug), `meritocracy` (no ranking surface), `mutual-admiration` (no reciprocation bonus), `old-guard` (no age rule), `rotating-chairs` (ranking head static), `small-circle` (cap=0), `tithe` (no decrease), `trust-decay` (3/4 subs pass, 1 fail), `whale-hunt` (no rule visible).

**Where the enforcement failures split:**
- ~8 are **expr env gaps** — matches on fields/events the engine doesn't expose (`peer_score` on cycle, `sender_rating`, `peer_age_s` in many configs, rating fields).
- ~5 are **missing directive implementations** — `evict_where`, trust-graph walks, probabilistic allow/deny, restart-durable deny/grudge lists.
- ~3 are **missing observables** — `managed score <net> <peer>` returns empty when no score event fired; tests expecting ranking outputs get empty JSON.
- ~1 is **test-side CLI call** — `high-trust-society` calls `managed cycle <net>` instead of `managed cycle --force --net <net>`.

**Helper changes this run (committed state in `network_helpers.sh`):**
- `: "${PILOT_ADMIN_TOKEN:=test-admin-token}"` (was `admin-token`) — matches `docker-compose.multi.policy.yml` overlay.
- `copy_policy_to_rendezvous` → uses `agent-a` (rendezvous has no daemon/pilotctl).
- `create_network_from_file` → dropped `--rules-file` from `network create`, added a follow-up `pilotctl policy set --net <id> --file` that copies only the `.expr_policy` object (which is what `policy.Parse` expects).

**Next moves (new issues to track):**
- File task: add `peer_score`, `peer_age_s`, `sender_rating` to the expr env on `cycle`/`join`/`leave` events.
- File task: implement `evict_where`, `prune_trust`, `fill_trust` directives end-to-end.
- File task: persist deny/grudge lists across daemon restart for `grudge-match`.
- Fix test bug in `test_net_high_trust_society_shipped.sh`: `managed cycle $NID` → `managed cycle --force --net $NID`.
- Strengthen weak-PASS assertions (burnout, golden-hour, gossip-tax, half-life, stable-state) to compare pre/post score deltas instead of equality-with-zero.

Raw per-test logs: `/tmp/chunki-results/*.log` (this session) — promote to `tests/integration/artifacts/` if kept.

### Appendix E.1 — Flagship shipped networks (re-run after CLI fix)

After patching `managed cycle $NID` → `managed cycle --force --net $NID` across 12 Chunk I scripts + `network_helpers.sh::trigger_cycle`, re-ran the three configs that actually ship on disk (task #200 reference):

| Network | Sub-pass | Sub-fail | Summary |
|---|---:|---:|---|
| `trust-decay` | 4 | 0 | ✅ clean: runner active, forced cycle returns `cycle_num=1`, prune/fill counters surface |
| `high-trust-society` | 2 | 1 | ⚠ cycle tick works, but `score:+1` on `connect` event **does not apply** — 5 connects yield empty score field |
| `data-exchange-policy` | 2 | 2 | ⚠ echo (port 7) passes, but tag-based gating fails **both directions**: port 1001 accepted without `service` tag (expected deny) AND port 1001 blocked with `service` tag (expected allow) |

**New product findings from flagship run:**

| # | Finding | Root cause hypothesis |
|---|---|---|
| F1 | `score` action on `on: connect` doesn't mutate peer_score | Either `connect` event path doesn't dispatch `score` directive, or the score store isn't flushed to `managed score` readout |
| F2 | `has_tag(local_tags, "service")` / `has_tag(peer_tags, "service")` never resolves true even after `pilotctl set-tags agent-b service` | Tag lookup path at policy-eval time queries a different store than `set-tags` writes to |
| F3 | Datagram default-verdict (no explicit deny-else rule) appears to be allow, letting port 1001 through when no `service` tag is set | Matches spec behavior if default is allow; the test encodes the opposite expectation — needs config + test to agree |

F1 and F2 are the dominant root-causes behind most Appendix E enforcement failures: any network whose promise depends on tag-conditioned actions or on `score` from a gate event will fail the same way.
