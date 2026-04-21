# Integration Test Interaction Matrix

Every cell in these matrices is one potential test. Cells tagged `[TESTED: file.sh]`
already have coverage; `[PARTIAL]` means incidental coverage in another test;
`[OPEN]` means no test exists; `[N/A]` means the interaction is not meaningful.

Use this doc to direct new test work — pick an `[OPEN]` cell that's high-value
relative to protocol guarantees and author a new `test_<name>.sh`. The parallel
runner (`run-all.sh`) auto-discovers any `test_*.sh` in this directory.

---

## Dimensions

The protocol surface decomposes into these axes. The matrix sections below
combine them pairwise or more.

| Axis | Values |
|------|--------|
| **Actors** | agent-a (submitter), agent-b (receiver), rendezvous, beacon, gateway, SDK client, dashboard consumer, webhook endpoint |
| **Operations** | send-file, send-message, task submit/accept/decline/results, pubsub publish/subscribe, trust grant/revoke, polo update, lookup, register/unregister, rotate-key, ping |
| **Transport states** | no-crypto, key-exchange-pending, ready, rekeyed, relayed, teardown-pending |
| **Task states** | NEW → ACCEPTED → SUCCEEDED/DECLINED/EXPIRED/FAILED/CANCELED |
| **Trust states** | none, granted, revoked, decayed, mutual, asymmetric |
| **Polo states** | positive, zero, negative, at-reward-deadband |
| **Policy events** | connect, datagram, cycle, join |
| **Policy actions** | allow, deny, score, tag, evict, evict_where, prune, fill, prune_trust, fill_trust, webhook, log |
| **Topologies** | 1:1, 1:N fan-out, N:1 fan-in, N:M mesh, ring, star, chain, split-brain |
| **Concurrency** | 1, 5, 10, 100, 1000 |
| **Payload size** | tiny (<1KB), small (1–64KB), medium (64KB–1MB), large (1–100MB), huge (>100MB) |
| **Agent classes** | public, restricted-cone NAT, port-restricted NAT, symmetric NAT, Cloud VM |
| **Failure modes** | clean restart, crash, partition, packet loss, reorder, delay, disk full, clock skew, rendezvous down, beacon down |

---

## Matrix 1 — Actor × Operation

Columns are operations. Rows are actor pairs. Each cell lists the existing
test(s) or flags `[OPEN]`.

| Pair → | send-file | send-message | task submit | task result | pubsub pub | pubsub sub | trust | polo | lookup | register | rotate-key | ping |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| agent-a ↔ agent-b | ✓ integrity, hostile, concurrent, bidirectional-transform | ✓ payload integrity, inbox ordering | ✓ execute_flow, executor, decline, expiry, persistence, accepted-restart | ✓ result integrity, file results | ✓ fanout, multi_publisher, topic_fifo | ✓ service_agent, fanout | ✓ trust_revoke | ✓ polo_gate | ✓ cli (via pilotctl lookup) | ✓ p2p (register on daemon up) | [OPEN] rotate-key hot path | ✓ p2p (ping used in accepted-restart) |
| agent-a ↔ rendezvous | [N/A] | [N/A] | [N/A] | [N/A] | [N/A] | [N/A] | [N/A] | ~ polo_gate (indirect ledger update) | ✓ cli, p2p | ✓ p2p | [OPEN] | [N/A] |
| agent-a ↔ beacon | [N/A] | [N/A] | [N/A] | [N/A] | [N/A] | [N/A] | [N/A] | [N/A] | [N/A] | [N/A] | [N/A] | [OPEN] beacon-only ping |
| agent → SDK client | ~ python sdk | ~ python sdk | ~ python sdk | [OPEN] node sdk | [OPEN] | [OPEN] node sdk subscribe | [OPEN] | [OPEN] | ~ python sdk | [OPEN] | [OPEN] | [OPEN] |
| SDK client ↔ SDK client | [OPEN] two-SDK-clients per-socket | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] |
| dashboard consumer → rendezvous | [N/A] | [N/A] | [N/A] | [N/A] | [N/A] | [N/A] | [N/A] | ✓ dashboard (polo display) | ✓ dashboard | ✓ dashboard | [N/A] | [N/A] |
| webhook endpoint ← agent | [OPEN] file.delivered hook | [OPEN] message.received hook | [OPEN] task.submitted hook | [OPEN] task.completed hook | [OPEN] pubsub.published hook | [OPEN] | [OPEN] trust.changed | [OPEN] polo.updated | [N/A] | [OPEN] agent.registered | [N/A] | [N/A] |
| gateway → agent | [OPEN] file via gateway | [OPEN] HTTP message over pilot | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] |

**High-value `[OPEN]`s in Matrix 1:** SDK coverage (Python and Node), webhook emission under each event type, gateway-as-intermediary.

---

## Matrix 2 — Operation × State Precondition

For each operation, does the stack handle every starting state correctly?

| Operation \ precondition | fresh connect | already-connected | crypto missing | mid-rekey | relay-only path | peer restarted | peer gone |
|---|---|---|---|---|---|---|---|
| send-file | ✓ integrity | ✓ concurrent | [PARTIAL] mixed_traffic exercises cold start | [OPEN] send during active rekey | [OPEN] force-relay send-file | [OPEN] send to just-restarted peer | [OPEN] send to dead peer (expected failure mode?) |
| send-message | ✓ payload integrity | ✓ inbox ordering | [PARTIAL] | [OPEN] | [OPEN] force-relay message | [OPEN] | [OPEN] |
| task submit | ✓ execute_flow | ✓ sequential_burst | [PARTIAL] | [OPEN] submit during rekey | [OPEN] | ✓ persistence_restart | [OPEN] submit to unregistered peer |
| task results | ✓ result integrity | ✓ | ~ accepted-restart (workaround via ping) | **P1-009** (documented bug) | [OPEN] results over relay | ✓ accepted-restart | [OPEN] results after submitter died |
| pubsub publish | ✓ topic_fifo | ✓ | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] publish to empty topic |
| pubsub subscribe | ✓ fanout | ✓ | [OPEN] subscribe before publisher connected | [OPEN] | [OPEN] | [OPEN] resubscribe after own restart | [OPEN] |
| trust grant | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] |
| trust revoke | ✓ revoke | [PARTIAL] | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] |
| polo update | ✓ polo_gate (submit side) | ✓ | [N/A] | [N/A] | [N/A] | [OPEN] polo persistence across restart | [OPEN] |
| register | ✓ p2p | ✓ re-register on restart | [N/A] | [N/A] | [N/A] | [OPEN] register same identity from new endpoint | [N/A] |
| rotate-key | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] |
| ping | ✓ accepted-restart | [PARTIAL] | [PARTIAL] warms tunnel | [PARTIAL] | [OPEN] | [OPEN] | [OPEN] ping ghost peer |

**High-value `[OPEN]`s in Matrix 2:** mid-rekey operation safety (P1-009 is this),
force-relay operations, rotate-key end-to-end.

---

## Matrix 3 — Failure Injection × Operation

Where the fault lives vs. what operation is in flight. `chaos` column needs
`tc netem` or equivalent in the compose file.

| Failure \ during | send-file | send-message | task submit | task result | pubsub | trust | register |
|---|---|---|---|---|---|---|---|
| Receiver clean restart | [OPEN] file mid-flight | [OPEN] msg mid-flight | ✓ persistence_restart | ~ accepted-restart (workaround) | [OPEN] subscriber restart | [OPEN] | ✓ p2p |
| Receiver crash (SIGKILL) | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] |
| Sender clean restart | [OPEN] | [OPEN] | [OPEN] submit during restart | [OPEN] | [OPEN] | [OPEN] | [OPEN] |
| Sender crash | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] |
| Rendezvous restart | [OPEN] existing tunnels survive? | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] reregister |
| Beacon restart | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] |
| Packet loss 10% | [OPEN] chaos | [OPEN] chaos | [OPEN] chaos | [OPEN] chaos | [OPEN] chaos | [OPEN] | [OPEN] |
| Packet loss 30% | [OPEN] chaos | [OPEN] chaos | [OPEN] chaos | [OPEN] chaos | [OPEN] chaos | [OPEN] | [OPEN] |
| Packet reorder | [OPEN] chaos | [OPEN] chaos | [OPEN] chaos | [OPEN] chaos | [OPEN] chaos | [OPEN] | [OPEN] |
| Packet delay 200ms | [OPEN] chaos | [OPEN] chaos | [OPEN] chaos | [OPEN] chaos | [OPEN] chaos | [OPEN] | [OPEN] |
| Partition mid-flight | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] |
| Partition heal | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] |
| Disk full (receiver) | [OPEN] received/ write fails gracefully? | [OPEN] inbox/ write fails | [OPEN] tasks/ write fails | [OPEN] | [OPEN] | [OPEN] | [OPEN] |
| Clock skew ±60s | [OPEN] | [OPEN] | [OPEN] deadline correctness | [OPEN] | [OPEN] | [OPEN] trust decay timing | [OPEN] |
| Clock rollback | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] |

**High-value `[OPEN]`s in Matrix 3:** receiver crash (SIGKILL vs graceful),
chaos-mesh packet loss under task flow, partition heal on pub/sub subscriptions.

---

## Matrix 4 — Policy Event × Action × Traffic Type

For each (event, action) pair, does the policy engine enforce it against each
traffic type? `connect` fires on inbound SYN; `datagram` on every packet;
`cycle` on periodic tick; `join` when a peer first enters the network.

| Event → Action | send-file | send-message | task submit | pubsub | trust ops |
|---|---|---|---|---|---|
| connect → allow | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] |
| connect → deny | [OPEN] connection rejected at dial | [OPEN] | ~ task_policy_decline (some coverage) | [OPEN] | [OPEN] |
| connect → score | [OPEN] score credited per dial | [OPEN] | [OPEN] | [OPEN] | [OPEN] |
| connect → tag | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] |
| datagram → allow | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] |
| datagram → deny | [OPEN] per-packet rejection | [OPEN] | [OPEN] | [OPEN] | [OPEN] |
| datagram → score | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] |
| cycle → prune_trust | [N/A] | [N/A] | [N/A] | [N/A] | [OPEN] trust_decay fires as advertised |
| cycle → fill_trust | [N/A] | [N/A] | [N/A] | [N/A] | [OPEN] trust_fill reaches target |
| cycle → evict | [OPEN] inactive peer evicted | [OPEN] | [OPEN] | [OPEN] | [OPEN] |
| cycle → webhook | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] |
| join → allow | [OPEN] membership grant | [OPEN] | [OPEN] | [OPEN] | [OPEN] |
| join → deny | [OPEN] membership refused | [OPEN] | [OPEN] | [OPEN] | [OPEN] |
| join → score | [OPEN] joining peer scored | [OPEN] | [OPEN] | [OPEN] | [OPEN] |

**High-value `[OPEN]`s in Matrix 4:** ~all of it. The policy engine has
decent unit coverage (`pkg/policy/policy_test.go`) but essentially zero
end-to-end integration coverage. Start with `connect → deny` and
`cycle → prune_trust` as templates; everything else follows.

Available shipped policies in `configs/networks/`: `trust-decay`,
`high-trust-society`, `data-exchange-policy` (3 total, not the 30+ from
early ideation — those don't exist as files).

---

## Matrix 5 — Topology × Traffic Pattern

Existing tests are almost all 2-agent (`a ↔ b`). 3+ agent tests would
need compose files with additional agents or dynamically-provisioned peers.

| Topology \ pattern | unicast | fan-out | fan-in | chain | mesh |
|---|---|---|---|---|---|
| 2 agents | ✓ (every existing test) | [N/A] | [N/A] | [N/A] | [N/A] |
| 3 agents | [OPEN] a→b→c task chain | [OPEN] a publishes, b+c receive | [OPEN] b,c task-submit to a concurrently | ✓ task_message_chain (partial: needs a third hop) | [OPEN] a↔b↔c with cross traffic |
| 5 agents | [OPEN] | [OPEN] pubsub fanout ≥ 5 | [OPEN] 5 workers one submitter | [OPEN] 5-hop chain | [OPEN] random pair traffic |
| 10+ agents | [OPEN] | [OPEN] | [OPEN] flash registration | [OPEN] | [OPEN] scale saturation |
| Ring | [OPEN] | [OPEN] | [OPEN] | [OPEN] a→b→c→a loop | [OPEN] |
| Star (1 hub, N leaves) | [OPEN] | [OPEN] hub fan-out to N | [OPEN] N leaves submit to hub | [OPEN] | [OPEN] |
| Split-brain | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] two rendezvous, observe divergence |
| Heal after split | [OPEN] | [OPEN] | [OPEN] | [OPEN] | [OPEN] tasks queued during split complete after heal |

**High-value `[OPEN]`s in Matrix 5:** 3-agent task chain (a→b→c, results
propagate back), 5-agent pubsub fan-out, flash-crowd registration with 10
fresh agents.

---

## Matrix 6 — Security × Attack Vector

Defensive posture: does the protocol resist these with bounded resource usage
and no silent data loss?

| Attack | Layer hit | Existing defense | Test |
|---|---|---|---|
| Replay packet after rekey | tunnel | replay window + AEAD nonce | [OPEN] capture + replay at wire level |
| Spoofed node_id | tunnel | AEAD AAD binds sender nodeID | [OPEN] craft frame with wrong AAD |
| Malformed frame | tunnel | length-prefix bounds check | [OPEN] wire fuzz via nc |
| Oversized payload (>max) | tunnel | size cap | [OPEN] 1 GiB task payload rejection |
| Key-exchange flood | tunnel | rate-limited rekey-request | [OPEN] saturate rekey → verify cap |
| Amplification via unreachable target | beacon | relay-only auth required | [OPEN] ask beacon to relay to third party |
| Symmetric-NAT discovery spoof | beacon | [OPEN] validate | [OPEN] |
| Sybil: many fresh identities | registry | ~ polo_gate blocks task submit from zero-polo | [OPEN] 50 fresh identities, verify reputation gates hold |
| Spam pubsub publish | pubsub | [OPEN] no per-publisher rate limit today | [OPEN] 10k msgs/s single publisher |
| Resource exhaustion via many IPC conns | IPC | P2-002 (open, no per-client quota) | [OPEN] unbounded IPC conn smoke |
| Task submit under polo=0 | tasks | polo gate check | ✓ polo_gate |
| Trust grant forgery | trust | signed grant only | [OPEN] unsigned grant rejection |

**High-value `[OPEN]`s in Matrix 6:** wire-level fuzz, rekey-flood rate-limit
cap, sybil under multiple reputation gates.

---

## Matrix 7 — Cross-Operation Concurrency (Race Surface)

What happens when op A and op B happen at the same time? Same pair, same
millisecond. Each row is a potential race condition test.

| Op A × Op B | Notes | Test |
|---|---|---|
| send-file × send-file (same pair) | Inbox seq atomic must hold under contention | ✓ send_file_concurrent |
| send-file × send-message | Three-service-ports accept-loop contention (1001 + 1002 + 1003) | ~ mixed_traffic_burst |
| send-file × task submit | Filename-seq vs task-id collision | ~ mixed_traffic_burst |
| task submit × task submit (same pair) | sequential_burst; stateful contention on tasks dir | ✓ sequential_burst |
| task submit × task accept (same task) | Accept before submit landed | [OPEN] |
| task accept × task accept (same task, 2 workers) | ✓ concurrent_workers | ✓ |
| task submit × rekey | Frame mid-rekey dropped? | **P1-009 root cause** — [OPEN] direct race test |
| task results × task results (same task, retry) | Double-completion | [PARTIAL] accepted-restart asserts single record |
| pubsub publish × subscribe (just joined) | Late subscriber backlog delivery | [OPEN] |
| pubsub publish × topic delete | Races: publish after delete | [OPEN] topic lifecycle not tested |
| trust grant × trust revoke | Concurrent opposite ops | [OPEN] |
| polo update × polo read | Dashboard pulls mid-update | [OPEN] |
| register × lookup | Lookup during race with registration | [OPEN] |
| Send-file × rekey | File framing fragmentation mid-rekey | [OPEN] |

**High-value `[OPEN]`s in Matrix 7:** mid-rekey direct race repro (the
underlying cause of P1-009), pubsub late-subscriber backlog semantics,
trust grant/revoke race.

---

## Matrix 8 — Payload Size × Operation

Stress at size boundaries. Most tests use small payloads; the protocol has
known issues at size extremes (P1-008 pending queue drops silently).

| Size \ op | send-file | send-message | task result payload | pubsub payload |
|---|---|---|---|---|
| Tiny (1 B) | ✓ part of integrity | ✓ | ✓ result_integrity | [OPEN] |
| Small (1–64 KB) | ✓ integrity, concurrent | ✓ payload_integrity | ✓ | [OPEN] |
| Medium (64 KB–1 MB) | ~ integrity has 50K, 200K | ~ | [OPEN] 1 MiB result payload | [OPEN] |
| Large (1–100 MB) | [OPEN] 50 MB file | [OPEN] 10 MB message (prob rejected) | [OPEN] 10 MB result file | [OPEN] |
| Huge (>100 MB) | [OPEN] 500 MB file — expected to fail, but cleanly | [OPEN] | [OPEN] | [OPEN] |

**High-value `[OPEN]`s in Matrix 8:** 50 MB file (real-world data exchange),
10 MB task result (model inference output size).

---

## Matrix 9 — Duration × Scenario

Long-running tests catch leaks, decay, renewal paths.

| Duration \ scenario | idle | steady traffic | burst | periodic |
|---|---|---|---|---|
| 1s | ✓ every test | ✓ | ✓ | [OPEN] |
| 60s | [OPEN] 1-min idle — no spurious rekey | [OPEN] | ✓ stress_edge | [OPEN] 1 min periodic pubsub |
| 10 min | [OPEN] mem/fd leak detection | [OPEN] | [OPEN] | [OPEN] cycle-tick policy fires once |
| 1 hr | [OPEN] auto-updater check | [OPEN] | [OPEN] | [OPEN] trust-decay 1-cycle observation |
| 24 hr | [OPEN] full decay cycle | [OPEN] | [OPEN] | [OPEN] shipped `cycle: "24h"` default |

**High-value `[OPEN]`s in Matrix 9:** `cycle: "24h"` policy — run with
shortened cycle (`1m`) and verify prune_trust actually prunes at tick.

---

## Matrix 10 — Observability End-to-End

Does the observable state match what the protocol actually did?

| Observable | Producer | Ground-truth check | Test |
|---|---|---|---|
| Dashboard `/api/stats` total_nodes | rendezvous | Count registered agents | ✓ dashboard, p2p |
| Dashboard polo score | rendezvous | Tasks completed × reward math | [OPEN] dashboard-vs-truth polo reconciliation |
| Webhook `task.completed` | daemon | Every completion fires exactly one hook | [OPEN] |
| Webhook `tunnel.established` | tunnel | Fires on key-exchange, with `rekeyed` flag | [OPEN] |
| Log `peer rekeyed` | tunnel | Fires iff peer's X25519 key changed | [OPEN] |
| Metric `EncryptOK` count | tunnel | == number of outbound encrypted frames | [OPEN] |
| `task list --type received/submitted` | daemon | Matches on-disk task files | ~ indirectly across many tests |

**High-value `[OPEN]`s in Matrix 10:** webhook fire-exactly-once under
restart, dashboard polo matches ground-truth.

---

## Prioritization

Recommended sequence for next ticks, biggest gap first:

1. **Policy end-to-end (Matrix 4)** — user explicitly flagged this. Start with
   `connect → deny`, then `cycle → prune_trust`. Template translates to any
   other event/action pair.
2. **3-agent topology (Matrix 5)** — unlocks a→b→c chain tests, which catch
   routing bugs a 2-agent setup can't hit. Requires a new compose file
   `docker-compose.multi3.yml`.
3. **Mid-rekey race direct repro (Matrix 7 + P1-009)** — we have a test that
   works-around the bug; now write one that *hits* it directly for regression
   coverage once the fix lands.
4. **Chaos (Matrix 3)** — add `tc netem` to the compose containers (needs
   `--cap-add NET_ADMIN`); then loss/reorder/delay during task flow.
5. **Large payloads (Matrix 8)** — 50 MB file, 10 MB task result.
6. **Long-duration decay (Matrix 9)** — shortened-cycle trust-decay + time-skip.
7. **SDK coverage (Matrix 1, row 4)** — Python and Node SDK round-trips per op.
8. **Observability reconciliation (Matrix 10)** — dashboard polo vs truth,
   webhook fire-exactly-once.

---

## Notes on implementation hooks

- **Extra agents in the same compose:** add `agent-c`, `agent-d` services
  cloned from `agent-b`. The parallel runner's subnet parameterization
  (`PILOT_SUBNET_PREFIX`) means a second compose file (`docker-compose.multi3.yml`)
  with 3 agents plays nicely with 4-way worker isolation.
- **Chaos containers need `cap_add: NET_ADMIN`** plus `apt install iproute2`
  in `Dockerfile.multi`. `tc qdisc add dev eth0 root netem loss 10%` is the
  standard incantation.
- **Short-cycle policies for tests:** configs with `"cycle": "5s"` make
  24-hour policy math testable in seconds.
- **Wire-level fuzz** can be scripted from any agent container with Python
  `socket` — no new tooling required.
- **Webhook verification** needs a tiny sink container (10 lines of Python
  `http.server`) receiving POSTs and logging them for assertion.
