# Integration Test Build-Out Plan

Target: close all 338 red cells across 10 matrices (per `COVERAGE-REPORT.md`).
Approach: 8 work chunks, each a natural cluster of tests that share fixtures.
Agents run in parallel, one per chunk.

## Shared conventions every test must follow

All new tests live under `tests/integration/` next to the existing ones and follow the exact pattern in `test_p2p.sh`:

```bash
#!/bin/bash
# <one-paragraph description of what this proves>

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'
PASSED=0
FAILED=0

ts() { date '+%Y-%m-%d %H:%M:%S'; }
log_test() { echo -e "[$(ts)] ${YELLOW}[TEST]${NC} $*"; }
log_pass() { echo -e "[$(ts)] ${GREEN}[PASS]${NC} $*"; PASSED=$((PASSED+1)); }
log_fail() { echo -e "[$(ts)] ${RED}[FAIL]${NC} $*"; FAILED=$((FAILED+1)); }

DC="docker compose -f docker-compose.multi.yml"

cd "$(dirname "$0")" || exit 1
# body...
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
```

- File name: `test_<chunk>_<scenario>.sh`, executable, in `tests/integration/`.
- Each test starts `$DC down -v` → `$DC up -d` and asserts `total_nodes >= N` before running.
- Final exit code reflects `FAILED == 0`.
- Always cleanup (`docker compose down` OR `touch /tmp/worker_stop`).
- Never log secrets. Never commit generated files into git.
- Runner `run-all.sh` auto-discovers `test_*.sh`; do not edit it.

Shared reference tests (read before authoring):
- `test_p2p.sh` — overall skeleton.
- `test_chaos_packet_loss.sh` — tc netem pattern, chaos overlay usage.
- `test_task_accepted_restart_recovery.sh` — worker loop pattern.
- `test_rendezvous_restart_midflight.sh` — stop/start service mid-test pattern.
- `test_ping_ghost_peer.sh` — fail-bounded-time pattern.

---

## Chunk A — Chaos / Failure-injection (Matrix 3, 102 cells)

Uses `docker-compose.multi.chaos.yml` (already exists) which grants `NET_ADMIN`. Adds tc netem + iptables partitions.

**Tests (one script per failure × op group):**
1. `test_chaos_loss10_all_ops.sh` — 10 % loss × {ping, message, file, task-submit, task-result, pubsub, trust, register}
2. `test_chaos_loss30_all_ops.sh` — 30 % loss × same 7 ops (known to reproduce P1-010)
3. `test_chaos_reorder_all_ops.sh` — `netem reorder 25% 50%` × 7 ops
4. `test_chaos_delay200_all_ops.sh` — `netem delay 200ms 50ms` × 7 ops
5. `test_partition_midflight.sh` — iptables DROP between a↔b during each op
6. `test_partition_heal.sh` — partition then heal; tasks queued during split complete after heal
7. `test_disk_full_receiver.sh` — bind-mount tmpfs size=1M at receiver's `/root/.pilot/received`, verify graceful error (not data corruption)
8. `test_clock_skew_receiver.sh` — `faketime` container image or `date -s`; ±60 s skew × deadline-sensitive ops
9. `test_clock_rollback.sh` — clock jumps backwards; verify no replay-window corruption
10. `test_receiver_sigkill_midfile.sh` — SIGKILL agent-b during in-flight send-file; assert sender reports clean error, no corruption on restart
11. `test_receiver_sigkill_midtask.sh` — SIGKILL agent-b between task ACCEPTED and results; submitter must see FAILED/EXPIRED, not stuck
12. `test_sender_sigkill_midfile.sh` — SIGKILL agent-a during send-file; receiver must clean up partial
13. `test_sender_clean_restart_midflight.sh` — `docker compose restart agent-a` during ops
14. `test_beacon_restart_midflight.sh` — stop/start rendezvous (same container hosts beacon at :9001)
15. `test_rendezvous_beacon_split.sh` — what if only the beacon side dies?

**Helpers to add:**
- `chaos_helpers.sh` (sourced) with `apply_loss`, `apply_reorder`, `apply_delay`, `apply_partition`, `heal_partition`, `strip_chaos`.

**Cells closed:** Matrix 3 rows 2–15 × 7 ops = 98 cells, Matrix 2 `peer-restarted` for sender, Matrix 6 replay-window.

---

## Chunk B — Policy engine end-to-end (Matrix 4, 56 cells)

Every shipped config under `configs/networks/*.json` must be exercised. Some need a short `"cycle"` override for CI; author a build-time override helper.

**Tests:**
1. `test_policy_connect_allow.sh` — load allow-all config, verify traffic passes; check policy event counter increments.
2. `test_policy_connect_deny.sh` — load deny-all; verify every op type (file/msg/submit/pubsub/trust) is refused with clear error.
3. `test_policy_connect_score.sh` — load scoring config; verify polo delta per dial.
4. `test_policy_connect_tag.sh` — load tagging config; verify peer is tagged in registry.
5. `test_policy_datagram_allow.sh` / `_deny.sh` / `_score.sh` — per-packet rules.
6. `test_policy_cycle_prune_trust.sh` — load `trust-decay` with `"cycle": "5s"`; verify trust links decay at tick.
7. `test_policy_cycle_fill_trust.sh` — inverse: trust links are auto-restored toward target.
8. `test_policy_cycle_evict.sh` — inactive peer evicted after N cycles.
9. `test_policy_cycle_webhook.sh` — cycle-triggered webhook fires.
10. `test_policy_join_allow.sh` / `_deny.sh` / `_score.sh` — membership gating on first join.
11. `test_policy_shipped_configs.sh` — smoke every `configs/networks/*.json` loads without error and the daemon reports it active.

**Helpers:**
- `policy_helpers.sh` — `load_policy "<path>"`, `wait_cycle_tick`, `assert_policy_counter <event> <count>`.

**Cells closed:** Matrix 4 entire matrix (57 of 57 applicable).

---

## Chunk C — Multi-agent topologies (Matrix 5, 34 cells)

Adds new compose files for 3+ agent clusters. Subnet-parameterized like existing.

**Compose files to add:**
- `docker-compose.multi3.yml` — rendezvous + agent-a + agent-b + agent-c
- `docker-compose.multi5.yml` — rendezvous + a,b,c,d,e
- `docker-compose.ring4.yml` — 4 agents + 1 rendezvous; policy forces ring edges only
- `docker-compose.star5hub.yml` — 1 hub agent + 4 leaves
- `docker-compose.multi10.yml` — 10-agent flash-crowd topology
- `docker-compose.splitbrain.yml` — 2 rendezvous services + agents partitioned between them

**Tests:**
1. `test_chain_abc_task.sh` — a→b→c task forwarding, result propagates back
2. `test_chain_abc_message.sh` — a→b→c message chain
3. `test_fanout_3agents_msg.sh` — a broadcasts, b+c receive via pubsub
4. `test_fanout_3agents_file.sh` — same but send-file fan-out
5. `test_fanin_3agents_tasks.sh` — b,c submit tasks to a concurrently
6. `test_mesh_3agents_crosstraffic.sh` — full mesh, random cross traffic
7. `test_fanout_5agents_pubsub.sh` — 5 subscribers one publisher
8. `test_ring4_routing.sh` — a→b→c→d→a loop
9. `test_star5_hub_fanout.sh` — hub publishes to 4 leaves
10. `test_star5_hub_fanin.sh` — 4 leaves submit to hub concurrently
11. `test_flash_crowd_10agents_register.sh` — all 10 register within 5 s, registry accurate
12. `test_splitbrain_divergence.sh` — 2 rendezvous, each sees half
13. `test_splitbrain_heal.sh` — reconnect; tasks queued during split complete after heal
14. `test_3agent_lookup_propagation.sh` — c's registration visible from a

**Helpers:**
- Add agent-c, agent-d, agent-e to base Dockerfile.multi (already generic) or use different hostnames via env.
- `topology_helpers.sh` — `wait_all_registered <count>`, `agent_addr_for <name>`.

**Cells closed:** Matrix 5 rows 3-agents through Heal (34 of 34 applicable).

---

## Chunk D — Security / adversarial (Matrix 6, 11 cells)

Wire-level attacks. Requires a raw UDP sender container (bind `python3` or `nc` into compose).

**Tests:**
1. `test_sec_replay_after_rekey.sh` — capture a valid encrypted packet, replay after the rekey interval. AEAD nonce + replay window must reject.
2. `test_sec_spoofed_node_id.sh` — craft frame with wrong AAD (node-id mismatch). Must be dropped.
3. `test_sec_malformed_frame.sh` — truncated headers, bad magic, overflow length prefix. No panic, no deadlock.
4. `test_sec_oversized_payload.sh` — 1 GiB task payload. Must be rejected at input validation, not OOM the daemon.
5. `test_sec_rekey_flood.sh` — send 10k rekey requests / s from one peer. Rate-limit must cap; CPU must stay bounded.
6. `test_sec_beacon_amplification.sh` — ask beacon to relay to an unreachable third party. Beacon must require prior registration, not reflect.
7. `test_sec_sym_nat_spoof.sh` — claim to be behind symmetric NAT with forged endpoint, verify no state corruption.
8. `test_sec_sybil_reputation.sh` — create 50 fresh identities in 1 s, attempt task submit. Polo-gate must block all (zero reputation).
9. `test_sec_pubsub_spam.sh` — single publisher pushes 10 k msgs/s; per-publisher rate limit fires or the daemon sheds cleanly.
10. `test_sec_ipc_exhaustion.sh` — open 10 k concurrent IPC conns to the daemon. Per-client cap must trip before FD exhaustion (P2-002).
11. `test_sec_trust_grant_forgery.sh` — unsigned trust-grant frame. Must be rejected.

**Helpers:**
- `raw_udp.py` — scapy-less raw UDP sender, parameterized.
- `sec_helpers.sh` — `capture_tunnel_frame`, `craft_frame <magic> <nodeid> <payload>`.

**Cells closed:** Matrix 6 entire matrix.

---

## Chunk E — Webhooks + observability (Matrix 1 row 7 + Matrix 10, 15 cells)

Adds a webhook-sink container (tiny Python `http.server` that logs all POSTs to a shared volume).

**Infrastructure:**
- `docker-compose.multi.webhooks.yml` — overlay adding `webhook-sink` service on :18080, shared `webhook_log/` volume.
- `webhook_sink.py` — ~30 lines, writes `{ts, path, body}` as JSON lines to `/var/log/webhooks.jsonl`.

**Tests:**
1. `test_webhook_file_delivered.sh` — configure `file.delivered` hook, send-file, assert one POST.
2. `test_webhook_message_received.sh`
3. `test_webhook_task_submitted.sh`
4. `test_webhook_task_completed.sh`
5. `test_webhook_pubsub_published.sh`
6. `test_webhook_trust_changed.sh`
7. `test_webhook_polo_updated.sh`
8. `test_webhook_agent_registered.sh`
9. `test_webhook_tunnel_established.sh`
10. `test_webhook_exactly_once_on_restart.sh` — kill receiver between task ACCEPTED and SUCCEEDED; webhook count = exactly 1.
11. `test_obs_dashboard_polo_truth.sh` — submit N tasks with known reward math; dashboard polo must equal computed value within 1 unit.
12. `test_obs_log_peer_rekeyed.sh` — force rekey via `pilotctl rotate-key` (or time); exactly one `peer rekeyed` log line with matching node id.
13. `test_obs_metric_encrypt_ok.sh` — send M files; `EncryptOK` metric delta == M × expected frames per file.
14. `test_obs_tasklist_vs_disk.sh` — `pilotctl task list` matches on-disk JSON files 1:1.

**Cells closed:** Matrix 1 webhook row (9 cells) + Matrix 10 (5 remaining cells) = 14.

---

## Chunk F — Operation × state preconditions (Matrix 2 remaining, 49 cells)

Mid-rekey, force-relay, post-restart, peer-gone patterns.

**Tests:**
1. `test_midrekey_send_file.sh` — start a rekey, send file during the in-flight key change. File must complete (direct P1-009 regression test).
2. `test_midrekey_send_message.sh`
3. `test_midrekey_task_submit.sh`
4. `test_midrekey_task_results.sh`
5. `test_force_relay_send_file.sh` — force both agents to use the beacon relay (simulate symmetric NAT via iptables); file must arrive.
6. `test_force_relay_send_message.sh`
7. `test_force_relay_task.sh`
8. `test_force_relay_pubsub.sh`
9. `test_peer_restarted_send_file.sh` — restart b, then a sends; tunnel re-established.
10. `test_peer_restarted_send_message.sh`
11. `test_peer_restarted_pubsub_sub.sh` — subscriber restarts; does it resubscribe?
12. `test_submit_to_unregistered_peer.sh` — task submit to a node the registry has never seen.
13. `test_results_after_submitter_died.sh` — submitter killed between ACCEPTED and results; worker sends results; what happens?
14. `test_pubsub_subscribe_before_publisher.sh` — sub joins an empty topic; publisher joins later; backlog delivery?
15. `test_pubsub_publish_to_empty_topic.sh`
16. `test_trust_grant_fresh.sh` — only `revoke` is covered today; grant from scratch.
17. `test_trust_grant_already_connected.sh`
18. `test_polo_persistence_restart.sh` — polo score survives daemon restart.
19. `test_register_identity_new_endpoint.sh` — same identity, new IP; old entry superseded.
20. `test_rotate_key_hot_path.sh` — placeholder; returns SKIP until task #146 ships.

**Cells closed:** Matrix 2 remaining 49 cells.

---

## Chunk G — Cross-op races + large payloads + duration (Matrix 7 + 8 + 9, 44 cells)

**Matrix 7 race tests:**
1. `test_race_submit_accept.sh` — accept before submit landed.
2. `test_race_submit_rekey.sh` — direct P1-009 repro (currently workaround-tested).
3. `test_race_pubsub_late_sub.sh`
4. `test_race_topic_delete_publish.sh`
5. `test_race_trust_grant_revoke.sh`
6. `test_race_polo_read_write.sh`
7. `test_race_register_lookup.sh`
8. `test_race_sendfile_rekey.sh`

**Matrix 8 large payloads:**
9. `test_size_file_10mb.sh`
10. `test_size_file_50mb.sh`
11. `test_size_file_100mb.sh`
12. `test_size_file_500mb_reject.sh` — expected to fail cleanly.
13. `test_size_message_10mb_reject.sh` — messages have a smaller cap.
14. `test_size_task_result_10mb.sh` — real AI-agent output size.
15. `test_size_pubsub_large.sh`

**Matrix 9 duration:**
16. `test_dur_idle_60s.sh` — verify no spurious rekey (should be > rekey interval).
17. `test_dur_idle_10min.sh` — mem/fd snapshot before, after; delta below threshold.
18. `test_dur_steady_10min.sh` — constant 10 msg/s for 10 min; mem/fd stable.
19. `test_dur_periodic_60s.sh` — 1 msg/s for 60 s.
20. `test_dur_shortcycle_policy_1m.sh` — `cycle: "5s"` trust-decay policy runs 60 s → ≥ 10 cycle events observed.
21. `test_dur_steady_24h_shortscale.sh` — compressed 24 h run: policy with `"cycle": "1s"` runs 300 s = 300 cycles, mimics 24 h × default `"cycle": "24h"` behavior.

**Cells closed:** Matrix 7 (8), Matrix 8 remaining (~12), Matrix 9 (~16). Some shorter durations covered as part of existing; bulk closes ~30 cells.

---

## Chunk H — Gateway + beacon ping + SDK-less misc (Matrix 1 rows 3, 8 — 13 cells)

**Tests:**
1. `test_beacon_ping.sh` — agent→beacon ping (beacon hosts a ping endpoint for liveness). Matrix 1 row 3 only open cell.
2. `test_gateway_file.sh` — send file through local gateway proxy.
3. `test_gateway_http_message.sh` — HTTP-over-pilot round-trip via gateway.
4. `test_gateway_task_submit.sh`
5. `test_gateway_task_result.sh`
6. `test_gateway_pubsub_pub.sh`
7. `test_gateway_pubsub_sub.sh`
8. `test_gateway_trust_grant.sh`
9. `test_gateway_polo_read.sh`
10. `test_gateway_lookup.sh`
11. `test_gateway_register.sh`
12. `test_gateway_rotate_key.sh`
13. `test_gateway_ping.sh`

**Infrastructure:** gateway service added to compose in an overlay `docker-compose.multi.gateway.yml` (gateway binary already exists).

**Cells closed:** Matrix 1 rows 3 + 8 (13 cells).

---

## Total accounting

| Chunk | Files added | Matrix cells closed |
|---|---:|---:|
| A chaos         | ~15 tests + 1 helper   | ~102 |
| B policy        | ~12 tests + 1 helper   | ~57 |
| C topologies    | ~14 tests + 6 compose  | ~34 |
| D security      | ~11 tests + 2 helpers  | ~11 |
| E webhooks+obs  | ~14 tests + sink       | ~15 |
| F preconditions | ~20 tests              | ~49 |
| G races/size/dur| ~21 tests              | ~36 |
| H gateway+misc  | ~13 tests + 1 compose  | ~13 |
| **Total**       | **~120 files**         | **~317 of 338** |

Remaining 21 cells are either duplicates already handled by parametrized tests or dependent on task #146 (rotate-key) shipping.

---

## Known-red tests (expected failures on first run)

Author the test against the spec, not the current implementation. A red-on-first-run test is a **finding**, not a bug in the test. Flag in the PR description:
- `test_chaos_loss30_all_ops.sh` — currently reproduces P1-010.
- `test_midrekey_*` — reproduces P1-009 directly.
- `test_disk_full_receiver.sh` — behavior unknown.
- `test_sec_rekey_flood.sh` — cap may not exist.
- `test_sec_ipc_exhaustion.sh` — P2-002 still open.
- `test_webhook_*` — webhook implementation status unverified; tests may reveal unimplemented hooks.
- `test_rotate_key_hot_path.sh` — task #146 pending; test will SKIP.

---

## Agent assignments

Each chunk is assigned to one subagent running in parallel. Agent prompt template is in `AGENT-PROMPT-TEMPLATE.md`.
