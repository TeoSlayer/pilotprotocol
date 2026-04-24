# Integration test run summary

- Run duration: 1221s
- Workers: 10
- Tests: 76 (pass=3, fail=73)
- Serial sum: 6106s (speedup = 5.00x)
- Utilization: w0=99.9% w1=44.8% w2=42.3% w3=50.1% w4=43.7% w5=45.7% w6=45.9% w7=40.6% w8=45.0% w9=42.0% 

| Status | Test | Duration | Exit |
|--------|------|----------|------|
| FAIL | `test_resilience.sh` | 1220s | 1 |
| FAIL | `test_dur_steady_10min.sh` | 612s | 1 |
| FAIL | `test_dur_steady_compressed_24h.sh` | 308s | 1 |
| FAIL | `test_cli.sh` | 279s | 1 |
| FAIL | `test_chaos_loss30_all_ops.sh` | 212s | 1 |
| FAIL | `test_ping_ghost_peer.sh` | 181s | 1 |
| FAIL | `test_chaos_packet_loss.sh` | 159s | 1 |
| FAIL | `test_register_identity_new_endpoint.sh` | 140s | 1 |
| FAIL | `test_force_relay_task.sh` | 138s | 1 |
| FAIL | `test_ring4_routing.sh` | 132s | 1 |
| FAIL | `test_rendezvous_restart_midflight.sh` | 122s | 1 |
| FAIL | `test_webhook_exactly_once_on_restart.sh` | 106s | 1 |
| FAIL | `test_webhook_file_delivered.sh` | 103s | 1 |
| FAIL | `test_force_relay_pubsub.sh` | 97s | 1 |
| FAIL | `test_midrekey_task_results.sh` | 95s | 1 |
| FAIL | `test_webhook_pubsub_published.sh` | 89s | 1 |
| FAIL | `test_fanin_3agents_tasks.sh` | 87s | 1 |
| FAIL | `test_gateway_http_message.sh` | 84s | 1 |
| FAIL | `test_webhook_task_completed.sh` | 84s | 1 |
| FAIL | `test_webhook_task_submitted.sh` | 83s | 1 |
| FAIL | `test_beacon_restart_midflight.sh` | 82s | 1 |
| FAIL | `test_net_mutual_admiration_shipped.sh` | 79s | 1 |
| FAIL | `test_webhook_tunnel_established.sh` | 77s | 1 |
| FAIL | `test_webhook_trust_changed.sh` | 76s | 1 |
| FAIL | `test_splitbrain_divergence.sh` | 74s | 1 |
| FAIL | `test_nat_dual_symmetric.sh` | 71s | 1 |
| FAIL | `test_partition_heal.sh` | 69s | 1 |
| FAIL | `test_dur_shortcycle_policy_1m.sh` | 68s | 1 |
| FAIL | `test_receiver_sigkill_midfile.sh` | 59s | 1 |
| FAIL | `test_sender_clean_restart_midflight.sh` | 49s | 1 |
| FAIL | `test_webhook_message_received.sh` | 49s | 1 |
| FAIL | `test_policy_datagram_score.sh` | 48s | 1 |
| FAIL | `test_net_data_exchange_policy_shipped.sh` | 47s | 1 |
| FAIL | `test_webhook_agent_registered.sh` | 44s | 1 |
| FAIL | `test_policy_connect_deny.sh` | 41s | 1 |
| FAIL | `test_net_polo_scoped_per_network.sh` | 39s | 1 |
| FAIL | `test_net_trust_scoped_per_network.sh` | 39s | 1 |
| FAIL | `test_sec_trust_grant_forgery.sh` | 35s | 1 |
| FAIL | `test_net_burnout_shipped.sh` | 31s | 1 |
| FAIL | `test_net_gossip_tax_shipped.sh` | 26s | 1 |
| FAIL | `test_tasks_and_edge.sh` | 24s | 1 |
| FAIL | `test_gateway_trust_grant.sh` | 23s | 1 |
| FAIL | `test_net_half_life_shipped.sh` | 23s | 1 |
| FAIL | `test_net_isolation_policy_scoping.sh` | 22s | 1 |
| FAIL | `test_chaos_delay200_all_ops.sh` | 21s | 1 |
| FAIL | `test_net_anti_camping_shipped.sh` | 21s | 1 |
| FAIL | `test_net_golden_hour_shipped.sh` | 21s | 1 |
| FAIL | `test_net_high_trust_society_shipped.sh` | 21s | 1 |
| FAIL | `test_net_lottery_shipped.sh` | 21s | 1 |
| FAIL | `test_task_executor.sh` | 21s | 1 |
| FAIL | `test_chaos_loss10_all_ops.sh` | 20s | 1 |
| FAIL | `test_net_cold_shoulder_shipped.sh` | 19s | 1 |
| FAIL | `test_net_gift_economy_shipped.sh` | 18s | 1 |
| FAIL | `test_net_karma_ledger_shipped.sh` | 18s | 1 |
| FAIL | `test_net_tithe_shipped.sh` | 18s | 1 |
| FAIL | `test_net_meritocracy_rating_shipped.sh` | 16s | 1 |
| FAIL | `test_net_meritocracy_shipped.sh` | 16s | 1 |
| FAIL | `test_net_ostracism_shipped.sh` | 16s | 1 |
| FAIL | `test_sec_ipc_exhaustion.sh` | 16s | 1 |
| FAIL | `test_net_pay_it_forward_shipped.sh` | 15s | 1 |
| FAIL | `test_policy_cycle_webhook.sh` | 15s | 1 |
| FAIL | `test_policy_datagram_deny.sh` | 15s | 1 |
| FAIL | `test_net_rotating_chairs_shipped.sh` | 14s | 1 |
| FAIL | `test_net_stable_state_shipped.sh` | 14s | 1 |
| FAIL | `test_policy_cycle_fill_trust.sh` | 14s | 1 |
| FAIL | `test_net_two_strikes_shipped.sh` | 13s | 1 |
| FAIL | `test_net_cooling_off_shipped.sh` | 12s | 1 |
| FAIL | `test_net_small_circle_shipped.sh` | 12s | 1 |
| FAIL | `test_net_cross_network_traffic_denied.sh` | 11s | 1 |
| FAIL | `test_net_whale_hunt_shipped.sh` | 11s | 1 |
| FAIL | `test_policy_join_allow.sh` | 11s | 1 |
| FAIL | `test_net_join_deny_per_network.sh` | 9s | 1 |
| FAIL | `test_splitbrain_heal.sh` | 6s | 1 |
| PASS | `test_nat_asymmetric_routing.sh` | 96s | 0 |
| PASS | `test_policy_cycle_evict.sh` | 15s | 0 |
| PASS | `test_net_aristocracy_shipped.sh` | 14s | 0 |

## Failed logs

### `test_splitbrain_heal.sh` (exit=1, 6s)

```
==========================================
Split-brain heal
==========================================
[2026-04-23 19:10:36] [1;33m[TEST][0m Starting splitbrain stack
[2026-04-23 19:10:41] [0;31m[FAIL][0m split not set up (c1=3 c2=2)
```

### `test_net_mutual_admiration_shipped.sh` (exit=1, 79s)

```
[2026-04-23 19:10:42] [0;32m[PASS][0m net=1
[2026-04-23 19:10:45] [1;33m[TEST][0m unilateral connect produces no score (until mutual)
[2026-04-23 19:11:55] [0;31m[FAIL][0m no mutual bonus: uni=0 mutual=0 (EXPECTED: increase on reciprocation)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_gateway_http_message.sh` (exit=1, 84s)

```
==========================================
Gateway: HTTP/message round-trip via proxy
==========================================
[2026-04-23 19:10:41] [0;32m[PASS][0m agent-b pilot addr: 0:0000.0000.0002
[2026-04-23 19:10:41] [1;33m[TEST][0m map agent-b into gateway local subnet
[2026-04-23 19:10:42] [0;32m[PASS][0m mapped 0:0000.0000.0002 -> 10.4.0.1
[2026-04-23 19:10:42] [1;33m[TEST][0m send payload to 10.4.0.1:1001 (agent-b's data-exchange service)
[2026-04-23 19:11:57] [0;31m[FAIL][0m could not open TCP to 10.4.0.1:1001 via gateway
[2026-04-23 19:11:59] [1;33m[TEST][0m payload delivered to agent-b inbox
[2026-04-23 19:11:59] [0;31m[FAIL][0m payload not found in agent-b inbox; gateway proxy may not have delivered
time=2026-04-24T02:10:42.481Z level=INFO msg="gateway connected" subnet=10.4.0.0/16
time=2026-04-24T02:10:42.481Z level=INFO msg="gateway running"

Passed: 2  Failed: 2
```

### `test_beacon_restart_midflight.sh` (exit=1, 82s)

```
==========================================
Beacon restart mid-flight
==========================================
[2026-04-23 19:10:47] [0;32m[PASS][0m both agents registered
[2026-04-23 19:10:47] [1;33m[TEST][0m warm task before beacon restart
[2026-04-23 19:10:48] [0;32m[PASS][0m warm ok
[2026-04-23 19:10:48] [1;33m[TEST][0m docker compose restart rendezvous (beacon container)
[2026-04-23 19:10:49] [0;32m[PASS][0m rendezvous+beacon container back online
[2026-04-23 19:10:49] [1;33m[TEST][0m both agents re-register post-beacon-restart
[2026-04-23 19:10:49] [0;32m[PASS][0m total_nodes=3
[2026-04-23 19:10:49] [1;33m[TEST][0m task still completes post-beacon-restart
[2026-04-23 19:12:03] [0;31m[FAIL][0m post-beacon task stuck (status=)
[2026-04-23 19:12:03] [1;33m[TEST][0m pilotctl lookup works post-beacon-restart
[2026-04-23 19:12:03] [0;32m[PASS][0m lookup ok: 0:0000.0000.0003
[2026-04-23 19:12:03] [1;33m[TEST][0m no panic/fatal in agent logs
[2026-04-23 19:12:03] [0;32m[PASS][0m clean logs

Passed: 6  Failed: 1
```

### `test_chaos_delay200_all_ops.sh` (exit=1, 21s)

```
==========================================
Chaos: 200ms delay x all 7 op families
==========================================
[2026-04-23 19:12:01] [0;32m[PASS][0m both agents registered
[2026-04-23 19:12:03] [1;33m[TEST][0m apply 200ms +/-50ms delay on agent-b eth0
[2026-04-23 19:12:03] [0;32m[PASS][0m netem delay applied
[2026-04-23 19:12:03] [1;33m[TEST][0m ping under 200ms delay
[2026-04-23 19:12:08] [0;32m[PASS][0m ping ok
[2026-04-23 19:12:08] [1;33m[TEST][0m send-message under delay
[2026-04-23 19:12:09] [0;32m[PASS][0m send-message ok
[2026-04-23 19:12:09] [1;33m[TEST][0m send-file 16 KiB under 200ms delay
[2026-04-23 19:12:11] [0;32m[PASS][0m send-file sha match
[2026-04-23 19:12:11] [1;33m[TEST][0m task submit under 200ms delay (90s)
[2026-04-23 19:12:12] [0;31m[FAIL][0m task stuck (status=)
[2026-04-23 19:12:12] [1;33m[TEST][0m pubsub publish under delay
[2026-04-23 19:12:12] [0;32m[PASS][0m publish ok
test_chaos_delay200_all_ops.sh: line 118: handshake: command not found
test_chaos_delay200_all_ops.sh: line 118: approve: command not found
[2026-04-23 19:12:12] [1;33m[TEST][0m trust handshake under delay (real CLI:  + receiver )
[2026-04-23 19:12:13] [0;32m[PASS][0m handshake ok
[2026-04-23 19:12:13] [1;33m[TEST][0m pilotctl find agent-b (registry lookup) under delay
[2026-04-23 19:12:13] [0;32m[PASS][0m registry lookup ok
[2026-04-23 19:12:13] [1;33m[TEST][0m strip delay and sanity ping
[2026-04-23 19:12:15] [0;32m[PASS][0m post-chaos ping ok
[2026-04-23 19:12:15] [1;33m[TEST][0m no panic/fatal
[2026-04-23 19:12:15] [0;32m[PASS][0m clean logs

Passed: 10  Failed: 1
```

### `test_chaos_loss10_all_ops.sh` (exit=1, 20s)

```
==========================================
Chaos: 10% loss x all 7 op families
==========================================
[2026-04-23 19:12:01] [1;33m[TEST][0m fresh chaos-capable stack
[2026-04-23 19:12:05] [0;32m[PASS][0m both agents registered
[2026-04-23 19:12:06] [1;33m[TEST][0m apply 10% loss on agent-b eth0
[2026-04-23 19:12:07] [0;32m[PASS][0m netem 10% loss applied
[2026-04-23 19:12:07] [1;33m[TEST][0m ping a->b under 10% loss
[2026-04-23 19:12:11] [0;32m[PASS][0m ping ok
[2026-04-23 19:12:11] [1;33m[TEST][0m send-message a->b under 10% loss
[2026-04-23 19:12:12] [0;32m[PASS][0m send-message returned
[2026-04-23 19:12:12] [1;33m[TEST][0m send-file 8 KiB under 10% loss (sha256 match)
[2026-04-23 19:12:13] [0;32m[PASS][0m send-file sha match
[2026-04-23 19:12:13] [1;33m[TEST][0m task submit a->b under 10% loss (completes)
[2026-04-23 19:12:13] [0;31m[FAIL][0m task submit failed: {"code":"connection_failed","error":"submit: EOF","message":"submit: EOF","status":"error"}
[2026-04-23 19:12:13] [1;33m[TEST][0m pubsub publish a->b/sensor/chaos
[2026-04-23 19:12:14] [0;32m[PASS][0m publish ok
[2026-04-23 19:12:14] [1;33m[TEST][0m trust handshake a->b under 10% loss
[2026-04-23 19:12:15] [0;32m[PASS][0m handshake returned
[2026-04-23 19:12:15] [1;33m[TEST][0m pilotctl find agent-b (registry lookup) under 10% loss
[2026-04-23 19:12:15] [0;32m[PASS][0m registry lookup ok
[2026-04-23 19:12:16] [1;33m[TEST][0m strip netem, baseline ping still works
[2026-04-23 19:12:18] [0;32m[PASS][0m post-chaos ping ok
[2026-04-23 19:12:18] [1;33m[TEST][0m no panic/fatal in agent logs
[2026-04-23 19:12:18] [0;32m[PASS][0m clean logs

Passed: 10  Failed: 1
```

### `test_rendezvous_restart_midflight.sh` (exit=1, 122s)

```
==========================================
Rendezvous restart mid-flight
==========================================
[2026-04-23 19:10:36] [1;33m[TEST][0m Starting p2p stack (clean)
[2026-04-23 19:10:40] [0;32m[PASS][0m both agents registered
[2026-04-23 19:10:41] [1;33m[TEST][0m warm-up task to establish tunnel + peer caches
[2026-04-23 19:10:43] [0;32m[PASS][0m tunnel warm (status=SUCCEEDED)
[2026-04-23 19:10:43] [1;33m[TEST][0m stop rendezvous container (keep agents up)
[2026-04-23 19:10:46] [0;32m[PASS][0m rendezvous stopped; still running: agent-a agent-b gateway 
[2026-04-23 19:10:46] [1;33m[TEST][0m task a->b completes while rendezvous down (30s)
[2026-04-23 19:11:26] [0;31m[FAIL][0m submit during outage failed: {"code":"not_found","error":"cannot resolve \"agent-b\" — is the hostname correct and is there mutual trust? (see: pilotctl handshake)","message":"cannot resolve \"agent-b\" — is the hostname correct and is there mutual trust? (see: pilotctl handshake)","status":"error"}
[2026-04-23 19:11:26] [1;33m[TEST][0m send-file 2 KiB a->b while rendezvous down
[2026-04-23 19:11:47] [0;31m[FAIL][0m file mismatch under outage src=deeed68345b2... dst=... ack=
[2026-04-23 19:11:47] [1;33m[TEST][0m start rendezvous back up
[2026-04-23 19:11:48] [0;32m[PASS][0m both agents re-registered post-rendezvous-restart (total=3)
[2026-04-23 19:11:48] [1;33m[TEST][0m pilotctl find agent-b from agent-a resolves
[2026-04-23 19:11:55] [0;32m[PASS][0m lookup resolved: 0:0000.0000.0002
[2026-04-23 19:11:55] [1;33m[TEST][0m task a->b completes post-rendezvous-restart
[2026-04-23 19:12:37] [0;31m[FAIL][0m post-restart task stuck (status=)
[2026-04-23 19:12:37] [1;33m[TEST][0m no panics/fatals in agent logs
[2026-04-23 19:12:37] [0;32m[PASS][0m clean logs

==========================================
Rendezvous restart summary
==========================================
Passed: [0;32m6[0m
Failed: [0;31m3[0m
==========================================
```

### `test_force_relay_task.sh` (exit=1, 138s)

```
==========================================
Force relay: task submit+complete
==========================================
[2026-04-23 19:10:43] [1;33m[TEST][0m partition direct UDP
[2026-04-23 19:10:44] [0;32m[PASS][0m direct severed
[2026-04-23 19:10:54] [1;33m[TEST][0m task submit a->b via relay
[2026-04-23 19:10:54] [0;31m[FAIL][0m submit failed at door: {"code":"connection_failed","error":"submit: EOF","message":"submit: EOF","status":"error"}
[2026-04-23 19:10:54] [1;33m[TEST][0m task reaches completion via relay
[2026-04-23 19:12:52] [0;31m[FAIL][0m stuck at  — likely P1-010
[2026-04-23 19:12:52] [1;33m[TEST][0m no panic/fatal
[2026-04-23 19:12:52] [0;32m[PASS][0m clean logs

Passed: 2  Failed: 2
```

### `test_gateway_trust_grant.sh` (exit=1, 23s)

```
==========================================
Gateway: trust grant agent-b
==========================================
[2026-04-23 19:13:13] [1;33m[TEST][0m gateway initiates handshake to agent-b
[2026-04-23 19:13:14] [0;32m[PASS][0m handshake sent
[2026-04-23 19:13:14] [1;33m[TEST][0m agent-b sees gateway in pending
[2026-04-23 19:13:14] [0;32m[PASS][0m agent-b has gateway in pending
jq: parse error: Invalid numeric literal at line 1, column 6
[2026-04-23 19:13:14] [1;33m[TEST][0m gateway trust list contains agent-b after approval
[2026-04-23 19:13:17] [0;31m[FAIL][0m agent-b (node_id=2) not in gateway trust list
{"data":{"trusted":[]},"status":"ok"}

Passed: 2  Failed: 1
```

### `test_dur_shortcycle_policy_1m.sh` (exit=1, 68s)

```
==========================================
Duration: short-cycle policy 5s x 60s
==========================================
[2026-04-23 19:12:23] [0;32m[PASS][0m both agents registered
[2026-04-23 19:12:23] [1;33m[TEST][0m write short-cycle expr_policy onto agent-a
[2026-04-23 19:12:24] [0;32m[PASS][0m policy written
[2026-04-23 19:12:24] [1;33m[TEST][0m create unmanaged network then attach expr_policy
[2026-04-23 19:12:25] [0;32m[PASS][0m network created (nid=1), policy attached, joined
[2026-04-23 19:12:25] [1;33m[TEST][0m run 60s and count cycle events
    cycle tick delta over 60s: 0 (expect >= 10)
[2026-04-23 19:13:25] [0;31m[FAIL][0m only 0 cycle ticks (expected >=10 for 5s cycle over 60s)
[2026-04-23 19:13:25] [1;33m[TEST][0m no panics
[2026-04-23 19:13:26] [0;32m[PASS][0m clean logs

Passed: 4  Failed: 1
```

### `test_fanin_3agents_tasks.sh` (exit=1, 87s)

```
  a-worker:   "task_id": "14485b28-4838-59e3-e495-e2ab6d976d7e"
  a-worker: }
  a-worker: 02:12:31.153888543 done tid=14485b28-4838-59e3-e495-e2ab6d976d7e desc=from-b:2
  a-worker: {
  a-worker:   "message": "Task accepted",
  a-worker:   "status": "ACCEPTED",
  a-worker:   "task_id": "ecd8ab96-fadb-2385-2ac0-beae17fcdecc"
  a-worker: }
  a-worker: {
  a-worker:   "sent_to": "0:0000.0000.0004",
  a-worker:   "sent_type": "text",
  a-worker:   "status": "SUCCEEDED",
  a-worker:   "task_id": "ecd8ab96-fadb-2385-2ac0-beae17fcdecc"
  a-worker: }
  a-worker: 02:12:31.252938335 done tid=ecd8ab96-fadb-2385-2ac0-beae17fcdecc desc=from-c:2
[2026-04-23 19:13:40] [1;33m[TEST][0m each submitter gets its own ack:* result
  mismatch role=b tid=c51e633b-58dc-322c-df63-df1d3a5cef39 result=
  mismatch role=b tid=dc2b1452-7d3a-3b2a-b616-a5482af0839f result=
  mismatch role=c tid=3f168d9e-65a7-1a67-ef1c-d353f7753a48 result=
  mismatch role=c tid=ea3c636d-f5fd-1ca3-50ab-7755abeaf520 result=
[2026-04-23 19:13:44] [0;31m[FAIL][0m 4 mis-routed results
[2026-04-23 19:13:44] [1;33m[TEST][0m no panics/fatals in daemon logs
[2026-04-23 19:13:44] [0;32m[PASS][0m clean logs

==========================================
Fan-in tasks summary
==========================================
Passed: [0;32m4[0m
Failed: [0;31m2[0m
==========================================
```

### `test_chaos_loss30_all_ops.sh` (exit=1, 212s)

```
==========================================
Chaos: 30% loss x all 7 op families (P1-010)
==========================================
[2026-04-23 19:10:35] [1;33m[TEST][0m fresh chaos-capable stack
[2026-04-23 19:10:40] [0;32m[PASS][0m both agents registered
[2026-04-23 19:10:43] [1;33m[TEST][0m apply 30% loss on agent-b eth0
[2026-04-23 19:10:43] [0;32m[PASS][0m netem 30% loss applied
[2026-04-23 19:10:43] [1;33m[TEST][0m ping a->b under 30% loss (long timeout)
[2026-04-23 19:10:55] [0;32m[PASS][0m ping ok
[2026-04-23 19:10:55] [1;33m[TEST][0m send-message under 30% loss
[2026-04-23 19:10:57] [0;32m[PASS][0m send-message ok
[2026-04-23 19:10:57] [1;33m[TEST][0m send-file 8 KiB under 30% loss (sha256 match or clean fail)
[2026-04-23 19:10:57] [0;32m[PASS][0m send-file sha match under 30% loss
[2026-04-23 19:10:57] [1;33m[TEST][0m task submit a->b under 30% loss (120s)
[2026-04-23 19:13:46] [0;31m[FAIL][0m task stuck (status=EXPIRED) — expected P1-010 finding
[2026-04-23 19:13:46] [1;33m[TEST][0m pubsub publish under 30% loss
[2026-04-23 19:13:48] [0;32m[PASS][0m publish ok
[2026-04-23 19:13:48] [1;33m[TEST][0m trust handshake under 30% loss
[2026-04-23 19:13:50] [0;32m[PASS][0m handshake ok
[2026-04-23 19:13:50] [1;33m[TEST][0m pilotctl find agent-b (registry lookup) under 30% loss
[2026-04-23 19:13:50] [0;32m[PASS][0m registry lookup ok
[2026-04-23 19:13:50] [1;33m[TEST][0m strip chaos and verify post-chaos ping works
[2026-04-23 19:13:53] [0;32m[PASS][0m post-chaos ping ok
[2026-04-23 19:13:53] [1;33m[TEST][0m no panic/fatal in agent logs
[2026-04-23 19:13:55] [0;32m[PASS][0m clean logs

Passed: 10  Failed: 1
```

### `test_force_relay_pubsub.sh` (exit=1, 97s)

```
==========================================
Force relay: pub/sub delivery
==========================================
[2026-04-23 19:12:47] [1;33m[TEST][0m subscribe on b (before partition)
[2026-04-23 19:12:49] [1;33m[TEST][0m partition direct UDP
[2026-04-23 19:12:50] [0;32m[PASS][0m direct severed
[2026-04-23 19:13:00] [1;33m[TEST][0m publish from a via relay
[2026-04-23 19:13:01] [0;32m[PASS][0m publish returned
[2026-04-23 19:13:01] [1;33m[TEST][0m subscriber on b receives event via relay
[2026-04-23 19:14:13] [0;31m[FAIL][0m event not received — likely P1-010
[2026-04-23 19:14:13] [1;33m[TEST][0m no panic/fatal
[2026-04-23 19:14:13] [0;32m[PASS][0m clean logs

Passed: 3  Failed: 1
```

### `test_net_anti_camping_shipped.sh` (exit=1, 21s)

```
[2026-04-23 19:14:18] [0;32m[PASS][0m net=1
[2026-04-23 19:14:21] [1;33m[TEST][0m force cycles — expect b evicted after threshold
[2026-04-23 19:14:28] [0;31m[FAIL][0m b still in rankings after idle cycles (EXPECTED: evicted)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_chaos_packet_loss.sh` (exit=1, 159s)

```
==========================================
Chaos: 30% packet loss on agent-b ingress
==========================================
[2026-04-23 19:12:05] [1;33m[TEST][0m start stack with NET_ADMIN overlay
[2026-04-23 19:12:09] [0;32m[PASS][0m both agents registered
[2026-04-23 19:12:10] [1;33m[TEST][0m agent-b has NET_ADMIN + iproute2 (tc qdisc show succeeds)
[2026-04-23 19:12:10] [0;32m[PASS][0m tc available
[2026-04-23 19:12:10] [1;33m[TEST][0m baseline (no chaos) task a->b completes
[2026-04-23 19:12:11] [0;32m[PASS][0m baseline task completed cleanly (status=SUCCEEDED)
[2026-04-23 19:12:11] [1;33m[TEST][0m apply 30% ingress+egress loss on agent-b eth0
[2026-04-23 19:12:12] [0;32m[PASS][0m netem applied: qdisc netem 8022: root refcnt 11 limit 1000 loss 30%
[2026-04-23 19:12:12] [1;33m[TEST][0m task a->b completes under 30% packet loss (60s timeout)
[2026-04-23 19:13:41] [0;31m[FAIL][0m task stuck under 30% loss (status=) — retransmit gap
[2026-04-23 19:13:41] [1;33m[TEST][0m send-file 4 KiB completes under 30% loss
[2026-04-23 19:13:44] [0;32m[PASS][0m file round-trip intact (ack=ACK FILE 4096 bytes sha=9cf26547d9cd...)
[2026-04-23 19:13:44] [1;33m[TEST][0m strip netem qdisc and verify clean traffic again
[2026-04-23 19:13:45] [0;32m[PASS][0m netem removed cleanly
[2026-04-23 19:14:42] [0;31m[FAIL][0m post-chaos task stuck (status=)
[2026-04-23 19:14:42] [1;33m[TEST][0m no panic/fatal in daemon logs
[2026-04-23 19:14:43] [0;32m[PASS][0m clean logs

==========================================
Chaos smoke summary
==========================================
Passed: [0;32m7[0m
Failed: [0;31m2[0m
==========================================
```

### `test_net_cold_shoulder_shipped.sh` (exit=1, 19s)

```
[2026-04-23 19:14:47] [0;32m[PASS][0m net=1
[2026-04-23 19:14:50] [1;33m[TEST][0m low-score peer traffic silently dropped
[2026-04-23 19:14:51] [0;31m[FAIL][0m traffic flowed from low-score peer (EXPECTED: cold-shoulder deny)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_midrekey_task_results.sh` (exit=1, 95s)

```
==========================================
Mid-rekey: task results (P1-009 direct)
==========================================
[2026-04-23 19:13:18] [1;33m[TEST][0m fresh stack
[2026-04-23 19:13:23] [0;32m[PASS][0m agents up
[2026-04-23 19:13:24] [1;33m[TEST][0m submit + accept T1
[2026-04-23 19:13:25] [0;32m[PASS][0m T1 ACCEPTED on b
[2026-04-23 19:13:25] [1;33m[TEST][0m restart agent-b (rekey)
[2026-04-23 19:13:27] [0;32m[PASS][0m agent-b back, tunnel rekey window open
[2026-04-23 19:13:27] [1;33m[TEST][0m send-results during rekey window (no warm-up)
[2026-04-23 19:13:27] [1;33m[TEST][0m submitter observes terminal status within 45s
[2026-04-23 19:14:51] [0;31m[FAIL][0m stuck at EXPIRED — direct P1-009 regression
[2026-04-23 19:14:51] [1;33m[TEST][0m result text matches sender payload
[2026-04-23 19:14:51] [0;31m[FAIL][0m payload missing: 
[2026-04-23 19:14:51] [1;33m[TEST][0m no panic/fatal
[2026-04-23 19:14:52] [0;32m[PASS][0m clean logs

Passed: 4  Failed: 2
```

### `test_net_cooling_off_shipped.sh` (exit=1, 12s)

```
[2026-04-23 19:14:55] [0;32m[PASS][0m net=1
[2026-04-23 19:14:57] [1;33m[TEST][0m violating peer is in cooldown
[2026-04-23 19:14:59] [0;31m[FAIL][0m retry succeeded inside cooldown window (EXPECTED: deny)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_burnout_shipped.sh` (exit=1, 31s)

```
[2026-04-23 19:14:45] [0;32m[PASS][0m net=1
[2026-04-23 19:14:49] [1;33m[TEST][0m generate burst traffic to trigger burnout cap
[2026-04-23 19:15:01] [1;33m[TEST][0m after burst, score is bounded or peer evicted (burnout cap)
[2026-04-23 19:15:01] [0;31m[FAIL][0m no burnout cap observed: score=0->0 listed=1 (EXPECTED: score moved AND bounded, OR peer evicted)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_nat_dual_symmetric.sh` (exit=1, 71s)

```
    
    #38 [agent-a] exporting to image
    #38 exporting layers 0.0s done
    #38 exporting manifest sha256:fb97f1e58508279d165f9852b5d24b20fbc035c668db723777aea7f6e75923a8 0.1s done
    #38 exporting config sha256:1c3eb23a7ed773e0a021dcf07b0e1e35c6827032a24dbf20ab0720ebcb0a29b8 0.1s done
    #38 exporting attestation manifest sha256:77c4c08e98aa524e29e0ccc4678af5c2f6994f28ce4393d1e4d1516a1ca57035 0.1s done
    #38 exporting manifest list sha256:8ae56525e7f926efd9836fe709bdeb1f3e47558ebf8e0b76e86485860843d8d4 0.0s done
    #38 naming to docker.io/library/pilot-multi:latest 0.0s done
    #38 unpacking to docker.io/library/pilot-multi:latest 0.0s done
    #38 DONE 0.5s
    
    #37 [agent-b] exporting to image
    #37 DONE 0.7s
    
    #39 [agent-a] resolving provenance for metadata file
    #39 DONE 0.3s
    
    #40 [rendezvous] resolving provenance for metadata file
    #40 DONE 0.2s
    
    #41 [agent-b] resolving provenance for metadata file
    #41 DONE 0.0s
     pilot-multi:latest  Built
     pilot-w7-nat-gw-b  Built
     pilot-multi:latest  Built
     pilot-w7-nat-gw-a  Built
     pilot-multi:latest  Built
     Network pilot-w7_private-a  Creating
     Network pilot-w7_private-a  Error
    failed to create network pilot-w7_private-a: Error response from daemon: invalid pool request: Pool overlaps with other one on this address space
```

### `test_net_cross_network_traffic_denied.sh` (exit=1, 11s)

```
[2026-04-23 19:14:58] [1;33m[TEST][0m create strict network X (deny non-members)
[2026-04-23 19:15:00] [0;32m[PASS][0m net=1
[2026-04-23 19:15:00] [1;33m[TEST][0m agent-a joins X; agent-b stays out
[2026-04-23 19:15:03] [0;32m[PASS][0m agent-a is member of X
[2026-04-23 19:15:03] [1;33m[TEST][0m agent-b (non-member of X) dials agent-a — expect deny
[2026-04-23 19:15:03] [0;31m[FAIL][0m cross-network send succeeded despite X's deny rule (EXPECTED: deny)
    resolved "agent-a" → 0:0000.0000.0002
    sent 19 bytes (no response)
Passed: [0;32m2[0m  Failed: [0;31m1[0m
```

### `test_cli.sh` (exit=1, 279s)

```
{
  "node_id": 71771,
  "type": "set_visibility_ok",
  "visibility": "private"
}
[2026-04-23 19:15:13] [0;32m[PASS][0m Visibility toggle works
[2026-04-23 19:15:13] [1;33m[TEST][0m Testing tag management
tags set: #test #integration #docker
tags cleared
[2026-04-23 19:15:13] [0;32m[PASS][0m Tag management works
[2026-04-23 19:15:13] [1;33m[TEST][0m Checking configuration
[2026-04-23 19:15:13] [0;32m[PASS][0m Configuration retrieved successfully
[2026-04-23 19:15:13] [1;33m[TEST][0m Deregistering from network
{
  "type": "deregister_ok"
}
[2026-04-23 19:15:13] [0;32m[PASS][0m Successfully deregistered from network

=========================================
Test Summary
=========================================
Passed: [0;32m16[0m
Failed: [0;31m5[0m
=========================================

[1;33m[CLEANUP][0m Stopping daemon...
[1;33m[CLEANUP][0m Last daemon errors:
time=2026-04-23T19:10:35.944-07:00 level=WARN msg="failed to save account file" error="create account dir: mkdir /root: read-only file system"
time=2026-04-23T19:10:36.026-07:00 level=WARN msg="failed to save identity" error="create identity dir: mkdir /root: read-only file system"
[1;33m[CLEANUP][0m Daemon stopped.
```

### `test_net_gift_economy_shipped.sh` (exit=1, 18s)

```
[2026-04-23 19:15:11] [0;32m[PASS][0m net=1
[2026-04-23 19:15:19] [1;33m[TEST][0m both sender and receiver accrue reward
[2026-04-23 19:15:19] [0;31m[FAIL][0m asymmetric rewards missing: A=0 B=0 (EXPECTED: both >0)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_golden_hour_shipped.sh` (exit=1, 21s)

```
[2026-04-23 19:15:12] [0;32m[PASS][0m net=1
[2026-04-23 19:15:15] [1;33m[TEST][0m fresh-join actions accrue bonus
[2026-04-23 19:15:23] [0;31m[FAIL][0m no golden-hour bonus: early=0 late-delta=0 (EXPECTED: early>0 AND early>late-delta)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_high_trust_society_shipped.sh` (exit=1, 21s)

```
[2026-04-23 19:15:18] [0;32m[PASS][0m net=1
[2026-04-23 19:15:21] [1;33m[TEST][0m 5 connects from a->b — score should be +5
[2026-04-23 19:15:26] [0;31m[FAIL][0m score=0 (EXPECTED >= 5; score action not applied per connect)
[2026-04-23 19:15:26] [1;33m[TEST][0m cycle tick runs without panic under active policy
[2026-04-23 19:15:26] [0;32m[PASS][0m cycle ok
Passed: [0;32m2[0m  Failed: [0;31m1[0m
```

### `test_net_half_life_shipped.sh` (exit=1, 23s)

```
[2026-04-23 19:15:17] [0;32m[PASS][0m net=1
[2026-04-23 19:15:27] [0;31m[FAIL][0m decay too weak or unseeded: 0 -> 0 (EXPECTED: S0>=4 AND S1<S0 AND S1<=1)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_gossip_tax_shipped.sh` (exit=1, 26s)

```
[2026-04-23 19:15:12] [0;32m[PASS][0m net=1
[2026-04-23 19:15:16] [1;33m[TEST][0m excessive pubsub publishes drain score
[2026-04-23 19:15:28] [0;31m[FAIL][0m no gossip tax: 0 -> 0 (EXPECTED: SC0>0 AND SC1<SC0 after high emit)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_join_deny_per_network.sh` (exit=1, 9s)

```
[2026-04-23 19:15:27] [0;32m[PASS][0m net=1
[2026-04-23 19:15:27] [1;33m[TEST][0m agent-b attempts to join — expect deny
[2026-04-23 19:15:29] [0;31m[FAIL][0m agent-b joined despite join-deny rule (EXPECTED: rejected)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_isolation_policy_scoping.sh` (exit=1, 22s)

```
[2026-04-23 19:15:22] [1;33m[TEST][0m create strict network (X)
[2026-04-23 19:15:24] [0;32m[PASS][0m net X = 1
[2026-04-23 19:15:24] [1;33m[TEST][0m create permissive network (Y)
[2026-04-23 19:15:26] [0;32m[PASS][0m net Y = 2
[2026-04-23 19:15:26] [1;33m[TEST][0m agent-a joins X; agent-b joins Y
[2026-04-23 19:15:30] [0;32m[PASS][0m memberships set
[2026-04-23 19:15:31] [1;33m[TEST][0m agent-b can reach agent-a on base network (Y's allow is permissive)
[2026-04-23 19:15:32] [0;32m[PASS][0m cross-scope base-network ping ok
[2026-04-23 19:15:32] [1;33m[TEST][0m X's deny is scoped to X (agent-a is member of X)
[2026-04-23 19:15:33] [0;32m[PASS][0m X runner has rules active
[2026-04-23 19:15:33] [1;33m[TEST][0m Y's allow is scoped to Y (agent-b is member of Y, not X)
[2026-04-23 19:15:35] [0;32m[PASS][0m Y runner has rules active
[2026-04-23 19:15:35] [1;33m[TEST][0m agent-a has NO runner for Y, agent-b has NO runner for X
[2026-04-23 19:15:36] [0;31m[FAIL][0m cross-scope status succeeded (leak): A->Y=ok  B->X=ok
Passed: [0;32m6[0m  Failed: [0;31m1[0m
```

### `test_net_data_exchange_policy_shipped.sh` (exit=1, 47s)

```
[2026-04-23 19:15:01] [0;32m[PASS][0m net=1
[2026-04-23 19:15:04] [1;33m[TEST][0m echo (port 7) is always allowed (allow-echo-dial rule)
[2026-04-23 19:15:34] [0;31m[FAIL][0m echo blocked (EXPECTED: port 7 always allowed)
[2026-04-23 19:15:34] [1;33m[TEST][0m port 1001 rejected when neither side has 'service' tag
[2026-04-23 19:15:38] [0;32m[PASS][0m 1001 send refused
[2026-04-23 19:15:38] [1;33m[TEST][0m port 1001 allowed once agent-b takes 'service' tag
[2026-04-23 19:15:41] [0;31m[FAIL][0m 1001 blocked with service tag (EXPECTED: allowed)
    resolved "agent-b" → 0:0000.0000.0003
    error: cannot connect to 0:0000.0000.0003 port 1001
    hint:  check that 0:0000.0000.0003 is reachable: pilotctl ping 0:0000.0000.0003
Passed: [0;32m2[0m  Failed: [0;31m2[0m
```

### `test_net_karma_ledger_shipped.sh` (exit=1, 18s)

```
[2026-04-23 19:15:33] [0;32m[PASS][0m net=1
[2026-04-23 19:15:38] [1;33m[TEST][0m 3 connects update karma ledger
[2026-04-23 19:15:43] [0;31m[FAIL][0m karma did not change (EXPECTED: monotonic increase)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_dur_steady_compressed_24h.sh` (exit=1, 308s)

```
==========================================
Duration: compressed 24h (1s cycle x 300s)
==========================================
[2026-04-23 19:10:40] [0;32m[PASS][0m both agents registered
[2026-04-23 19:10:40] [1;33m[TEST][0m write 1s-cycle expr_policy
[2026-04-23 19:10:41] [0;32m[PASS][0m policy written
[2026-04-23 19:10:41] [1;33m[TEST][0m create unmanaged network then attach expr_policy
[2026-04-23 19:10:42] [0;32m[PASS][0m network active (nid=1), policy attached, joined
[2026-04-23 19:10:42] [0;32m[PASS][0m T0 rss=11856KiB fds=9
[2026-04-23 19:10:42] [1;33m[TEST][0m run for 300s
[2026-04-23 19:15:42] [0;32m[PASS][0m run complete
    cycle ticks during run: 0 (expected ~300)
[2026-04-23 19:15:43] [1;33m[TEST][0m tick count within ±25% of 300
[2026-04-23 19:15:43] [0;31m[FAIL][0m tick count 0 outside [225, 375]
    delta rss=0KiB fds=0
[2026-04-23 19:15:43] [1;33m[TEST][0m rss delta < 50 MiB
[2026-04-23 19:15:43] [0;32m[PASS][0m rss delta 0KiB within budget
[2026-04-23 19:15:43] [1;33m[TEST][0m fd delta < 20
[2026-04-23 19:15:43] [0;32m[PASS][0m fd delta 0 within budget
[2026-04-23 19:15:43] [1;33m[TEST][0m no panics
[2026-04-23 19:15:43] [0;32m[PASS][0m clean logs

Passed: 8  Failed: 1
```

### `test_net_meritocracy_rating_shipped.sh` (exit=1, 16s)

```
[2026-04-23 19:15:40] [0;32m[PASS][0m net=1
[2026-04-23 19:15:43] [1;33m[TEST][0m rating surface exposed per peer
[2026-04-23 19:15:44] [0;31m[FAIL][0m no rating surface (EXPECTED: per-peer rating)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_meritocracy_shipped.sh` (exit=1, 16s)

```
[2026-04-23 19:15:41] [0;32m[PASS][0m net=1
[2026-04-23 19:15:44] [1;33m[TEST][0m top-score peer is in rankings and surfaces merit
[2026-04-23 19:15:46] [0;31m[FAIL][0m no ranking surface (EXPECTED: rankings expose merit order)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_ostracism_shipped.sh` (exit=1, 16s)

```
[2026-04-23 19:15:41] [0;32m[PASS][0m net=1
[2026-04-23 19:15:44] [1;33m[TEST][0m below-threshold peer is evicted on cycle
[2026-04-23 19:15:46] [0;31m[FAIL][0m low-score peer present (EXPECTED: ostracized/evicted)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_lottery_shipped.sh` (exit=1, 21s)

```
[2026-04-23 19:15:40] [0;32m[PASS][0m net=1
[2026-04-23 19:15:43] [1;33m[TEST][0m repeated connects yield non-deterministic pass/fail
[2026-04-23 19:15:48] [0;31m[FAIL][0m deterministic outcome pass=10 deny=0 (EXPECTED: probabilistic)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_pay_it_forward_shipped.sh` (exit=1, 15s)

```
[2026-04-23 19:15:49] [0;32m[PASS][0m net=1
[2026-04-23 19:15:52] [1;33m[TEST][0m pubsub relay accrues forwarding reward
[2026-04-23 19:15:54] [0;31m[FAIL][0m no forwarding reward (EXPECTED: score bump on forward)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_small_circle_shipped.sh` (exit=1, 12s)

```
[2026-04-23 19:15:54] [0;32m[PASS][0m net=1
[2026-04-23 19:15:56] [1;33m[TEST][0m max_peers cap enforced (small-circle)
[2026-04-23 19:15:57] [0;31m[FAIL][0m cap=0 (EXPECTED: small positive cap, e.g. 10)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_rotating_chairs_shipped.sh` (exit=1, 14s)

```
[2026-04-23 19:15:53] [0;32m[PASS][0m net=1
[2026-04-23 19:15:56] [1;33m[TEST][0m rankings reorder across forced cycles
[2026-04-23 19:15:58] [0;31m[FAIL][0m ranking head static (0) across cycles (EXPECTED: rotation)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_stable_state_shipped.sh` (exit=1, 14s)

```
[2026-04-23 19:15:55] [0;32m[PASS][0m net=1
[2026-04-23 19:15:58] [1;33m[TEST][0m cycles converge peer count toward target
[2026-04-23 19:16:00] [0;31m[FAIL][0m peer count drifted or empty: 0 -> 0 (EXPECTED: C0>=1 AND |ΔC|<=2)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_two_strikes_shipped.sh` (exit=1, 13s)

```
[2026-04-23 19:15:57] [0;32m[PASS][0m net=1
[2026-04-23 19:16:00] [1;33m[TEST][0m two failed attempts evict peer
[2026-04-23 19:16:03] [0;31m[FAIL][0m peer still present after 2 strikes (EXPECTED: evicted)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_tithe_shipped.sh` (exit=1, 18s)

```
[2026-04-23 19:15:56] [0;32m[PASS][0m net=1
[2026-04-23 19:15:59] [1;33m[TEST][0m tithe clips accumulated score on cycle
[2026-04-23 19:16:05] [0;31m[FAIL][0m no tithe: 0 -> 0 (EXPECTED: score decrease)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_whale_hunt_shipped.sh` (exit=1, 11s)

```
[2026-04-23 19:16:02] [0;32m[PASS][0m net=1
[2026-04-23 19:16:05] [1;33m[TEST][0m high-score peer is flagged / taxed
[2026-04-23 19:16:06] [0;31m[FAIL][0m no whale-score rule visible (EXPECTED: rule keyed on high peer_score)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_policy_cycle_fill_trust.sh` (exit=1, 14s)

```
==========================================
Policy: cycle × fill_trust
==========================================
[2026-04-23 19:16:11] [0;32m[PASS][0m stack up
[2026-04-23 19:16:11] [1;33m[TEST][0m Apply fill_trust policy on agent-b
load_policy: network_id=1 policy=/tests/fixtures/policies/short_cycle_fill_trust.json (on agent-b)
[2026-04-23 19:16:13] [0;32m[PASS][0m policy loaded (net=1)
[2026-04-23 19:16:13] [1;33m[TEST][0m confirm agent-b starts with 0 trust links
[2026-04-23 19:16:14] [0;32m[PASS][0m trust set empty
[2026-04-23 19:16:14] [1;33m[TEST][0m force cycle
[2026-04-23 19:16:17] [0;32m[PASS][0m cycle forced
[2026-04-23 19:16:17] [1;33m[TEST][0m agent-b logged 'sent trust requests'
[2026-04-23 19:16:17] [0;32m[PASS][0m fill_trust fired
[2026-04-23 19:16:17] [1;33m[TEST][0m agent-a has a pending handshake from agent-b
[2026-04-23 19:16:19] [0;31m[FAIL][0m agent-a pending=0 (want >=1)
Passed: \033[0;32m5\033[0m  Failed: \033[0;31m1\033[0m
```

### `test_net_polo_scoped_per_network.sh` (exit=1, 39s)

```
create_network_from_file: attempt 1 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 2s
create_network_from_file: attempt 2 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 4s
create_network_from_file: attempt 3 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 6s
create_network_from_file: attempt 4 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 8s
create_network_from_file: attempt 5 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 10s
create_network_from_file: create failed after 5 attempts: {"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}
[2026-04-23 19:16:20] [0;31m[FAIL][0m create X
```

### `test_policy_cycle_webhook.sh` (exit=1, 15s)

```
==========================================
Policy: cycle × webhook
==========================================
[2026-04-23 19:16:12] [0;32m[PASS][0m stack up
[2026-04-23 19:16:12] [1;33m[TEST][0m start a local webhook sink inside agent-b container
[2026-04-23 19:16:14] [0;32m[PASS][0m sink listening on 127.0.0.1:18080
[2026-04-23 19:16:14] [1;33m[TEST][0m restart agent-b daemon with -webhook flag
[2026-04-23 19:16:14] [0;32m[PASS][0m agent-b relaunched with webhook
[2026-04-23 19:16:20] [1;33m[TEST][0m Apply webhook-on-cycle policy
load_policy: cannot resolve agent-b node_id
[2026-04-23 19:16:21] [0;31m[FAIL][0m load
```

### `test_net_trust_scoped_per_network.sh` (exit=1, 39s)

```
create_network_from_file: attempt 1 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 2s
create_network_from_file: attempt 2 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 4s
create_network_from_file: attempt 3 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 6s
create_network_from_file: attempt 4 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 8s
create_network_from_file: attempt 5 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 10s
create_network_from_file: create failed after 5 attempts: {"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}
[2026-04-23 19:16:27] [0;31m[FAIL][0m create X
```

### `test_policy_join_allow.sh` (exit=1, 11s)

```
==========================================
Policy: join × allow (schema-level)
==========================================
[2026-04-23 19:16:27] [0;32m[PASS][0m stack up
[2026-04-23 19:16:27] [1;33m[TEST][0m Apply allow-join policy on agent-b
load_policy: network_id=1 policy=/tests/fixtures/policies/join_allow.json (on agent-b)
[2026-04-23 19:16:30] [0;32m[PASS][0m policy loaded (net=1)
[2026-04-23 19:16:30] [1;33m[TEST][0m agent-a joining managed network succeeds
[2026-04-23 19:16:30] [0;32m[PASS][0m join succeeded
[2026-04-23 19:16:30] [1;33m[TEST][0m agent-a member list contains agent-a and agent-b
[2026-04-23 19:16:32] [0;31m[FAIL][0m expected >=2 members, got 0
[2026-04-23 19:16:32] [1;33m[TEST][0m FINDING: join event firing not wired in daemon
    (documented in test comment header)
Passed: \033[0;32m3\033[0m  Failed: \033[0;31m1\033[0m
```

### `test_policy_datagram_deny.sh` (exit=1, 15s)

```
==========================================
Policy: datagram × deny
==========================================
[2026-04-23 19:16:24] [0;32m[PASS][0m stack up
[2026-04-23 19:16:24] [1;33m[TEST][0m Apply deny-all datagram policy on agent-b
load_policy: network_id=1 policy=/tests/fixtures/policies/deny_all_datagram.json (on agent-b)
[2026-04-23 19:16:26] [0;32m[PASS][0m policy loaded (net=1)
[2026-04-23 19:16:26] [1;33m[TEST][0m send datagram under deny — expect failure / timeout
[2026-04-23 19:16:31] [0;32m[PASS][0m send rejected/timed out (rc=1)
[2026-04-23 19:16:31] [1;33m[TEST][0m agent-b logs datagram rejection
assert_policy_event: agent=agent-b event=datagram_deny pattern=datagram rejected: not allowed\|datagram\.port_rejected\|datagram.*not allowed count=0 want>=1
[2026-04-23 19:16:34] [0;31m[FAIL][0m no datagram_deny event observed
Passed: \033[0;32m3\033[0m  Failed: \033[0;31m1\033[0m
```

### `test_policy_connect_deny.sh` (exit=1, 41s)

```
==========================================
Policy: connect × deny
==========================================
[2026-04-23 19:16:01] [1;33m[TEST][0m Starting stack
[2026-04-23 19:16:07] [0;32m[PASS][0m stack up
[2026-04-23 19:16:07] [1;33m[TEST][0m Apply deny-all connect policy on agent-b
load_policy: network_id=1 policy=/tests/fixtures/policies/deny_all_connect.json (on agent-b)
[2026-04-23 19:16:10] [0;32m[PASS][0m deny-all policy loaded (net=1)
[2026-04-23 19:16:11] [1;33m[TEST][0m echo under deny-all must fail (timeout or refusal)
[2026-04-23 19:16:19] [0;32m[PASS][0m echo refused/timed out under deny policy (rc=124)
[2026-04-23 19:16:19] [1;33m[TEST][0m agent-b logs syn.port_rejected OR port_rejected OR policy deny
assert_policy_event: agent=agent-b event=connect_deny pattern=SYN rejected: not allowed\|syn\.port_rejected\|port_rejected count=0 want>=1
[2026-04-23 19:16:21] [0;31m[FAIL][0m no deny events in agent-b logs (expected under deny-all connect)
[2026-04-23 19:16:21] [1;33m[TEST][0m send-message under deny-all must fail
[2026-04-23 19:16:30] [0;32m[PASS][0m send-message refused/timed out (rc=124)
[2026-04-23 19:16:30] [1;33m[TEST][0m send-file under deny-all must fail
[2026-04-23 19:16:40] [0;32m[PASS][0m send-file refused/timed out (rc=124)

==========================================
Passed: \033[0;32m5\033[0m  Failed: \033[0;31m1\033[0m
==========================================
```

### `test_sec_ipc_exhaustion.sh` (exit=1, 16s)

```
[2026-04-23 19:16:35] [1;33m[TEST][0m fresh stack
[2026-04-23 19:16:40] [1;33m[TEST][0m attempt 10k concurrent IPC connections
successfully opened IPC conns: 4310
[2026-04-23 19:16:41] [1;33m[TEST][0m daemon still responds to pilotctl info from a NEW connection
[2026-04-23 19:16:45] [0;32m[PASS][0m daemon responsive after IPC exhaustion attempt
[2026-04-23 19:16:45] [1;33m[TEST][0m per-client cap enforced (OPEN should be well below 10000)
[2026-04-23 19:16:46] [0;31m[FAIL][0m no IPC cap detected (4310 conns opened) — see P2-002
[2026-04-23 19:16:46] [1;33m[TEST][0m no agent-a panic on accept() exhaustion
[2026-04-23 19:16:48] [0;32m[PASS][0m no panic/EMFILE in logs

Passed: 2  Failed: 1
```

### `test_partition_heal.sh` (exit=1, 69s)

```
==========================================
Partition then heal: queued ops complete
==========================================
[2026-04-23 19:16:03] [0;32m[PASS][0m both agents registered
[2026-04-23 19:16:06] [0;32m[PASS][0m IPs resolved a=172.29.11.20 b=172.29.11.21
[2026-04-23 19:16:06] [1;33m[TEST][0m pre-submit 3 tasks BEFORE partition (worker paused)
[2026-04-23 19:16:08] [0;32m[PASS][0m pre-submitted 3 task ids
[2026-04-23 19:16:08] [1;33m[TEST][0m install partition a<->b
[2026-04-23 19:16:09] [0;32m[PASS][0m partition effective
[2026-04-23 19:16:10] [1;33m[TEST][0m none of the submitted tasks already completed
[2026-04-23 19:16:10] [0;32m[PASS][0m 0/3 completed during split (correct)
[2026-04-23 19:16:10] [1;33m[TEST][0m heal partition
[2026-04-23 19:16:55] [0;31m[FAIL][0m heal did not restore path
```

### `test_policy_datagram_score.sh` (exit=1, 48s)

```
==========================================
Policy: datagram × score
==========================================
[2026-04-23 19:16:25] [0;32m[PASS][0m stack up
[2026-04-23 19:16:25] [1;33m[TEST][0m Apply score-on-datagram policy on agent-b
load_policy: network_id=1 policy=/tests/fixtures/policies/score_on_datagram.json (on agent-b)
[2026-04-23 19:16:28] [0;32m[PASS][0m policy loaded (net=1)
[2026-04-23 19:16:28] [1;33m[TEST][0m baseline score (may be empty for fresh peer)
[2026-04-23 19:16:29] [0;32m[PASS][0m baseline score=0
[2026-04-23 19:16:29] [1;33m[TEST][0m drive 5 datagrams from agent-a
[2026-04-23 19:16:59] [0;32m[PASS][0m sent
[2026-04-23 19:17:02] [1;33m[TEST][0m peer score increased
[2026-04-23 19:17:04] [0;31m[FAIL][0m score not increased (base=0 new=0)
Passed: \033[0;32m4\033[0m  Failed: \033[0;31m1\033[0m
```

### `test_sec_trust_grant_forgery.sh` (exit=1, 35s)

```
[2026-04-23 19:16:43] [1;33m[TEST][0m fresh stack
[2026-04-23 19:16:54] [1;33m[TEST][0m stand up a fresh sybil daemon identity inside agent-a
forger node_id: 
[2026-04-23 19:16:59] [0;31m[FAIL][0m forger daemon didn't register
time=2026-04-24T02:16:54.894Z level=INFO msg="daemon start: email address required: use -email you@example.com"
[2026-04-23 19:17:02] [1;33m[TEST][0m forger attempts trust grant to agent-b (unrequested)
[2026-04-23 19:17:06] [1;33m[TEST][0m agent-b does NOT auto-trust the forger
[2026-04-23 19:17:08] [0;32m[PASS][0m forger is NOT in trusted list
[2026-04-23 19:17:08] [1;33m[TEST][0m forger with a tampered identity file cannot impersonate
[2026-04-23 19:17:13] [1;33m[TEST][0m agent-b logs show signature verification guard
[2026-04-23 19:17:14] [1;33m[TEST][0m no explicit verification-failure log seen — trust path handled rejection instead
[2026-04-23 19:17:14] [1;33m[TEST][0m agent-b pending handshake count bounded
[2026-04-23 19:17:15] [0;32m[PASS][0m pending queue bounded (0)

Passed: 2  Failed: 1
```

### `test_receiver_sigkill_midfile.sh` (exit=1, 59s)

```
==========================================
SIGKILL agent-b mid-send-file
==========================================
[2026-04-23 19:16:27] [0;32m[PASS][0m both agents registered
[2026-04-23 19:16:28] [1;33m[TEST][0m prepare 4 MiB payload on agent-a
[2026-04-23 19:16:29] [0;32m[PASS][0m payload ready (f4eb388c3a71d816582406452245c00e4032ba8b2885c0e4c2ef4a46ea06565e)
[2026-04-23 19:16:29] [1;33m[TEST][0m start send-file in background, then SIGKILL agent-b
[2026-04-23 19:16:33] [0;32m[PASS][0m agent-b SIGKILL'd mid-transfer
[2026-04-23 19:16:33] [1;33m[TEST][0m send-file on agent-a returns (not hung)
[2026-04-23 19:16:37] [0;32m[PASS][0m send-file returned (rc=1)
[2026-04-23 19:16:37] [1;33m[TEST][0m sender did NOT claim success after receiver died
[2026-04-23 19:16:37] [0;32m[PASS][0m no false-success ack
[2026-04-23 19:16:37] [1;33m[TEST][0m no panic/fatal on agent-a
[2026-04-23 19:16:37] [0;32m[PASS][0m clean logs on a
[2026-04-23 19:16:37] [1;33m[TEST][0m restart agent-b
[2026-04-23 19:16:39] [0;32m[PASS][0m agent-b re-registered
[2026-04-23 19:16:39] [1;33m[TEST][0m no silent-corrupt partial file on agent-b
[2026-04-23 19:16:39] [0;32m[PASS][0m no partial file left (acceptable)
[2026-04-23 19:16:39] [1;33m[TEST][0m fresh send-file post-restart completes with sha match
[2026-04-23 19:17:19] [0;31m[FAIL][0m post-restart send mismatch src=2267e36fb522... dst=...

Passed: 8  Failed: 1
```

### `test_task_executor.sh` (exit=1, 21s)

```
[2026-04-23 19:17:19] [1;33m[TEST][0m start auto-accept worker on agent-b
[2026-04-23 19:17:20] [0;32m[PASS][0m worker started on agent-b
[2026-04-23 19:17:20] [1;33m[TEST][0m agent-a submits T1 (polo should allow)
[2026-04-23 19:17:21] [0;32m[PASS][0m T1 submitted: 101421cc-2993-f2fa-14a0-0d608750de7a
[2026-04-23 19:17:22] [1;33m[TEST][0m T1 reaches completed/succeeded on submitter
[2026-04-23 19:17:22] [0;32m[PASS][0m submitter sees T1 status=SUCCEEDED
[2026-04-23 19:17:22] [1;33m[TEST][0m pilotctl task result returns correlated payload
[2026-04-23 19:17:22] [0;32m[PASS][0m T1 result correlates: "done: compute-fibonacci"
[2026-04-23 19:17:22] [1;33m[TEST][0m polo gate rejects second a -> b submit with too-low score
[2026-04-23 19:17:23] [0;31m[FAIL][0m polo gate did not block (accepted=false message=Task rejected by polo gate: submitter polo below receiver polo)
[2026-04-23 19:17:23] [1;33m[TEST][0m enable-tasks on agent-a for reverse flow
[2026-04-23 19:17:25] [1;33m[TEST][0m agent-b submits B1 to agent-a (should be allowed)
[2026-04-23 19:17:26] [0;32m[PASS][0m B1 submitted: 8fa10212-c26c-56ad-35d3-03a4f74dc2ba
[2026-04-23 19:17:26] [1;33m[TEST][0m B1 completes on agent-b
[2026-04-23 19:17:26] [0;32m[PASS][0m agent-b sees B1 status=SUCCEEDED
[2026-04-23 19:17:26] [1;33m[TEST][0m balanced exchange restores polo, a can submit again
[2026-04-23 19:17:27] [0;32m[PASS][0m post-balance submit accepted: 1da8b6af-d24e-39b9-935c-36addaca97d2
[2026-04-23 19:17:29] [1;33m[TEST][0m post-balance task result correlates
[2026-04-23 19:17:29] [0;32m[PASS][0m post-balance result correlates
[2026-04-23 19:17:29] [1;33m[TEST][0m pilotctl task result on missing id returns clean error
[2026-04-23 19:17:29] [0;32m[PASS][0m missing-id handled cleanly
[2026-04-23 19:17:29] [1;33m[TEST][0m no panics/fatals in daemon logs
[2026-04-23 19:17:30] [0;32m[PASS][0m clean logs

==========================================
Task-executor test summary
==========================================
Passed: [0;32m12[0m
Failed: [0;31m1[0m
==========================================
```

### `test_sender_clean_restart_midflight.sh` (exit=1, 49s)

```
==========================================
Clean restart of agent-a mid-flight
==========================================
[2026-04-23 19:17:02] [0;32m[PASS][0m both agents registered
[2026-04-23 19:17:07] [1;33m[TEST][0m submit 3 tasks then restart agent-a cleanly
[2026-04-23 19:17:13] [0;32m[PASS][0m agent-a re-registered post-restart
[2026-04-23 19:17:13] [1;33m[TEST][0m agent-a task list --type submitted still works post-restart
[2026-04-23 19:17:14] [0;32m[PASS][0m task list ok
[2026-04-23 19:17:14] [1;33m[TEST][0m fresh task submit post-restart completes
[2026-04-23 19:17:34] [0;31m[FAIL][0m fresh task stuck post-restart (status=)
[2026-04-23 19:17:34] [1;33m[TEST][0m fresh send-file post-restart
[2026-04-23 19:17:36] [0;32m[PASS][0m file sha match post-restart
[2026-04-23 19:17:37] [1;33m[TEST][0m no panic/fatal
[2026-04-23 19:17:37] [0;32m[PASS][0m clean logs

Passed: 5  Failed: 1
```

### `test_tasks_and_edge.sh` (exit=1, 24s)

```
[2026-04-23 19:17:33] [0;32m[PASS][0m task queue ok
[2026-04-23 19:17:33] [1;33m[TEST][0m send-message type=json
[2026-04-23 19:17:33] [0;32m[PASS][0m send-message JSON ack ok
[2026-04-23 19:17:33] [1;33m[TEST][0m send-message type=binary
[2026-04-23 19:17:34] [0;32m[PASS][0m send-message binary ack ok
[2026-04-23 19:17:34] [1;33m[TEST][0m send-file and verify byte count
[2026-04-23 19:17:36] [0;32m[PASS][0m send-file 10240 bytes acked (10240)
[2026-04-23 19:17:36] [1;33m[TEST][0m inbox has at least 2 message entries (JSON + binary text)
[2026-04-23 19:17:36] [0;32m[PASS][0m inbox has 2 entries
[2026-04-23 19:17:36] [1;33m[TEST][0m received/ has the binary file delivered by send-file
[2026-04-23 19:17:37] [0;32m[PASS][0m received/ has 1 file(s)
[2026-04-23 19:17:37] [1;33m[TEST][0m inbox --clear empties the inbox
[2026-04-23 19:17:38] [0;32m[PASS][0m inbox cleared (was 2 now 0)
[2026-04-23 19:17:38] [1;33m[TEST][0m ping unknown hostname returns clear error
[2026-04-23 19:17:39] [0;32m[PASS][0m unknown hostname rejected cleanly
[2026-04-23 19:17:39] [1;33m[TEST][0m send missing --data flag returns invalid_argument
[2026-04-23 19:17:40] [0;32m[PASS][0m missing --data rejected with invalid_argument
[2026-04-23 19:17:40] [1;33m[TEST][0m set-hostname with bad characters rejected
[2026-04-23 19:17:42] [0;32m[PASS][0m invalid hostname rejected (status=error)
[2026-04-23 19:17:42] [1;33m[TEST][0m lookup of nonexistent node_id returns error
[2026-04-23 19:17:43] [0;32m[PASS][0m lookup of ghost node fails cleanly
[2026-04-23 19:17:43] [1;33m[TEST][0m pilotctl version
[2026-04-23 19:17:43] [0;32m[PASS][0m version: dev

==========================================
Tasks/Edge Test Summary
==========================================
Passed: [0;32m18[0m
Failed: [0;31m1[0m
==========================================
```

### `test_webhook_agent_registered.sh` (exit=1, 44s)

```
service "webhook-sink" is not running
service "webhook-sink" is not running
service "webhook-sink" is not running
service "webhook-sink" is not running
service "webhook-sink" is not running
service "webhook-sink" is not running
service "webhook-sink" is not running
service "webhook-sink" is not running
service "webhook-sink" is not running
service "webhook-sink" is not running
service "webhook-sink" is not running
service "webhook-sink" is not running
[2026-04-23 19:18:02] [1;33m[TEST][0m at least 2 registration webhooks after 2 agent restarts (got delta=0)
[2026-04-23 19:18:02] [0;31m[FAIL][0m expected delta>=2 got 0
[2026-04-23 19:18:02] [1;33m[TEST][0m canonical 'agent.registered' event name
service "webhook-sink" is not running
test_webhook_agent_registered.sh: line 72: [: : integer expression expected
[2026-04-23 19:18:03] [0;31m[FAIL][0m agent.registered NOT wired — daemon emits 'node.registered'/'node.reregistered' instead
Passed: 0  Failed: 2
```

### `test_splitbrain_divergence.sh` (exit=1, 74s)

```
==========================================
Split-brain divergence (2 rendezvous)
==========================================
[2026-04-23 19:17:09] [1;33m[TEST][0m Starting splitbrain stack
[2026-04-23 19:18:20] [1;33m[TEST][0m rendezvous-1 sees 2 agents
[2026-04-23 19:18:21] [0;31m[FAIL][0m rendezvous-1 sees 3 nodes — expected 2 (partition leaked)
[2026-04-23 19:18:21] [1;33m[TEST][0m rendezvous-2 sees 2 agents
[2026-04-23 19:18:21] [0;32m[PASS][0m rendezvous-2 has exactly 2 nodes (agent-c,d)
[2026-04-23 19:18:21] [1;33m[TEST][0m agent-a cannot lookup agent-c (cross-partition)
[2026-04-23 19:18:21] [0;32m[PASS][0m agent-a cannot resolve agent-c (partition holds)
[2026-04-23 19:18:21] [1;33m[TEST][0m agent-c cannot lookup agent-a (cross-partition)
[2026-04-23 19:18:21] [0;32m[PASS][0m agent-c cannot resolve agent-a (partition holds)
[2026-04-23 19:18:21] [1;33m[TEST][0m agent-a can lookup agent-b (same side)
[2026-04-23 19:18:22] [0;32m[PASS][0m same-side lookup works (agent-b=0:0000.0000.0001)
[2026-04-23 19:18:22] [1;33m[TEST][0m agent-c can lookup agent-d (same side)
[2026-04-23 19:18:22] [0;32m[PASS][0m same-side lookup works (agent-d=0:0000.0000.0001)
[2026-04-23 19:18:22] [1;33m[TEST][0m no panic/fatal in any daemon log
[2026-04-23 19:18:22] [0;32m[PASS][0m clean logs

==========================================
Split-brain divergence summary
==========================================
Passed: [0;32m6[0m
Failed: [0;31m1[0m
==========================================
```

### `test_webhook_message_received.sh` (exit=1, 49s)

```
[2026-04-23 19:17:59] [0;32m[PASS][0m both agents registered
[2026-04-23 19:17:59] [1;33m[TEST][0m configure agent-b webhook
[2026-04-23 19:18:00] [0;32m[PASS][0m webhook set
service "webhook-sink" is not running
service "webhook-sink" is not running
service "webhook-sink" is not running
service "webhook-sink" is not running
service "webhook-sink" is not running
service "webhook-sink" is not running
service "webhook-sink" is not running
service "webhook-sink" is not running
service "webhook-sink" is not running
service "webhook-sink" is not running
service "webhook-sink" is not running
[2026-04-23 19:18:15] [1;33m[TEST][0m agent-a sends exactly one message to agent-b
[2026-04-23 19:18:17] [0;32m[PASS][0m send-message ok
service "webhook-sink" is not running
[2026-04-23 19:18:29] [1;33m[TEST][0m exactly one message.received webhook (delta=0)
[2026-04-23 19:18:29] [0;31m[FAIL][0m expected delta=1 got 0
Passed: 3  Failed: 1
```

### `test_ring4_routing.sh` (exit=1, 132s)

```
    02:18:09.078748505 hop host=agent-b path=start,agent-b ttl=2
    resolved "agent-c" → 0:0000.0000.0003
    {
      "ack": "ACK JSON 56 bytes",
      "bytes": 56,
      "target": "0:0000.0000.0003",
      "type": "json"
    }
  === c ring.log ===
    02:18:09.524650380 hop host=agent-c path=start,agent-b,agent-c ttl=1
    resolved "agent-d" → 0:0000.0000.0002
    {
      "ack": "ACK JSON 64 bytes",
      "bytes": 64,
      "target": "0:0000.0000.0002",
      "type": "json"
    }
  === d ring.log ===
    02:18:10.002834381 hop host=agent-d path=start,agent-b,agent-c,agent-d ttl=0
[2026-04-23 19:18:43] [1;33m[TEST][0m final path shows all four hops in order
[2026-04-23 19:18:43] [0;31m[FAIL][0m path wrong: got '' want 'start,agent-b,agent-c,agent-d,agent-a'
[2026-04-23 19:18:43] [1;33m[TEST][0m no panics/fatals
[2026-04-23 19:18:43] [0;32m[PASS][0m clean logs

==========================================
Ring-4 routing summary
==========================================
Passed: [0;32m4[0m
Failed: [0;31m2[0m
==========================================
```

### `test_register_identity_new_endpoint.sh` (exit=1, 140s)

```
==========================================
Identity re-register with new endpoint
==========================================
[2026-04-23 19:16:32] [0;32m[PASS][0m agents up
[2026-04-23 19:16:33] [0;32m[PASS][0m initial endpoint: 172.29.15.21:4000
[2026-04-23 19:16:33] [1;33m[TEST][0m stop agent-b, bring it back with a different listen port
Error response from daemon: container dd3830ec74228a79ca49a7380a96fdce33dffea48b971efa5de452a2bc1069fc is not running
[2026-04-23 19:18:34] [0;32m[PASS][0m new endpoint seen in registry: 172.29.15.21:4000
[2026-04-23 19:18:34] [1;33m[TEST][0m registry entry superseded: new endpoint reflects :4001
[2026-04-23 19:18:34] [0;31m[FAIL][0m endpoint still 172.29.15.21:4000 (expected suffix :4001, was 172.29.15.21:4000)
[2026-04-23 19:18:34] [1;33m[TEST][0m node_id remains the same (same identity)
[2026-04-23 19:18:34] [0;31m[FAIL][0m node_id changed: 2 -> 
[2026-04-23 19:18:34] [1;33m[TEST][0m only one registry entry for this identity (no stale duplicate)
[2026-04-23 19:18:34] [0;31m[FAIL][0m registry has 3 nodes — stale duplicate suspected
[2026-04-23 19:18:34] [1;33m[TEST][0m agent-a can still reach agent-b at the new endpoint
[2026-04-23 19:18:47] [0;31m[FAIL][0m ping failed after endpoint change — a may be caching old endpoint
[2026-04-23 19:18:47] [1;33m[TEST][0m no panic/fatal
[2026-04-23 19:18:47] [0;32m[PASS][0m clean logs

Passed: 4  Failed: 4
```

### `test_ping_ghost_peer.sh` (exit=1, 181s)

```
==========================================
Ping / send / submit to a ghost peer
==========================================
[2026-04-23 19:15:59] [1;33m[TEST][0m fresh stack
[2026-04-23 19:16:04] [0;32m[PASS][0m both agents registered
[2026-04-23 19:16:04] [1;33m[TEST][0m warm-up ping a->b so agent-a has cached crypto+endpoint
[2026-04-23 19:16:06] [0;32m[PASS][0m tunnel warm
[2026-04-23 19:16:06] [1;33m[TEST][0m SIGKILL agent-b (no graceful unregister)
[2026-04-23 19:16:08] [0;32m[PASS][0m agent-b is dead
[2026-04-23 19:16:08] [1;33m[TEST][0m ping a->b (ghost) fails within --timeout 4s
[2026-04-23 19:16:13] [0;32m[PASS][0m ping failed in 5s (rc=1)
[2026-04-23 19:16:13] [1;33m[TEST][0m send-message a->b (ghost) fails with clear error
[2026-04-23 19:16:23] [0;32m[PASS][0m send-message refused (rc=124)
[2026-04-23 19:16:23] [1;33m[TEST][0m task submit a->b (ghost) — must not report completion
[2026-04-23 19:16:39] [0;32m[PASS][0m submit to ghost peer refused at the front door
[2026-04-23 19:16:39] [1;33m[TEST][0m agent-a has no panic/fatal after ghost attempts
[2026-04-23 19:16:39] [0;32m[PASS][0m agent-a log clean
[2026-04-23 19:16:39] [1;33m[TEST][0m restart agent-b; ping a->b works again
[2026-04-23 19:19:00] [0;31m[FAIL][0m a's state poisoned — ping still fails after b came back

==========================================
Ghost-peer summary
==========================================
Passed: [0;32m7[0m
Failed: [0;31m1[0m
==========================================
```

### `test_webhook_exactly_once_on_restart.sh` (exit=1, 106s)

```
[2026-04-23 19:19:17] [0;31m[FAIL][0m agents did not register
```

### `test_webhook_file_delivered.sh` (exit=1, 103s)

```
[2026-04-23 19:17:42] [1;33m[TEST][0m fresh webhooks stack
[2026-04-23 19:19:25] [0;31m[FAIL][0m agents did not register
```

### `test_webhook_pubsub_published.sh` (exit=1, 89s)

```
[2026-04-23 19:19:36] [0;31m[FAIL][0m agents did not register
```

### `test_webhook_task_completed.sh` (exit=1, 84s)

```
[2026-04-23 19:19:47] [0;31m[FAIL][0m agents did not register
```

### `test_webhook_task_submitted.sh` (exit=1, 83s)

```
[2026-04-23 19:19:58] [0;31m[FAIL][0m agents did not register
```

### `test_webhook_trust_changed.sh` (exit=1, 76s)

```
[2026-04-23 19:20:02] [0;31m[FAIL][0m agents did not register
```

### `test_webhook_tunnel_established.sh` (exit=1, 77s)

```
[2026-04-23 19:20:05] [0;31m[FAIL][0m agents did not register
```

### `test_dur_steady_10min.sh` (exit=1, 612s)

```
==========================================
Duration: steady 10 msg/s x 600s
==========================================
[2026-04-23 19:10:40] [0;32m[PASS][0m both agents registered
[2026-04-23 19:10:40] [1;33m[TEST][0m T=0 snapshot (agent-a)
[2026-04-23 19:10:41] [0;32m[PASS][0m T0: rss=12016KiB fds=9
[2026-04-23 19:10:41] [1;33m[TEST][0m start steady send loop 10/s for 600s
[2026-04-23 19:20:46] [1;33m[TEST][0m T=end snapshot (agent-a)
[2026-04-23 19:20:46] [0;32m[PASS][0m T1: rss=31036KiB fds=9
    delta: rss=19020KiB fds=0
[2026-04-23 19:20:46] [1;33m[TEST][0m rss delta < 100 MiB over 10 min of load
[2026-04-23 19:20:46] [0;32m[PASS][0m rss delta 19020KiB within budget
[2026-04-23 19:20:46] [1;33m[TEST][0m fd delta < 50
[2026-04-23 19:20:46] [0;32m[PASS][0m fd delta 0 within budget
[2026-04-23 19:20:46] [1;33m[TEST][0m expected send volume reached
[2026-04-23 19:20:47] [0;31m[FAIL][0m sent=2086 much less than target 6000
[2026-04-23 19:20:47] [1;33m[TEST][0m no panics / leaks in logs
[2026-04-23 19:20:47] [0;32m[PASS][0m clean logs

Passed: 6  Failed: 1
```

### `test_resilience.sh` (exit=1, 1220s)

```
==========================================
Resilience / restart / concurrency tests
==========================================
[2026-04-23 19:10:39] [1;33m[TEST][0m 50 parallel echo roundtrips from agent-a to agent-b
[2026-04-23 19:10:45] [0;32m[PASS][0m 50/50 echo roundtrips ok
[2026-04-23 19:10:45] [1;33m[TEST][0m restart agent-b and confirm it re-registers
[2026-04-23 19:10:54] [0;32m[PASS][0m agent-b re-registered (was 2, now 2)
[2026-04-23 19:10:54] [1;33m[TEST][0m echo to agent-b recovers after restart (poll ≤4min)
[2026-04-23 19:30:39] [0;31m[FAIL][0m post-restart echo never recovered in 4 minutes
[2026-04-23 19:30:39] [1;33m[TEST][0m restart rendezvous and confirm agents reconnect (≤4min)
[2026-04-23 19:30:39] [0;32m[PASS][0m both agents reconnected after rendezvous restart (total_nodes=3, ~1×5s)
[2026-04-23 19:30:39] [1;33m[TEST][0m agent-a process survived 60s+ of activity
[2026-04-23 19:30:39] [0;32m[PASS][0m agent-a pid 1 alive, RSS 18980 KB
[2026-04-23 19:30:39] [1;33m[TEST][0m pulse endpoint shows non-zero total_requests
[2026-04-23 19:30:40] [0;31m[FAIL][0m pulse flat: total_requests=1578 samples=0
[2026-04-23 19:30:40] [1;33m[TEST][0m concurrent send-message agent-a→b and agent-b→a
[2026-04-23 19:30:55] [0;32m[PASS][0m concurrent bidirectional send-message completed
[2026-04-23 19:30:55] [1;33m[TEST][0m agent logs free of panic/fatal
[2026-04-23 19:30:55] [0;32m[PASS][0m no panic/fatal/race in recent logs

==========================================
Resilience Test Summary
==========================================
Passed: [0;32m6[0m
Failed: [0;31m2[0m
==========================================
```

