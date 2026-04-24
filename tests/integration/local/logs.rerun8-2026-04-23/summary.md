# Integration test run summary

- Run duration: 1525s
- Workers: 10
- Tests: 231 (pass=155, fail=76)
- Serial sum: 12834s (speedup = 8.42x)
- Utilization: w0=99.0% w1=80.4% w2=84.6% w3=86.0% w4=86.4% w5=79.0% w6=85.6% w7=76.1% w8=88.1% w9=76.6% 

| Status | Test | Duration | Exit |
|--------|------|----------|------|
| FAIL | `test_resilience.sh` | 1239s | 1 |
| FAIL | `test_dur_steady_10min.sh` | 610s | 1 |
| FAIL | `test_dur_steady_compressed_24h.sh` | 309s | 1 |
| FAIL | `test_cli.sh` | 275s | 1 |
| FAIL | `test_ping_ghost_peer.sh` | 186s | 1 |
| FAIL | `test_chaos_loss30_all_ops.sh` | 172s | 1 |
| FAIL | `test_register_identity_new_endpoint.sh` | 162s | 1 |
| FAIL | `test_chaos_packet_loss.sh` | 144s | 1 |
| FAIL | `test_force_relay_task.sh` | 124s | 1 |
| FAIL | `test_chaos_loss10_all_ops.sh` | 109s | 1 |
| FAIL | `test_rendezvous_restart_midflight.sh` | 109s | 1 |
| FAIL | `test_webhook_exactly_once_on_restart.sh` | 104s | 1 |
| FAIL | `test_webhook_file_delivered.sh` | 101s | 1 |
| FAIL | `test_webhook_message_received.sh` | 101s | 1 |
| FAIL | `test_webhook_pubsub_published.sh` | 97s | 1 |
| FAIL | `test_webhook_task_completed.sh` | 96s | 1 |
| FAIL | `test_webhook_task_submitted.sh` | 96s | 1 |
| FAIL | `test_gateway_http_message.sh` | 93s | 1 |
| FAIL | `test_beacon_restart_midflight.sh` | 92s | 1 |
| FAIL | `test_webhook_tunnel_established.sh` | 92s | 1 |
| FAIL | `test_force_relay_pubsub.sh` | 91s | 1 |
| FAIL | `test_webhook_trust_changed.sh` | 91s | 1 |
| FAIL | `test_midrekey_task_results.sh` | 89s | 1 |
| FAIL | `test_partition_heal.sh` | 82s | 1 |
| FAIL | `test_fanin_3agents_tasks.sh` | 77s | 1 |
| FAIL | `test_net_mutual_admiration_shipped.sh` | 77s | 1 |
| FAIL | `test_receiver_sigkill_midfile.sh` | 72s | 1 |
| FAIL | `test_nat_asymmetric_routing.sh` | 71s | 1 |
| FAIL | `test_dur_shortcycle_policy_1m.sh` | 69s | 1 |
| FAIL | `test_net_data_exchange_policy_shipped.sh` | 63s | 1 |
| FAIL | `test_ring4_routing.sh` | 63s | 1 |
| FAIL | `test_net_gossip_tax_shipped.sh` | 56s | 1 |
| FAIL | `test_policy_datagram_score.sh` | 55s | 1 |
| FAIL | `test_sender_clean_restart_midflight.sh` | 51s | 1 |
| FAIL | `test_policy_connect_deny.sh` | 50s | 1 |
| FAIL | `test_webhook_agent_registered.sh` | 50s | 1 |
| FAIL | `test_net_polo_scoped_per_network.sh` | 41s | 1 |
| FAIL | `test_tasks_and_edge.sh` | 41s | 1 |
| FAIL | `test_net_golden_hour_shipped.sh` | 39s | 1 |
| FAIL | `test_net_trust_scoped_per_network.sh` | 39s | 1 |
| FAIL | `test_policy_cycle_evict.sh` | 36s | 1 |
| FAIL | `test_nat_dual_symmetric.sh` | 34s | 1 |
| FAIL | `test_net_gift_economy_shipped.sh` | 34s | 1 |
| FAIL | `test_net_burnout_shipped.sh` | 31s | 1 |
| FAIL | `test_sec_trust_grant_forgery.sh` | 31s | 1 |
| FAIL | `test_net_isolation_policy_scoping.sh` | 30s | 1 |
| FAIL | `test_policy_cycle_fill_trust.sh` | 30s | 1 |
| FAIL | `test_net_half_life_shipped.sh` | 29s | 1 |
| FAIL | `test_net_high_trust_society_shipped.sh` | 27s | 1 |
| FAIL | `test_policy_cycle_webhook.sh` | 27s | 1 |
| FAIL | `test_splitbrain_divergence.sh` | 27s | 1 |
| FAIL | `test_chaos_delay200_all_ops.sh` | 26s | 1 |
| FAIL | `test_gateway_trust_grant.sh` | 26s | 1 |
| FAIL | `test_policy_datagram_deny.sh` | 25s | 1 |
| FAIL | `test_policy_join_allow.sh` | 23s | 1 |
| FAIL | `test_task_executor.sh` | 23s | 1 |
| FAIL | `test_net_anti_camping_shipped.sh` | 21s | 1 |
| FAIL | `test_net_cross_network_traffic_denied.sh` | 21s | 1 |
| FAIL | `test_net_cooling_off_shipped.sh` | 20s | 1 |
| FAIL | `test_net_karma_ledger_shipped.sh` | 20s | 1 |
| FAIL | `test_net_lottery_shipped.sh` | 19s | 1 |
| FAIL | `test_net_tithe_shipped.sh` | 18s | 1 |
| FAIL | `test_net_aristocracy_shipped.sh` | 16s | 1 |
| FAIL | `test_net_meritocracy_shipped.sh` | 15s | 1 |
| FAIL | `test_net_pay_it_forward_shipped.sh` | 15s | 1 |
| FAIL | `test_net_rotating_chairs_shipped.sh` | 15s | 1 |
| FAIL | `test_net_small_circle_shipped.sh` | 15s | 1 |
| FAIL | `test_net_join_deny_per_network.sh` | 14s | 1 |
| FAIL | `test_net_meritocracy_rating_shipped.sh` | 14s | 1 |
| FAIL | `test_net_stable_state_shipped.sh` | 14s | 1 |
| FAIL | `test_net_two_strikes_shipped.sh` | 14s | 1 |
| FAIL | `test_net_ostracism_shipped.sh` | 13s | 1 |
| FAIL | `test_net_whale_hunt_shipped.sh` | 13s | 1 |
| FAIL | `test_sec_ipc_exhaustion.sh` | 11s | 1 |
| FAIL | `test_net_cold_shoulder_shipped.sh` | 7s | 1 |
| FAIL | `test_splitbrain_heal.sh` | 6s | 1 |
| PASS | `test_dur_idle_10min.sh` | 606s | 0 |
| PASS | `test_sec_rekey_flood.sh` | 237s | 0 |
| PASS | `test_size_file_100mb.sh` | 196s | 0 |
| PASS | `test_size_file_50mb.sh` | 145s | 0 |
| PASS | `test_nat_address_restricted.sh` | 127s | 0 |
| PASS | `test_nat_stateful_firewall.sh` | 123s | 0 |
| PASS | `test_nat_plus_mtu.sh` | 113s | 0 |
| PASS | `test_nat_plus_loss.sh` | 106s | 0 |
| PASS | `test_nat_cgn.sh` | 104s | 0 |
| PASS | `test_nat_conntrack_timeout.sh` | 98s | 0 |
| PASS | `test_nat_restricted_cone.sh` | 92s | 0 |
| PASS | `test_nat_udp_blocked.sh` | 90s | 0 |
| PASS | `test_nat_full_cone.sh` | 86s | 0 |
| PASS | `test_policy_shipped_configs.sh` | 85s | 0 |
| PASS | `test_nat_hairpin.sh` | 79s | 0 |
| PASS | `test_nat_symmetric.sh` | 79s | 0 |
| PASS | `test_receiver_sigkill_midtask.sh` | 75s | 0 |
| PASS | `test_task_accept_expiry.sh` | 75s | 0 |
| PASS | `test_net_grudge_match_shipped.sh` | 73s | 0 |
| PASS | `test_nat_partition_post_reg.sh` | 72s | 0 |
| PASS | `test_network_edge.sh` | 70s | 0 |
| PASS | `test_sec_replay_after_rekey.sh` | 69s | 0 |
| PASS | `test_dur_idle_60s.sh` | 66s | 0 |
| PASS | `test_dur_periodic_60s.sh` | 66s | 0 |
| PASS | `test_sec_sym_nat_spoof.sh` | 66s | 0 |
| PASS | `test_nat_plus_latency.sh` | 64s | 0 |
| PASS | `test_nat_rendezvous_natted.sh` | 64s | 0 |
| PASS | `test_race_polo_read_write.sh` | 64s | 0 |
| PASS | `test_stress_edge.sh` | 62s | 0 |
| PASS | `test_task_sequential_burst.sh` | 62s | 0 |
| PASS | `test_nat_plus_reorder.sh` | 61s | 0 |
| PASS | `test_nat_plus_bandwidth.sh` | 57s | 0 |
| PASS | `test_nat_egress_443_only.sh` | 56s | 0 |
| PASS | `test_sender_sigkill_midfile.sh` | 53s | 0 |
| PASS | `test_service_agent.sh` | 51s | 0 |
| PASS | `test_trust_revoke.sh` | 51s | 0 |
| PASS | `test_pubsub_fanout.sh` | 49s | 0 |
| PASS | `test_size_file_10mb.sh` | 48s | 0 |
| PASS | `test_sec_sybil_reputation.sh` | 45s | 0 |
| PASS | `test_webhook_polo_updated.sh` | 45s | 0 |
| PASS | `test_star5_hub_fanout.sh` | 44s | 0 |
| PASS | `test_task_polo_gate.sh` | 43s | 0 |
| PASS | `test_size_file_500mb_reject.sh` | 42s | 0 |
| PASS | `test_nat_ipv6_only.sh` | 41s | 0 |
| PASS | `test_race_register_lookup.sh` | 41s | 0 |
| PASS | `test_size_pubsub_large.sh` | 41s | 0 |
| PASS | `test_task_progress_events.sh` | 41s | 0 |
| PASS | `test_task_result_integrity.sh` | 41s | 0 |
| PASS | `test_peer_restarted_pubsub_sub.sh` | 40s | 0 |
| PASS | `test_send_file_concurrent.sh` | 40s | 0 |
| PASS | `test_mixed_traffic_burst.sh` | 39s | 0 |
| PASS | `test_sec_pubsub_spam.sh` | 39s | 0 |
| PASS | `test_task_polo_guarantee.sh` | 39s | 0 |
| PASS | `test_results_after_submitter_died.sh` | 38s | 0 |
| PASS | `test_task_bidirectional_services.sh` | 38s | 0 |
| PASS | `test_trust_grant_already_connected.sh` | 38s | 0 |
| PASS | `test_trust_grant_fresh.sh` | 37s | 0 |
| PASS | `test_task_file_results.sh` | 36s | 0 |
| PASS | `test_policy_connect_score.sh` | 35s | 0 |
| PASS | `test_task_accepted_restart_recovery.sh` | 35s | 0 |
| PASS | `test_nat_multihomed.sh` | 34s | 0 |
| PASS | `test_policy_join_score.sh` | 34s | 0 |
| PASS | `test_task_concurrent_workers.sh` | 33s | 0 |
| PASS | `test_task_message_chain.sh` | 32s | 0 |
| PASS | `test_gateway_rotate_key.sh` | 31s | 0 |
| PASS | `test_net_cross_network_traffic_allowed.sh` | 31s | 0 |
| PASS | `test_policy_connect_tag.sh` | 31s | 0 |
| PASS | `test_task_policy_decline.sh` | 30s | 0 |
| PASS | `test_race_trust_grant_revoke.sh` | 29s | 0 |
| PASS | `test_task_description_integrity.sh` | 29s | 0 |
| PASS | `test_task_execute_fifo.sh` | 29s | 0 |
| PASS | `test_policy_cycle_prune_trust.sh` | 28s | 0 |
| PASS | `test_sec_beacon_amplification.sh` | 28s | 0 |
| PASS | `test_star5_hub_fanin.sh` | 28s | 0 |
| PASS | `test_task_decline.sh` | 28s | 0 |
| PASS | `test_force_relay_send_message.sh` | 27s | 0 |
| PASS | `test_pubsub_service_agent.sh` | 27s | 0 |
| PASS | `test_size_task_result_10mb.sh` | 27s | 0 |
| PASS | `test_task_execute_flow.sh` | 27s | 0 |
| PASS | `test_task_persistence_restart.sh` | 27s | 0 |
| PASS | `test_bidirectional.sh` | 26s | 0 |
| PASS | `test_sec_spoofed_node_id.sh` | 26s | 0 |
| PASS | `test_size_message_10mb_reject.sh` | 26s | 0 |
| PASS | `test_race_topic_delete_publish.sh` | 25s | 0 |
| PASS | `test_chaos_reorder_all_ops.sh` | 24s | 0 |
| PASS | `test_fanout_5agents_pubsub.sh` | 24s | 0 |
| PASS | `test_force_relay_send_file.sh` | 24s | 0 |
| PASS | `test_race_sendfile_rekey.sh` | 24s | 0 |
| PASS | `test_type_routed_service.sh` | 24s | 0 |
| PASS | `test_gateway_pubsub_pub.sh` | 23s | 0 |
| PASS | `test_gateway_task_result.sh` | 23s | 0 |
| PASS | `test_mesh_3agents_crosstraffic.sh` | 23s | 0 |
| PASS | `test_policy_join_deny.sh` | 23s | 0 |
| PASS | `test_net_forgiveness_shipped.sh` | 22s | 0 |
| PASS | `test_obs_log_peer_rekeyed.sh` | 22s | 0 |
| PASS | `test_polo_persistence_restart.sh` | 22s | 0 |
| PASS | `test_pubsub_publish_to_empty_topic.sh` | 22s | 0 |
| PASS | `test_pubsub_subscribe_before_publisher.sh` | 22s | 0 |
| PASS | `test_rendezvous_beacon_split.sh` | 22s | 0 |
| PASS | `test_sec_malformed_frame.sh` | 22s | 0 |
| PASS | `test_gateway_task_submit.sh` | 21s | 0 |
| PASS | `test_net_dunbar_150_shipped.sh` | 21s | 0 |
| PASS | `test_partition_midflight.sh` | 21s | 0 |
| PASS | `test_policy_datagram_allow.sh` | 21s | 0 |
| PASS | `test_task_invalid_states.sh` | 20s | 0 |
| PASS | `test_pubsub_topic_fifo.sh` | 19s | 0 |
| PASS | `test_race_submit_rekey.sh` | 19s | 0 |
| PASS | `test_submit_to_unregistered_peer.sh` | 19s | 0 |
| PASS | `test_disk_full_receiver.sh` | 18s | 0 |
| PASS | `test_midrekey_send_message.sh` | 18s | 0 |
| PASS | `test_midrekey_task_submit.sh` | 18s | 0 |
| PASS | `test_net_fifo_shipped.sh` | 18s | 0 |
| PASS | `test_obs_metric_encrypt_ok.sh` | 18s | 0 |
| PASS | `test_send_file_bidirectional_transform.sh` | 18s | 0 |
| PASS | `test_send_file_integrity.sh` | 18s | 0 |
| PASS | `test_chain_abc_task.sh` | 17s | 0 |
| PASS | `test_fanout_3agents_pubsub.sh` | 17s | 0 |
| PASS | `test_gateway_file.sh` | 17s | 0 |
| PASS | `test_gateway_polo_read.sh` | 17s | 0 |
| PASS | `test_gateway_register.sh` | 17s | 0 |
| PASS | `test_midrekey_send_file.sh` | 17s | 0 |
| PASS | `test_pubsub_multi_publisher.sh` | 17s | 0 |
| PASS | `test_gateway_lookup.sh` | 16s | 0 |
| PASS | `test_net_vouching_chain_shipped.sh` | 16s | 0 |
| PASS | `test_task_list_ordering.sh` | 16s | 0 |
| PASS | `test_net_join_allow_per_network.sh` | 15s | 0 |
| PASS | `test_net_sybil_gauntlet_shipped.sh` | 15s | 0 |
| PASS | `test_obs_dashboard_polo_truth.sh` | 15s | 0 |
| PASS | `test_obs_tasklist_vs_disk.sh` | 15s | 0 |
| PASS | `test_peer_restarted_send_message.sh` | 15s | 0 |
| PASS | `test_race_pubsub_late_sub.sh` | 15s | 0 |
| PASS | `test_net_lifo_shipped.sh` | 14s | 0 |
| PASS | `test_net_old_guard_shipped.sh` | 14s | 0 |
| PASS | `test_net_seniority_shipped.sh` | 14s | 0 |
| PASS | `test_race_submit_accept.sh` | 14s | 0 |
| PASS | `test_send_file_hostile_names.sh` | 14s | 0 |
| PASS | `test_dashboard.sh` | 13s | 0 |
| PASS | `test_flash_crowd_10agents_register.sh` | 13s | 0 |
| PASS | `test_message_payload_integrity.sh` | 13s | 0 |
| PASS | `test_peer_restarted_send_file.sh` | 13s | 0 |
| PASS | `test_chain_abc_message.sh` | 12s | 0 |
| PASS | `test_clock_rollback.sh` | 12s | 0 |
| PASS | `test_gateway_pubsub_sub.sh` | 12s | 0 |
| PASS | `test_inbox_ordering.sh` | 12s | 0 |
| PASS | `test_net_trust_decay_shipped.sh` | 12s | 0 |
| PASS | `test_policy_connect_allow.sh` | 12s | 0 |
| PASS | `test_rotate_key_hot_path.sh` | 12s | 0 |
| PASS | `test_clock_skew_receiver.sh` | 11s | 0 |
| PASS | `test_beacon_ping.sh` | 10s | 0 |
| PASS | `test_rotate_key.sh` | 9s | 0 |
| PASS | `test_sec_oversized_payload.sh` | 9s | 0 |
| PASS | `test_3agent_lookup_propagation.sh` | 8s | 0 |
| PASS | `test_net_all_shipped_configs_load.sh` | 8s | 0 |
| PASS | `test_fanout_3agents_file.sh` | 7s | 0 |
| PASS | `test_gateway_ping.sh` | 7s | 0 |

## Failed logs

### `test_force_relay_task.sh` (exit=1, 124s)

```
==========================================
Force relay: task submit+complete
==========================================
[2026-04-23 18:37:22] [1;33m[TEST][0m partition direct UDP
[2026-04-23 18:37:23] [0;32m[PASS][0m direct severed
[2026-04-23 18:37:33] [1;33m[TEST][0m task submit a->b via relay
[2026-04-23 18:37:33] [0;31m[FAIL][0m submit failed at door: {"code":"connection_failed","error":"submit: EOF","message":"submit: EOF","status":"error"}
[2026-04-23 18:37:33] [1;33m[TEST][0m task reaches completion via relay
[2026-04-23 18:39:19] [0;31m[FAIL][0m stuck at  — likely P1-010
[2026-04-23 18:39:19] [1;33m[TEST][0m no panic/fatal
[2026-04-23 18:39:19] [0;32m[PASS][0m clean logs

Passed: 2  Failed: 2
```

### `test_rendezvous_restart_midflight.sh` (exit=1, 109s)

```
==========================================
Rendezvous restart mid-flight
==========================================
[2026-04-23 18:37:43] [1;33m[TEST][0m Starting p2p stack (clean)
[2026-04-23 18:37:46] [0;32m[PASS][0m both agents registered
[2026-04-23 18:37:46] [1;33m[TEST][0m warm-up task to establish tunnel + peer caches
[2026-04-23 18:37:48] [0;32m[PASS][0m tunnel warm (status=SUCCEEDED)
[2026-04-23 18:37:48] [1;33m[TEST][0m stop rendezvous container (keep agents up)
[2026-04-23 18:37:50] [0;32m[PASS][0m rendezvous stopped; still running: agent-a agent-b gateway 
[2026-04-23 18:37:50] [1;33m[TEST][0m task a->b completes while rendezvous down (30s)
[2026-04-23 18:38:28] [0;31m[FAIL][0m submit during outage failed: {"code":"not_found","error":"cannot resolve \"agent-b\" — is the hostname correct and is there mutual trust? (see: pilotctl handshake)","message":"cannot resolve \"agent-b\" — is the hostname correct and is there mutual trust? (see: pilotctl handshake)","status":"error"}
[2026-04-23 18:38:28] [1;33m[TEST][0m send-file 2 KiB a->b while rendezvous down
[2026-04-23 18:38:48] [0;31m[FAIL][0m file mismatch under outage src=55a086168fc3... dst=... ack=
[2026-04-23 18:38:48] [1;33m[TEST][0m start rendezvous back up
[2026-04-23 18:38:49] [0;32m[PASS][0m both agents re-registered post-rendezvous-restart (total=3)
[2026-04-23 18:38:49] [1;33m[TEST][0m pilotctl find agent-b from agent-a resolves
[2026-04-23 18:38:57] [0;32m[PASS][0m lookup resolved: 0:0000.0000.0003
[2026-04-23 18:38:57] [1;33m[TEST][0m task a->b completes post-rendezvous-restart
[2026-04-23 18:39:32] [0;31m[FAIL][0m post-restart task stuck (status=)
[2026-04-23 18:39:32] [1;33m[TEST][0m no panics/fatals in agent logs
[2026-04-23 18:39:32] [0;32m[PASS][0m clean logs

==========================================
Rendezvous restart summary
==========================================
Passed: [0;32m6[0m
Failed: [0;31m3[0m
==========================================
```

### `test_chaos_loss30_all_ops.sh` (exit=1, 172s)

```
==========================================
Chaos: 30% loss x all 7 op families (P1-010)
==========================================
[2026-04-23 18:37:16] [1;33m[TEST][0m fresh chaos-capable stack
[2026-04-23 18:37:20] [0;32m[PASS][0m both agents registered
[2026-04-23 18:37:22] [1;33m[TEST][0m apply 30% loss on agent-b eth0
[2026-04-23 18:37:22] [0;32m[PASS][0m netem 30% loss applied
[2026-04-23 18:37:22] [1;33m[TEST][0m ping a->b under 30% loss (long timeout)
[2026-04-23 18:37:40] [0;32m[PASS][0m ping ok
[2026-04-23 18:37:40] [1;33m[TEST][0m send-message under 30% loss
[2026-04-23 18:37:41] [0;32m[PASS][0m send-message ok
[2026-04-23 18:37:41] [1;33m[TEST][0m send-file 8 KiB under 30% loss (sha256 match or clean fail)
[2026-04-23 18:37:42] [0;32m[PASS][0m send-file sha match under 30% loss
[2026-04-23 18:37:42] [1;33m[TEST][0m task submit a->b under 30% loss (120s)
[2026-04-23 18:40:04] [0;31m[FAIL][0m task stuck (status=CANCELLED) — expected P1-010 finding
[2026-04-23 18:40:04] [1;33m[TEST][0m pubsub publish under 30% loss
[2026-04-23 18:40:04] [0;32m[PASS][0m publish ok
[2026-04-23 18:40:04] [1;33m[TEST][0m trust handshake under 30% loss
[2026-04-23 18:40:04] [0;32m[PASS][0m handshake ok
[2026-04-23 18:40:04] [1;33m[TEST][0m pilotctl find agent-b (registry lookup) under 30% loss
[2026-04-23 18:40:04] [0;32m[PASS][0m registry lookup ok
[2026-04-23 18:40:04] [1;33m[TEST][0m strip chaos and verify post-chaos ping works
[2026-04-23 18:40:06] [0;32m[PASS][0m post-chaos ping ok
[2026-04-23 18:40:06] [1;33m[TEST][0m no panic/fatal in agent logs
[2026-04-23 18:40:06] [0;32m[PASS][0m clean logs

Passed: 10  Failed: 1
```

### `test_splitbrain_heal.sh` (exit=1, 6s)

```
==========================================
Split-brain heal
==========================================
[2026-04-23 18:40:33] [1;33m[TEST][0m Starting splitbrain stack
[2026-04-23 18:40:38] [0;31m[FAIL][0m split not set up (c1=3 c2=2)
```

### `test_gateway_http_message.sh` (exit=1, 93s)

```
==========================================
Gateway: HTTP/message round-trip via proxy
==========================================
[2026-04-23 18:39:48] [0;32m[PASS][0m agent-b pilot addr: 0:0000.0000.0002
[2026-04-23 18:39:48] [1;33m[TEST][0m map agent-b into gateway local subnet
[2026-04-23 18:39:48] [0;32m[PASS][0m mapped 0:0000.0000.0002 -> 10.4.0.1
[2026-04-23 18:39:48] [1;33m[TEST][0m send payload to 10.4.0.1:1001 (agent-b's data-exchange service)
[2026-04-23 18:41:03] [0;31m[FAIL][0m could not open TCP to 10.4.0.1:1001 via gateway
[2026-04-23 18:41:05] [1;33m[TEST][0m payload delivered to agent-b inbox
[2026-04-23 18:41:06] [0;31m[FAIL][0m payload not found in agent-b inbox; gateway proxy may not have delivered
time=2026-04-24T01:39:49.242Z level=INFO msg="gateway connected" subnet=10.4.0.0/16
time=2026-04-24T01:39:49.242Z level=INFO msg="gateway running"

Passed: 2  Failed: 2
```

### `test_cli.sh` (exit=1, 275s)

```
{
  "node_id": 71771,
  "type": "set_visibility_ok",
  "visibility": "private"
}
[2026-04-23 18:41:50] [0;32m[PASS][0m Visibility toggle works
[2026-04-23 18:41:50] [1;33m[TEST][0m Testing tag management
tags set: #test #integration #docker
tags cleared
[2026-04-23 18:41:50] [0;32m[PASS][0m Tag management works
[2026-04-23 18:41:50] [1;33m[TEST][0m Checking configuration
[2026-04-23 18:41:50] [0;32m[PASS][0m Configuration retrieved successfully
[2026-04-23 18:41:50] [1;33m[TEST][0m Deregistering from network
{
  "type": "deregister_ok"
}
[2026-04-23 18:41:50] [0;32m[PASS][0m Successfully deregistered from network

=========================================
Test Summary
=========================================
Passed: [0;32m16[0m
Failed: [0;31m5[0m
=========================================

[1;33m[CLEANUP][0m Stopping daemon...
[1;33m[CLEANUP][0m Last daemon errors:
time=2026-04-23T18:37:15.925-07:00 level=WARN msg="failed to save account file" error="create account dir: mkdir /root: read-only file system"
time=2026-04-23T18:37:15.985-07:00 level=WARN msg="failed to save identity" error="create identity dir: mkdir /root: read-only file system"
[1;33m[CLEANUP][0m Daemon stopped.
```

### `test_dur_steady_compressed_24h.sh` (exit=1, 309s)

```
==========================================
Duration: compressed 24h (1s cycle x 300s)
==========================================
[2026-04-23 18:37:19] [0;32m[PASS][0m both agents registered
[2026-04-23 18:37:19] [1;33m[TEST][0m write 1s-cycle expr_policy
[2026-04-23 18:37:20] [0;32m[PASS][0m policy written
[2026-04-23 18:37:20] [1;33m[TEST][0m create unmanaged network then attach expr_policy
[2026-04-23 18:37:21] [0;32m[PASS][0m network active (nid=1), policy attached, joined
[2026-04-23 18:37:21] [0;32m[PASS][0m T0 rss=8684KiB fds=9
[2026-04-23 18:37:21] [1;33m[TEST][0m run for 300s
[2026-04-23 18:42:21] [0;32m[PASS][0m run complete
    cycle ticks during run: 0 (expected ~300)
[2026-04-23 18:42:21] [1;33m[TEST][0m tick count within ±25% of 300
[2026-04-23 18:42:21] [0;31m[FAIL][0m tick count 0 outside [225, 375]
    delta rss=512KiB fds=0
[2026-04-23 18:42:23] [1;33m[TEST][0m rss delta < 50 MiB
[2026-04-23 18:42:23] [0;32m[PASS][0m rss delta 512KiB within budget
[2026-04-23 18:42:23] [1;33m[TEST][0m fd delta < 20
[2026-04-23 18:42:23] [0;32m[PASS][0m fd delta 0 within budget
[2026-04-23 18:42:23] [1;33m[TEST][0m no panics
[2026-04-23 18:42:24] [0;32m[PASS][0m clean logs

Passed: 8  Failed: 1
```

### `test_net_mutual_admiration_shipped.sh` (exit=1, 77s)

```
[2026-04-23 18:41:17] [0;32m[PASS][0m net=1
[2026-04-23 18:41:20] [1;33m[TEST][0m unilateral connect produces no score (until mutual)
[2026-04-23 18:42:30] [0;31m[FAIL][0m no mutual bonus: uni=0 mutual=0 (EXPECTED: increase on reciprocation)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_chaos_delay200_all_ops.sh` (exit=1, 26s)

```
==========================================
Chaos: 200ms delay x all 7 op families
==========================================
[2026-04-23 18:42:30] [0;32m[PASS][0m both agents registered
[2026-04-23 18:42:33] [1;33m[TEST][0m apply 200ms +/-50ms delay on agent-b eth0
[2026-04-23 18:42:34] [0;32m[PASS][0m netem delay applied
[2026-04-23 18:42:34] [1;33m[TEST][0m ping under 200ms delay
[2026-04-23 18:42:39] [0;32m[PASS][0m ping ok
[2026-04-23 18:42:39] [1;33m[TEST][0m send-message under delay
[2026-04-23 18:42:39] [0;32m[PASS][0m send-message ok
[2026-04-23 18:42:39] [1;33m[TEST][0m send-file 16 KiB under 200ms delay
[2026-04-23 18:42:42] [0;32m[PASS][0m send-file sha match
[2026-04-23 18:42:42] [1;33m[TEST][0m task submit under 200ms delay (90s)
[2026-04-23 18:42:43] [0;31m[FAIL][0m task stuck (status=)
[2026-04-23 18:42:43] [1;33m[TEST][0m pubsub publish under delay
[2026-04-23 18:42:44] [0;32m[PASS][0m publish ok
test_chaos_delay200_all_ops.sh: line 118: handshake: command not found
test_chaos_delay200_all_ops.sh: line 118: approve: command not found
[2026-04-23 18:42:44] [1;33m[TEST][0m trust handshake under delay (real CLI:  + receiver )
[2026-04-23 18:42:45] [0;32m[PASS][0m handshake ok
[2026-04-23 18:42:45] [1;33m[TEST][0m pilotctl find agent-b (registry lookup) under delay
[2026-04-23 18:42:45] [0;32m[PASS][0m registry lookup ok
[2026-04-23 18:42:45] [1;33m[TEST][0m strip delay and sanity ping
[2026-04-23 18:42:48] [0;32m[PASS][0m post-chaos ping ok
[2026-04-23 18:42:48] [1;33m[TEST][0m no panic/fatal
[2026-04-23 18:42:48] [0;32m[PASS][0m clean logs

Passed: 10  Failed: 1
```

### `test_beacon_restart_midflight.sh` (exit=1, 92s)

```
==========================================
Beacon restart mid-flight
==========================================
[2026-04-23 18:41:49] [0;32m[PASS][0m both agents registered
[2026-04-23 18:41:49] [1;33m[TEST][0m warm task before beacon restart
[2026-04-23 18:41:50] [0;32m[PASS][0m warm ok
[2026-04-23 18:41:50] [1;33m[TEST][0m docker compose restart rendezvous (beacon container)
[2026-04-23 18:41:51] [0;32m[PASS][0m rendezvous+beacon container back online
[2026-04-23 18:41:51] [1;33m[TEST][0m both agents re-register post-beacon-restart
[2026-04-23 18:41:51] [0;32m[PASS][0m total_nodes=2
[2026-04-23 18:41:51] [1;33m[TEST][0m task still completes post-beacon-restart
[2026-04-23 18:43:16] [0;31m[FAIL][0m post-beacon task stuck (status=)
[2026-04-23 18:43:16] [1;33m[TEST][0m pilotctl lookup works post-beacon-restart
[2026-04-23 18:43:16] [0;32m[PASS][0m lookup ok: 0:0000.0000.0002
[2026-04-23 18:43:16] [1;33m[TEST][0m no panic/fatal in agent logs
[2026-04-23 18:43:16] [0;32m[PASS][0m clean logs

Passed: 6  Failed: 1
```

### `test_dur_shortcycle_policy_1m.sh` (exit=1, 69s)

```
==========================================
Duration: short-cycle policy 5s x 60s
==========================================
[2026-04-23 18:43:04] [0;32m[PASS][0m both agents registered
[2026-04-23 18:43:04] [1;33m[TEST][0m write short-cycle expr_policy onto agent-a
[2026-04-23 18:43:04] [0;32m[PASS][0m policy written
[2026-04-23 18:43:04] [1;33m[TEST][0m create unmanaged network then attach expr_policy
[2026-04-23 18:43:05] [0;32m[PASS][0m network created (nid=1), policy attached, joined
[2026-04-23 18:43:05] [1;33m[TEST][0m run 60s and count cycle events
    cycle tick delta over 60s: 0 (expect >= 10)
[2026-04-23 18:44:06] [0;31m[FAIL][0m only 0 cycle ticks (expected >=10 for 5s cycle over 60s)
[2026-04-23 18:44:06] [1;33m[TEST][0m no panics
[2026-04-23 18:44:07] [0;32m[PASS][0m clean logs

Passed: 4  Failed: 1
```

### `test_chaos_loss10_all_ops.sh` (exit=1, 109s)

```
==========================================
Chaos: 10% loss x all 7 op families
==========================================
[2026-04-23 18:42:26] [1;33m[TEST][0m fresh chaos-capable stack
[2026-04-23 18:42:32] [0;32m[PASS][0m both agents registered
[2026-04-23 18:42:33] [1;33m[TEST][0m apply 10% loss on agent-b eth0
[2026-04-23 18:42:34] [0;32m[PASS][0m netem 10% loss applied
[2026-04-23 18:42:34] [1;33m[TEST][0m ping a->b under 10% loss
[2026-04-23 18:42:38] [0;32m[PASS][0m ping ok
[2026-04-23 18:42:38] [1;33m[TEST][0m send-message a->b under 10% loss
[2026-04-23 18:42:38] [0;32m[PASS][0m send-message returned
[2026-04-23 18:42:38] [1;33m[TEST][0m send-file 8 KiB under 10% loss (sha256 match)
[2026-04-23 18:42:40] [0;32m[PASS][0m send-file sha match
[2026-04-23 18:42:40] [1;33m[TEST][0m task submit a->b under 10% loss (completes)
[2026-04-23 18:44:05] [0;31m[FAIL][0m task stuck (status=EXPIRED)
[2026-04-23 18:44:05] [1;33m[TEST][0m pubsub publish a->b/sensor/chaos
[2026-04-23 18:44:06] [0;32m[PASS][0m publish ok
[2026-04-23 18:44:06] [1;33m[TEST][0m trust handshake a->b under 10% loss
[2026-04-23 18:44:08] [0;32m[PASS][0m handshake returned
[2026-04-23 18:44:08] [1;33m[TEST][0m pilotctl find agent-b (registry lookup) under 10% loss
[2026-04-23 18:44:08] [0;32m[PASS][0m registry lookup ok
[2026-04-23 18:44:08] [1;33m[TEST][0m strip netem, baseline ping still works
[2026-04-23 18:44:11] [0;32m[PASS][0m post-chaos ping ok
[2026-04-23 18:44:11] [1;33m[TEST][0m no panic/fatal in agent logs
[2026-04-23 18:44:12] [0;32m[PASS][0m clean logs

Passed: 10  Failed: 1
```

### `test_fanin_3agents_tasks.sh` (exit=1, 77s)

```
  a-worker: 01:43:12.751337716 done tid=779fd476-9c56-c6bb-c0df-1a7e58bdc048 desc=from-b:1
  a-worker: {
  a-worker:   "message": "Task accepted",
  a-worker:   "status": "ACCEPTED",
  a-worker:   "task_id": "34ffe9bd-f67d-8ff5-3fe8-da87d96e49f9"
  a-worker: }
  a-worker: {
  a-worker:   "sent_to": "0:0000.0000.0002",
  a-worker:   "sent_type": "text",
  a-worker:   "status": "SUCCEEDED",
  a-worker:   "task_id": "34ffe9bd-f67d-8ff5-3fe8-da87d96e49f9"
  a-worker: }
  a-worker: 01:43:12.972607091 done tid=34ffe9bd-f67d-8ff5-3fe8-da87d96e49f9 desc=from-c:1
[2026-04-23 18:44:18] [1;33m[TEST][0m each submitter gets its own ack:* result
  mismatch role=b tid=3ccb810d-8996-f42d-9766-b2a0a19507a6 result=
  mismatch role=b tid=53c89521-1575-1c63-cbd4-b368dc232792 result=
  mismatch role=b tid=c82cb292-43af-ff63-31d4-bfacdb9fc57b result=
  mismatch role=c tid=45ddafc2-b99b-73f2-76da-922f8200e94a result=
  mismatch role=c tid=9c9273bf-6c4d-afb0-79e3-203be11d8213 result=
  mismatch role=c tid=d9cc6026-3f8e-8ab5-02d7-d8785628fd92 result=
[2026-04-23 18:44:19] [0;31m[FAIL][0m 6 mis-routed results
[2026-04-23 18:44:19] [1;33m[TEST][0m no panics/fatals in daemon logs
[2026-04-23 18:44:19] [0;32m[PASS][0m clean logs

==========================================
Fan-in tasks summary
==========================================
Passed: [0;32m4[0m
Failed: [0;31m2[0m
==========================================
```

### `test_chaos_packet_loss.sh` (exit=1, 144s)

```
==========================================
Chaos: 30% packet loss on agent-b ingress
==========================================
[2026-04-23 18:42:29] [1;33m[TEST][0m start stack with NET_ADMIN overlay
[2026-04-23 18:42:36] [0;32m[PASS][0m both agents registered
[2026-04-23 18:42:37] [1;33m[TEST][0m agent-b has NET_ADMIN + iproute2 (tc qdisc show succeeds)
[2026-04-23 18:42:37] [0;32m[PASS][0m tc available
[2026-04-23 18:42:37] [1;33m[TEST][0m baseline (no chaos) task a->b completes
[2026-04-23 18:42:40] [0;32m[PASS][0m baseline task completed cleanly (status=SUCCEEDED)
[2026-04-23 18:42:40] [1;33m[TEST][0m apply 30% ingress+egress loss on agent-b eth0
[2026-04-23 18:42:41] [0;32m[PASS][0m netem applied: qdisc netem 801c: root refcnt 11 limit 1000 loss 30%
[2026-04-23 18:42:41] [1;33m[TEST][0m task a->b completes under 30% packet loss (60s timeout)
[2026-04-23 18:44:09] [0;31m[FAIL][0m task stuck under 30% loss (status=) — retransmit gap
[2026-04-23 18:44:09] [1;33m[TEST][0m send-file 4 KiB completes under 30% loss
[2026-04-23 18:44:11] [0;32m[PASS][0m file round-trip intact (ack=ACK FILE 4096 bytes sha=51ad12061c23...)
[2026-04-23 18:44:11] [1;33m[TEST][0m strip netem qdisc and verify clean traffic again
[2026-04-23 18:44:13] [0;32m[PASS][0m netem removed cleanly
[2026-04-23 18:44:53] [0;31m[FAIL][0m post-chaos task stuck (status=)
[2026-04-23 18:44:53] [1;33m[TEST][0m no panic/fatal in daemon logs
[2026-04-23 18:44:53] [0;32m[PASS][0m clean logs

==========================================
Chaos smoke summary
==========================================
Passed: [0;32m7[0m
Failed: [0;31m2[0m
==========================================
```

### `test_gateway_trust_grant.sh` (exit=1, 26s)

```
==========================================
Gateway: trust grant agent-b
==========================================
[2026-04-23 18:45:12] [1;33m[TEST][0m gateway initiates handshake to agent-b
[2026-04-23 18:45:13] [0;32m[PASS][0m handshake sent
[2026-04-23 18:45:13] [1;33m[TEST][0m agent-b sees gateway in pending
[2026-04-23 18:45:13] [0;32m[PASS][0m agent-b has gateway in pending
jq: parse error: Invalid numeric literal at line 1, column 6
[2026-04-23 18:45:14] [1;33m[TEST][0m gateway trust list contains agent-b after approval
[2026-04-23 18:45:16] [0;31m[FAIL][0m agent-b (node_id=1) not in gateway trust list
{"data":{"trusted":[]},"status":"ok"}

Passed: 2  Failed: 1
```

### `test_force_relay_pubsub.sh` (exit=1, 91s)

```
==========================================
Force relay: pub/sub delivery
==========================================
[2026-04-23 18:44:15] [1;33m[TEST][0m subscribe on b (before partition)
[2026-04-23 18:44:18] [1;33m[TEST][0m partition direct UDP
[2026-04-23 18:44:19] [0;32m[PASS][0m direct severed
[2026-04-23 18:44:29] [1;33m[TEST][0m publish from a via relay
[2026-04-23 18:44:29] [0;32m[PASS][0m publish returned
[2026-04-23 18:44:29] [1;33m[TEST][0m subscriber on b receives event via relay
[2026-04-23 18:45:29] [0;31m[FAIL][0m event not received — likely P1-010
[2026-04-23 18:45:29] [1;33m[TEST][0m no panic/fatal
[2026-04-23 18:45:29] [0;32m[PASS][0m clean logs

Passed: 3  Failed: 1
```

### `test_nat_asymmetric_routing.sh` (exit=1, 71s)

```
    #37 naming to docker.io/library/pilot-multi:latest 0.1s done
    #37 unpacking to docker.io/library/pilot-multi:latest 0.1s done
    #37 DONE 1.0s
    
    #38 [agent-a] exporting to image
    #38 exporting layers 0.0s done
    #38 exporting manifest sha256:5f287931b8edd6abf0ce3b046bee1ef57f1c74b00971483e0472878eb7c6da28 0.1s done
    #38 exporting config sha256:270dcdc2482bc15369e012d2633de6c59b20ddc5402811b71f440b9c7c3097dc 0.0s done
    #38 exporting attestation manifest sha256:19d1e91b527a7592adc7f5f7178f16b35d89099fb920a057d17ae6aaa8eae00c 0.3s done
    #38 exporting manifest list sha256:8ae0cfd216d49b29c51d6d680288ce89ee1d41bade7902cbf200b31753c35a7c 0.3s done
    #38 naming to docker.io/library/pilot-multi:latest done
    #38 unpacking to docker.io/library/pilot-multi:latest 0.1s done
    #38 DONE 1.5s
    
    #39 [rendezvous] resolving provenance for metadata file
    #39 DONE 0.5s
    
    #40 [agent-b] resolving provenance for metadata file
    #40 DONE 0.2s
    
    #41 [agent-a] resolving provenance for metadata file
    #41 DONE 0.1s
     pilot-w6-nat-gw-a  Built
     pilot-w6-nat-gw-b  Built
     pilot-multi:latest  Built
     pilot-multi:latest  Built
     pilot-multi:latest  Built
     Network pilot-w6_private-a  Creating
     Network pilot-w6_private-a  Error
    failed to create network pilot-w6_private-a: Error response from daemon: invalid pool request: Pool overlaps with other one on this address space
```

### `test_midrekey_task_results.sh` (exit=1, 89s)

```
==========================================
Mid-rekey: task results (P1-009 direct)
==========================================
[2026-04-23 18:45:12] [1;33m[TEST][0m fresh stack
[2026-04-23 18:45:17] [0;32m[PASS][0m agents up
[2026-04-23 18:45:18] [1;33m[TEST][0m submit + accept T1
[2026-04-23 18:45:22] [0;32m[PASS][0m T1 ACCEPTED on b
[2026-04-23 18:45:22] [1;33m[TEST][0m restart agent-b (rekey)
[2026-04-23 18:45:23] [0;32m[PASS][0m agent-b back, tunnel rekey window open
[2026-04-23 18:45:23] [1;33m[TEST][0m send-results during rekey window (no warm-up)
[2026-04-23 18:45:24] [1;33m[TEST][0m submitter observes terminal status within 45s
[2026-04-23 18:46:38] [0;31m[FAIL][0m stuck at EXPIRED — direct P1-009 regression
[2026-04-23 18:46:38] [1;33m[TEST][0m result text matches sender payload
[2026-04-23 18:46:38] [0;31m[FAIL][0m payload missing: 
[2026-04-23 18:46:38] [1;33m[TEST][0m no panic/fatal
[2026-04-23 18:46:39] [0;32m[PASS][0m clean logs

Passed: 4  Failed: 2
```

### `test_dur_steady_10min.sh` (exit=1, 610s)

```
==========================================
Duration: steady 10 msg/s x 600s
==========================================
[2026-04-23 18:37:19] [0;32m[PASS][0m both agents registered
[2026-04-23 18:37:19] [1;33m[TEST][0m T=0 snapshot (agent-a)
[2026-04-23 18:37:19] [0;32m[PASS][0m T0: rss=8684KiB fds=9
[2026-04-23 18:37:19] [1;33m[TEST][0m start steady send loop 10/s for 600s
[2026-04-23 18:47:24] [1;33m[TEST][0m T=end snapshot (agent-a)
[2026-04-23 18:47:25] [0;32m[PASS][0m T1: rss=27268KiB fds=9
    delta: rss=18584KiB fds=0
[2026-04-23 18:47:25] [1;33m[TEST][0m rss delta < 100 MiB over 10 min of load
[2026-04-23 18:47:25] [0;32m[PASS][0m rss delta 18584KiB within budget
[2026-04-23 18:47:25] [1;33m[TEST][0m fd delta < 50
[2026-04-23 18:47:25] [0;32m[PASS][0m fd delta 0 within budget
[2026-04-23 18:47:25] [1;33m[TEST][0m expected send volume reached
[2026-04-23 18:47:25] [0;31m[FAIL][0m sent=1950 much less than target 6000
[2026-04-23 18:47:25] [1;33m[TEST][0m no panics / leaks in logs
[2026-04-23 18:47:25] [0;32m[PASS][0m clean logs

Passed: 6  Failed: 1
```

### `test_net_anti_camping_shipped.sh` (exit=1, 21s)

```
[2026-04-23 18:50:47] [0;32m[PASS][0m net=1
[2026-04-23 18:50:50] [1;33m[TEST][0m force cycles — expect b evicted after threshold
[2026-04-23 18:50:59] [0;31m[FAIL][0m b still in rankings after idle cycles (EXPECTED: evicted)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_aristocracy_shipped.sh` (exit=1, 16s)

```
[2026-04-23 18:50:55] [0;32m[PASS][0m net=1
[2026-04-23 18:50:58] [1;33m[TEST][0m tagged elite peer bypasses default deny
[2026-04-23 18:51:00] [0;31m[FAIL][0m elite tag denied (EXPECTED: elevated privilege for elite)
[2026-04-23 18:51:00] [1;33m[TEST][0m untagged peer access vs elite: asymmetric
[2026-04-23 18:51:02] [0;32m[PASS][0m untagged denied, elite allowed — asymmetric privilege confirmed
Passed: [0;32m2[0m  Failed: [0;31m1[0m
```

### `test_nat_dual_symmetric.sh` (exit=1, 34s)

```
    #27 DONE 0.2s
    
    #28 [rendezvous] exporting to image
    #28 exporting layers done
    #28 exporting manifest sha256:fd29529e91cd413a38a2380b1fd0d0d15840c4b43bd452b0ee76728df6556e0d 0.0s done
    #28 exporting config sha256:4ebb2e69a49466ae8202caf44ad8ad815af2fc27e8b7fa5ff72c7426db3671da 0.0s done
    #28 exporting attestation manifest sha256:dee67c278ce192c7a9eb89753c7786e923748a6ea3569b754eed1ccd03dc1248 0.0s done
    #28 exporting manifest list sha256:501d65051993e23e807cb39370fa477fdcfe3677f541ce34a064f68e7977e4d8 0.0s done
    #28 naming to docker.io/library/pilot-multi:latest done
    #28 unpacking to docker.io/library/pilot-multi:latest 0.0s done
    #28 DONE 0.2s
    
    #29 [agent-b] resolving provenance for metadata file
    #29 DONE 0.2s
    
    #30 [agent-a] resolving provenance for metadata file
    #30 DONE 0.1s
    
    #31 [rendezvous] resolving provenance for metadata file
    #31 DONE 0.1s
     pilot-w9-nat-gw-a  Built
     pilot-w9-nat-gw-b  Built
     pilot-multi:latest  Built
     pilot-multi:latest  Built
     pilot-multi:latest  Built
     Network pilot-w9_public  Creating
     Network pilot-w9_public  Created
     Network pilot-w9_private-a  Creating
     Network pilot-w9_private-a  Error
    failed to create network pilot-w9_private-a: Error response from daemon: invalid pool request: Pool overlaps with other one on this address space
```

### `test_net_cold_shoulder_shipped.sh` (exit=1, 7s)

```
[2026-04-23 18:51:07] [0;32m[PASS][0m net=1
[2026-04-23 18:51:10] [1;33m[TEST][0m low-score peer traffic silently dropped
[2026-04-23 18:51:10] [0;31m[FAIL][0m traffic flowed from low-score peer (EXPECTED: cold-shoulder deny)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_cooling_off_shipped.sh` (exit=1, 20s)

```
[2026-04-23 18:51:22] [0;32m[PASS][0m net=1
[2026-04-23 18:51:26] [1;33m[TEST][0m violating peer is in cooldown
[2026-04-23 18:51:29] [0;31m[FAIL][0m retry succeeded inside cooldown window (EXPECTED: deny)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_burnout_shipped.sh` (exit=1, 31s)

```
[2026-04-23 18:51:06] [0;32m[PASS][0m net=1
[2026-04-23 18:51:08] [1;33m[TEST][0m generate burst traffic to trigger burnout cap
[2026-04-23 18:51:32] [1;33m[TEST][0m after burst, score is bounded or peer evicted (burnout cap)
[2026-04-23 18:51:32] [0;31m[FAIL][0m no burnout cap observed: score=->0 listed=1 (EXPECTED: score moved AND bounded, OR peer evicted)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_cross_network_traffic_denied.sh` (exit=1, 21s)

```
[2026-04-23 18:51:43] [1;33m[TEST][0m create strict network X (deny non-members)
[2026-04-23 18:51:48] [0;32m[PASS][0m net=1
[2026-04-23 18:51:48] [1;33m[TEST][0m agent-a joins X; agent-b stays out
[2026-04-23 18:51:54] [0;32m[PASS][0m agent-a is member of X
[2026-04-23 18:51:54] [1;33m[TEST][0m agent-b (non-member of X) dials agent-a — expect deny
[2026-04-23 18:51:55] [0;31m[FAIL][0m cross-network send succeeded despite X's deny rule (EXPECTED: deny)
    resolved "agent-a" → 0:0000.0000.0003
    sent 19 bytes (no response)
Passed: [0;32m2[0m  Failed: [0;31m1[0m
```

### `test_net_data_exchange_policy_shipped.sh` (exit=1, 63s)

```
[2026-04-23 18:51:50] [0;32m[PASS][0m net=1
[2026-04-23 18:51:56] [1;33m[TEST][0m echo (port 7) is always allowed (allow-echo-dial rule)
[2026-04-23 18:52:27] [0;31m[FAIL][0m echo blocked (EXPECTED: port 7 always allowed)
[2026-04-23 18:52:27] [1;33m[TEST][0m port 1001 rejected when neither side has 'service' tag
[2026-04-23 18:52:34] [0;32m[PASS][0m 1001 send refused
[2026-04-23 18:52:34] [1;33m[TEST][0m port 1001 allowed once agent-b takes 'service' tag
[2026-04-23 18:52:40] [0;31m[FAIL][0m 1001 blocked with service tag (EXPECTED: allowed)
    resolved "agent-b" → 0:0000.0000.0002
    error: cannot connect to 0:0000.0000.0002 port 1001
    hint:  check that 0:0000.0000.0002 is reachable: pilotctl ping 0:0000.0000.0002
Passed: [0;32m2[0m  Failed: [0;31m2[0m
```

### `test_net_gift_economy_shipped.sh` (exit=1, 34s)

```
[2026-04-23 18:52:27] [0;32m[PASS][0m net=1
[2026-04-23 18:52:44] [1;33m[TEST][0m both sender and receiver accrue reward
[2026-04-23 18:52:44] [0;31m[FAIL][0m asymmetric rewards missing: A=0 B=0 (EXPECTED: both >0)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_golden_hour_shipped.sh` (exit=1, 39s)

```
[2026-04-23 18:52:31] [0;32m[PASS][0m net=1
[2026-04-23 18:52:36] [1;33m[TEST][0m fresh-join actions accrue bonus
[2026-04-23 18:52:50] [0;31m[FAIL][0m no golden-hour bonus: early=0 late-delta=0 (EXPECTED: early>0 AND early>late-delta)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_gossip_tax_shipped.sh` (exit=1, 56s)

```
[2026-04-23 18:52:40] [0;32m[PASS][0m net=1
[2026-04-23 18:52:46] [1;33m[TEST][0m excessive pubsub publishes drain score
[2026-04-23 18:53:11] [0;31m[FAIL][0m no gossip tax: 0 -> 0 (EXPECTED: SC0>0 AND SC1<SC0 after high emit)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_high_trust_society_shipped.sh` (exit=1, 27s)

```
[2026-04-23 18:53:06] [0;32m[PASS][0m net=1
[2026-04-23 18:53:10] [1;33m[TEST][0m 5 connects from a->b — score should be +5
[2026-04-23 18:53:16] [0;31m[FAIL][0m score=0 (EXPECTED >= 5; score action not applied per connect)
[2026-04-23 18:53:16] [1;33m[TEST][0m cycle tick runs without panic under active policy
[2026-04-23 18:53:17] [0;32m[PASS][0m cycle ok
Passed: [0;32m2[0m  Failed: [0;31m1[0m
```

### `test_net_half_life_shipped.sh` (exit=1, 29s)

```
[2026-04-23 18:53:07] [0;32m[PASS][0m net=1
[2026-04-23 18:53:19] [0;31m[FAIL][0m decay too weak or unseeded: 0 -> 0 (EXPECTED: S0>=4 AND S1<S0 AND S1<=1)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_isolation_policy_scoping.sh` (exit=1, 30s)

```
[2026-04-23 18:53:06] [1;33m[TEST][0m create strict network (X)
[2026-04-23 18:53:10] [0;32m[PASS][0m net X = 1
[2026-04-23 18:53:10] [1;33m[TEST][0m create permissive network (Y)
[2026-04-23 18:53:12] [0;32m[PASS][0m net Y = 2
[2026-04-23 18:53:12] [1;33m[TEST][0m agent-a joins X; agent-b joins Y
[2026-04-23 18:53:17] [0;32m[PASS][0m memberships set
[2026-04-23 18:53:19] [1;33m[TEST][0m agent-b can reach agent-a on base network (Y's allow is permissive)
[2026-04-23 18:53:21] [0;32m[PASS][0m cross-scope base-network ping ok
[2026-04-23 18:53:21] [1;33m[TEST][0m X's deny is scoped to X (agent-a is member of X)
[2026-04-23 18:53:22] [0;32m[PASS][0m X runner has rules active
[2026-04-23 18:53:22] [1;33m[TEST][0m Y's allow is scoped to Y (agent-b is member of Y, not X)
[2026-04-23 18:53:22] [0;32m[PASS][0m Y runner has rules active
[2026-04-23 18:53:23] [1;33m[TEST][0m agent-a has NO runner for Y, agent-b has NO runner for X
[2026-04-23 18:53:24] [0;31m[FAIL][0m cross-scope status succeeded (leak): A->Y=ok  B->X=ok
Passed: [0;32m6[0m  Failed: [0;31m1[0m
```

### `test_net_join_deny_per_network.sh` (exit=1, 14s)

```
[2026-04-23 18:53:25] [0;32m[PASS][0m net=1
[2026-04-23 18:53:25] [1;33m[TEST][0m agent-b attempts to join — expect deny
[2026-04-23 18:53:27] [0;31m[FAIL][0m agent-b joined despite join-deny rule (EXPECTED: rejected)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_karma_ledger_shipped.sh` (exit=1, 20s)

```
[2026-04-23 18:53:31] [0;32m[PASS][0m net=1
[2026-04-23 18:53:34] [1;33m[TEST][0m 3 connects update karma ledger
[2026-04-23 18:53:40] [0;31m[FAIL][0m karma did not change (EXPECTED: monotonic increase)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_meritocracy_rating_shipped.sh` (exit=1, 14s)

```
[2026-04-23 18:53:40] [0;32m[PASS][0m net=1
[2026-04-23 18:53:43] [1;33m[TEST][0m rating surface exposed per peer
[2026-04-23 18:53:43] [0;31m[FAIL][0m no rating surface (EXPECTED: per-peer rating)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_meritocracy_shipped.sh` (exit=1, 15s)

```
[2026-04-23 18:53:39] [0;32m[PASS][0m net=1
[2026-04-23 18:53:42] [1;33m[TEST][0m top-score peer is in rankings and surfaces merit
[2026-04-23 18:53:44] [0;31m[FAIL][0m no ranking surface (EXPECTED: rankings expose merit order)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_lottery_shipped.sh` (exit=1, 19s)

```
[2026-04-23 18:53:36] [0;32m[PASS][0m net=1
[2026-04-23 18:53:39] [1;33m[TEST][0m repeated connects yield non-deterministic pass/fail
[2026-04-23 18:53:45] [0;31m[FAIL][0m deterministic outcome pass=10 deny=0 (EXPECTED: probabilistic)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_ostracism_shipped.sh` (exit=1, 13s)

```
[2026-04-23 18:53:50] [0;32m[PASS][0m net=1
[2026-04-23 18:53:53] [1;33m[TEST][0m below-threshold peer is evicted on cycle
[2026-04-23 18:53:55] [0;31m[FAIL][0m low-score peer present (EXPECTED: ostracized/evicted)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_pay_it_forward_shipped.sh` (exit=1, 15s)

```
[2026-04-23 18:53:54] [0;32m[PASS][0m net=1
[2026-04-23 18:53:57] [1;33m[TEST][0m pubsub relay accrues forwarding reward
[2026-04-23 18:53:59] [0;31m[FAIL][0m no forwarding reward (EXPECTED: score bump on forward)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_rotating_chairs_shipped.sh` (exit=1, 15s)

```
[2026-04-23 18:53:56] [0;32m[PASS][0m net=1
[2026-04-23 18:53:59] [1;33m[TEST][0m rankings reorder across forced cycles
[2026-04-23 18:54:00] [0;31m[FAIL][0m ranking head static (0) across cycles (EXPECTED: rotation)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_small_circle_shipped.sh` (exit=1, 15s)

```
[2026-04-23 18:53:57] [0;32m[PASS][0m net=1
[2026-04-23 18:54:00] [1;33m[TEST][0m max_peers cap enforced (small-circle)
[2026-04-23 18:54:01] [0;31m[FAIL][0m cap=0 (EXPECTED: small positive cap, e.g. 10)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_stable_state_shipped.sh` (exit=1, 14s)

```
[2026-04-23 18:54:05] [0;32m[PASS][0m net=1
[2026-04-23 18:54:08] [1;33m[TEST][0m cycles converge peer count toward target
[2026-04-23 18:54:10] [0;31m[FAIL][0m peer count drifted or empty: 0 -> 0 (EXPECTED: C0>=1 AND |ΔC|<=2)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_tithe_shipped.sh` (exit=1, 18s)

```
[2026-04-23 18:54:05] [0;32m[PASS][0m net=1
[2026-04-23 18:54:08] [1;33m[TEST][0m tithe clips accumulated score on cycle
[2026-04-23 18:54:14] [0;31m[FAIL][0m no tithe: 0 -> 0 (EXPECTED: score decrease)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_two_strikes_shipped.sh` (exit=1, 14s)

```
[2026-04-23 18:54:10] [0;32m[PASS][0m net=1
[2026-04-23 18:54:13] [1;33m[TEST][0m two failed attempts evict peer
[2026-04-23 18:54:16] [0;31m[FAIL][0m peer still present after 2 strikes (EXPECTED: evicted)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_whale_hunt_shipped.sh` (exit=1, 13s)

```
[2026-04-23 18:54:19] [0;32m[PASS][0m net=1
[2026-04-23 18:54:22] [1;33m[TEST][0m high-score peer is flagged / taxed
[2026-04-23 18:54:23] [0;31m[FAIL][0m no whale-score rule visible (EXPECTED: rule keyed on high peer_score)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_polo_scoped_per_network.sh` (exit=1, 41s)

```
create_network_from_file: attempt 1 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 2s
create_network_from_file: attempt 2 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 4s
create_network_from_file: attempt 3 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 6s
create_network_from_file: attempt 4 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 8s
create_network_from_file: attempt 5 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 10s
create_network_from_file: create failed after 5 attempts: {"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}
[2026-04-23 18:54:26] [0;31m[FAIL][0m create X
```

### `test_net_trust_scoped_per_network.sh` (exit=1, 39s)

```
create_network_from_file: attempt 1 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 2s
create_network_from_file: attempt 2 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 4s
create_network_from_file: attempt 3 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 6s
create_network_from_file: attempt 4 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 8s
create_network_from_file: attempt 5 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 10s
create_network_from_file: create failed after 5 attempts: {"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}
[2026-04-23 18:54:40] [0;31m[FAIL][0m create X
```

### `test_policy_cycle_fill_trust.sh` (exit=1, 30s)

```
==========================================
Policy: cycle × fill_trust
==========================================
[2026-04-23 18:55:09] [0;32m[PASS][0m stack up
[2026-04-23 18:55:09] [1;33m[TEST][0m Apply fill_trust policy on agent-b
load_policy: network_id=1 policy=/tests/fixtures/policies/short_cycle_fill_trust.json (on agent-b)
[2026-04-23 18:55:15] [0;32m[PASS][0m policy loaded (net=1)
[2026-04-23 18:55:15] [1;33m[TEST][0m confirm agent-b starts with 0 trust links
[2026-04-23 18:55:15] [0;32m[PASS][0m trust set empty
[2026-04-23 18:55:15] [1;33m[TEST][0m force cycle
[2026-04-23 18:55:19] [0;32m[PASS][0m cycle forced
[2026-04-23 18:55:19] [1;33m[TEST][0m agent-b logged 'sent trust requests'
[2026-04-23 18:55:19] [0;32m[PASS][0m fill_trust fired
[2026-04-23 18:55:19] [1;33m[TEST][0m agent-a has a pending handshake from agent-b
[2026-04-23 18:55:22] [0;31m[FAIL][0m agent-a pending=0 (want >=1)
Passed: \033[0;32m5\033[0m  Failed: \033[0;31m1\033[0m
```

### `test_policy_cycle_evict.sh` (exit=1, 36s)

```
==========================================
Policy: cycle × evict
==========================================
[2026-04-23 18:55:09] [0;32m[PASS][0m stack up
[2026-04-23 18:55:09] [1;33m[TEST][0m Apply tag-then-evict policy on agent-b
load_policy: network_id=1 policy=/tests/fixtures/policies/short_cycle_evict.json (on agent-b)
[2026-04-23 18:55:14] [0;32m[PASS][0m policy loaded (net=1)
[2026-04-23 18:55:15] [1;33m[TEST][0m bootstrap peer set via cycle
[2026-04-23 18:55:16] [1;33m[TEST][0m connect agent-a → agent-b to trigger 'stale' tag
[2026-04-23 18:55:19] [1;33m[TEST][0m agent-a has tag 'stale' after connect
[2026-04-23 18:55:20] [0;32m[PASS][0m tags=["stale"]
[2026-04-23 18:55:20] [1;33m[TEST][0m force cycle -> evict stale peers
[2026-04-23 18:55:25] [0;31m[FAIL][0m peer_count did not shrink (1 -> 1)
[2026-04-23 18:55:25] [1;33m[TEST][0m agent-b logged 'policy: evicted peers'
[2026-04-23 18:55:25] [0;32m[PASS][0m evict fired
Passed: \033[0;32m4\033[0m  Failed: \033[0;31m1\033[0m
```

### `test_policy_connect_deny.sh` (exit=1, 50s)

```
==========================================
Policy: connect × deny
==========================================
[2026-04-23 18:54:41] [1;33m[TEST][0m Starting stack
[2026-04-23 18:54:47] [0;32m[PASS][0m stack up
[2026-04-23 18:54:47] [1;33m[TEST][0m Apply deny-all connect policy on agent-b
load_policy: network_id=1 policy=/tests/fixtures/policies/deny_all_connect.json (on agent-b)
[2026-04-23 18:54:54] [0;32m[PASS][0m deny-all policy loaded (net=1)
[2026-04-23 18:54:57] [1;33m[TEST][0m echo under deny-all must fail (timeout or refusal)
[2026-04-23 18:55:06] [0;32m[PASS][0m echo refused/timed out under deny policy (rc=124)
[2026-04-23 18:55:06] [1;33m[TEST][0m agent-b logs syn.port_rejected OR port_rejected OR policy deny
assert_policy_event: agent=agent-b event=connect_deny pattern=SYN rejected: not allowed\|syn\.port_rejected\|port_rejected count=0 want>=1
[2026-04-23 18:55:09] [0;31m[FAIL][0m no deny events in agent-b logs (expected under deny-all connect)
[2026-04-23 18:55:09] [1;33m[TEST][0m send-message under deny-all must fail
[2026-04-23 18:55:17] [0;32m[PASS][0m send-message refused/timed out (rc=124)
[2026-04-23 18:55:18] [1;33m[TEST][0m send-file under deny-all must fail
[2026-04-23 18:55:29] [0;32m[PASS][0m send-file refused/timed out (rc=124)

==========================================
Passed: \033[0;32m5\033[0m  Failed: \033[0;31m1\033[0m
==========================================
```

### `test_partition_heal.sh` (exit=1, 82s)

```
==========================================
Partition then heal: queued ops complete
==========================================
[2026-04-23 18:54:30] [0;32m[PASS][0m both agents registered
[2026-04-23 18:54:32] [0;32m[PASS][0m IPs resolved a=172.29.18.20 b=172.29.18.21
[2026-04-23 18:54:32] [1;33m[TEST][0m pre-submit 3 tasks BEFORE partition (worker paused)
[2026-04-23 18:54:34] [0;32m[PASS][0m pre-submitted 3 task ids
[2026-04-23 18:54:34] [1;33m[TEST][0m install partition a<->b
[2026-04-23 18:54:36] [0;32m[PASS][0m partition effective
[2026-04-23 18:54:37] [1;33m[TEST][0m none of the submitted tasks already completed
[2026-04-23 18:54:37] [0;32m[PASS][0m 0/3 completed during split (correct)
[2026-04-23 18:54:37] [1;33m[TEST][0m heal partition
[2026-04-23 18:55:35] [0;31m[FAIL][0m heal did not restore path
```

### `test_policy_cycle_webhook.sh` (exit=1, 27s)

```
==========================================
Policy: cycle × webhook
==========================================
[2026-04-23 18:55:29] [0;32m[PASS][0m stack up
[2026-04-23 18:55:29] [1;33m[TEST][0m start a local webhook sink inside agent-b container
[2026-04-23 18:55:31] [0;32m[PASS][0m sink listening on 127.0.0.1:18080
[2026-04-23 18:55:31] [1;33m[TEST][0m restart agent-b daemon with -webhook flag
[2026-04-23 18:55:32] [0;32m[PASS][0m agent-b relaunched with webhook
[2026-04-23 18:55:37] [1;33m[TEST][0m Apply webhook-on-cycle policy
load_policy: cannot resolve agent-b node_id
[2026-04-23 18:55:40] [0;31m[FAIL][0m load
```

### `test_policy_datagram_deny.sh` (exit=1, 25s)

```
==========================================
Policy: datagram × deny
==========================================
[2026-04-23 18:55:32] [0;32m[PASS][0m stack up
[2026-04-23 18:55:32] [1;33m[TEST][0m Apply deny-all datagram policy on agent-b
load_policy: network_id=1 policy=/tests/fixtures/policies/deny_all_datagram.json (on agent-b)
[2026-04-23 18:55:38] [0;32m[PASS][0m policy loaded (net=1)
[2026-04-23 18:55:38] [1;33m[TEST][0m send datagram under deny — expect failure / timeout
[2026-04-23 18:55:44] [0;32m[PASS][0m send rejected/timed out (rc=1)
[2026-04-23 18:55:44] [1;33m[TEST][0m agent-b logs datagram rejection
assert_policy_event: agent=agent-b event=datagram_deny pattern=datagram rejected: not allowed\|datagram\.port_rejected\|datagram.*not allowed count=0 want>=1
[2026-04-23 18:55:47] [0;31m[FAIL][0m no datagram_deny event observed
Passed: \033[0;32m3\033[0m  Failed: \033[0;31m1\033[0m
```

### `test_policy_join_allow.sh` (exit=1, 23s)

```
==========================================
Policy: join × allow (schema-level)
==========================================
[2026-04-23 18:55:35] [0;32m[PASS][0m stack up
[2026-04-23 18:55:35] [1;33m[TEST][0m Apply allow-join policy on agent-b
load_policy: network_id=1 policy=/tests/fixtures/policies/join_allow.json (on agent-b)
[2026-04-23 18:55:45] [0;32m[PASS][0m policy loaded (net=1)
[2026-04-23 18:55:45] [1;33m[TEST][0m agent-a joining managed network succeeds
[2026-04-23 18:55:46] [0;32m[PASS][0m join succeeded
[2026-04-23 18:55:46] [1;33m[TEST][0m agent-a member list contains agent-a and agent-b
[2026-04-23 18:55:49] [0;31m[FAIL][0m expected >=2 members, got 0
[2026-04-23 18:55:49] [1;33m[TEST][0m FINDING: join event firing not wired in daemon
    (documented in test comment header)
Passed: \033[0;32m3\033[0m  Failed: \033[0;31m1\033[0m
```

### `test_policy_datagram_score.sh` (exit=1, 55s)

```
==========================================
Policy: datagram × score
==========================================
[2026-04-23 18:55:33] [0;32m[PASS][0m stack up
[2026-04-23 18:55:33] [1;33m[TEST][0m Apply score-on-datagram policy on agent-b
load_policy: network_id=1 policy=/tests/fixtures/policies/score_on_datagram.json (on agent-b)
[2026-04-23 18:55:39] [0;32m[PASS][0m policy loaded (net=1)
[2026-04-23 18:55:40] [1;33m[TEST][0m baseline score (may be empty for fresh peer)
[2026-04-23 18:55:43] [0;32m[PASS][0m baseline score=0
[2026-04-23 18:55:43] [1;33m[TEST][0m drive 5 datagrams from agent-a
[2026-04-23 18:56:15] [0;32m[PASS][0m sent
[2026-04-23 18:56:18] [1;33m[TEST][0m peer score increased
[2026-04-23 18:56:18] [0;31m[FAIL][0m score not increased (base=0 new=0)
Passed: \033[0;32m4\033[0m  Failed: \033[0;31m1\033[0m
```

### `test_sec_ipc_exhaustion.sh` (exit=1, 11s)

```
[2026-04-23 18:56:59] [1;33m[TEST][0m fresh stack
[2026-04-23 18:57:04] [1;33m[TEST][0m attempt 10k concurrent IPC connections
successfully opened IPC conns: 5121
[2026-04-23 18:57:06] [1;33m[TEST][0m daemon still responds to pilotctl info from a NEW connection
[2026-04-23 18:57:08] [0;32m[PASS][0m daemon responsive after IPC exhaustion attempt
[2026-04-23 18:57:08] [1;33m[TEST][0m per-client cap enforced (OPEN should be well below 10000)
[2026-04-23 18:57:08] [0;31m[FAIL][0m no IPC cap detected (5121 conns opened) — see P2-002
[2026-04-23 18:57:08] [1;33m[TEST][0m no agent-a panic on accept() exhaustion
[2026-04-23 18:57:08] [0;32m[PASS][0m no panic/EMFILE in logs

Passed: 2  Failed: 1
```

### `test_receiver_sigkill_midfile.sh` (exit=1, 72s)

```
==========================================
SIGKILL agent-b mid-send-file
==========================================
[2026-04-23 18:56:37] [0;32m[PASS][0m both agents registered
[2026-04-23 18:56:39] [1;33m[TEST][0m prepare 4 MiB payload on agent-a
[2026-04-23 18:56:41] [0;32m[PASS][0m payload ready (abd96d78fb3d1294d720881944bd6e4cf66026efa3c115b89e4e0e0f29d391b7)
[2026-04-23 18:56:41] [1;33m[TEST][0m start send-file in background, then SIGKILL agent-b
[2026-04-23 18:56:48] [0;32m[PASS][0m agent-b SIGKILL'd mid-transfer
[2026-04-23 18:56:48] [1;33m[TEST][0m send-file on agent-a returns (not hung)
[2026-04-23 18:56:51] [0;32m[PASS][0m send-file returned (rc=1)
[2026-04-23 18:56:51] [1;33m[TEST][0m sender did NOT claim success after receiver died
[2026-04-23 18:56:51] [0;32m[PASS][0m no false-success ack
[2026-04-23 18:56:51] [1;33m[TEST][0m no panic/fatal on agent-a
[2026-04-23 18:56:51] [0;32m[PASS][0m clean logs on a
[2026-04-23 18:56:51] [1;33m[TEST][0m restart agent-b
[2026-04-23 18:56:53] [0;32m[PASS][0m agent-b re-registered
[2026-04-23 18:56:53] [1;33m[TEST][0m no silent-corrupt partial file on agent-b
[2026-04-23 18:56:54] [0;32m[PASS][0m no partial file left (acceptable)
[2026-04-23 18:56:54] [1;33m[TEST][0m fresh send-file post-restart completes with sha match
[2026-04-23 18:57:33] [0;31m[FAIL][0m post-restart send mismatch src=736b1c4e38e5... dst=...

Passed: 8  Failed: 1
```

### `test_ping_ghost_peer.sh` (exit=1, 186s)

```
==========================================
Ping / send / submit to a ghost peer
==========================================
[2026-04-23 18:54:35] [1;33m[TEST][0m fresh stack
[2026-04-23 18:54:40] [0;32m[PASS][0m both agents registered
[2026-04-23 18:54:40] [1;33m[TEST][0m warm-up ping a->b so agent-a has cached crypto+endpoint
[2026-04-23 18:54:42] [0;32m[PASS][0m tunnel warm
[2026-04-23 18:54:42] [1;33m[TEST][0m SIGKILL agent-b (no graceful unregister)
[2026-04-23 18:54:44] [0;32m[PASS][0m agent-b is dead
[2026-04-23 18:54:44] [1;33m[TEST][0m ping a->b (ghost) fails within --timeout 4s
[2026-04-23 18:54:49] [0;32m[PASS][0m ping failed in 5s (rc=1)
[2026-04-23 18:54:49] [1;33m[TEST][0m send-message a->b (ghost) fails with clear error
[2026-04-23 18:55:00] [0;32m[PASS][0m send-message refused (rc=124)
[2026-04-23 18:55:00] [1;33m[TEST][0m task submit a->b (ghost) — must not report completion
[2026-04-23 18:55:16] [0;32m[PASS][0m submit to ghost peer refused at the front door
[2026-04-23 18:55:16] [1;33m[TEST][0m agent-a has no panic/fatal after ghost attempts
[2026-04-23 18:55:16] [0;32m[PASS][0m agent-a log clean
[2026-04-23 18:55:16] [1;33m[TEST][0m restart agent-b; ping a->b works again
[2026-04-23 18:57:41] [0;31m[FAIL][0m a's state poisoned — ping still fails after b came back

==========================================
Ghost-peer summary
==========================================
Passed: [0;32m7[0m
Failed: [0;31m1[0m
==========================================
```

### `test_ring4_routing.sh` (exit=1, 63s)

```
    01:56:57.567564417 hop host=agent-b path=start,agent-b ttl=2
    resolved "agent-c" → 0:0000.0000.0004
    {
      "ack": "ACK JSON 56 bytes",
      "bytes": 56,
      "target": "0:0000.0000.0004",
      "type": "json"
    }
  === c ring.log ===
    01:56:58.080602167 hop host=agent-c path=start,agent-b,agent-c ttl=1
    resolved "agent-d" → 0:0000.0000.0005
    {
      "ack": "ACK JSON 64 bytes",
      "bytes": 64,
      "target": "0:0000.0000.0005",
      "type": "json"
    }
  === d ring.log ===
    01:56:58.565478792 hop host=agent-d path=start,agent-b,agent-c,agent-d ttl=0
[2026-04-23 18:57:40] [1;33m[TEST][0m final path shows all four hops in order
[2026-04-23 18:57:40] [0;31m[FAIL][0m path wrong: got '' want 'start,agent-b,agent-c,agent-d,agent-a'
[2026-04-23 18:57:40] [1;33m[TEST][0m no panics/fatals
[2026-04-23 18:57:40] [0;32m[PASS][0m clean logs

==========================================
Ring-4 routing summary
==========================================
Passed: [0;32m4[0m
Failed: [0;31m2[0m
==========================================
```

### `test_resilience.sh` (exit=1, 1239s)

```
==========================================
Resilience / restart / concurrency tests
==========================================
[2026-04-23 18:37:18] [1;33m[TEST][0m 50 parallel echo roundtrips from agent-a to agent-b
[2026-04-23 18:37:24] [0;32m[PASS][0m 50/50 echo roundtrips ok
[2026-04-23 18:37:24] [1;33m[TEST][0m restart agent-b and confirm it re-registers
[2026-04-23 18:37:32] [0;32m[PASS][0m agent-b re-registered (was 1, now 1)
[2026-04-23 18:37:32] [1;33m[TEST][0m echo to agent-b recovers after restart (poll ≤4min)
[2026-04-23 18:57:27] [0;31m[FAIL][0m post-restart echo never recovered in 4 minutes
[2026-04-23 18:57:27] [1;33m[TEST][0m restart rendezvous and confirm agents reconnect (≤4min)
[2026-04-23 18:57:29] [0;32m[PASS][0m both agents reconnected after rendezvous restart (total_nodes=3, ~1×5s)
[2026-04-23 18:57:29] [1;33m[TEST][0m agent-a process survived 60s+ of activity
[2026-04-23 18:57:34] [0;32m[PASS][0m agent-a pid 1 alive, RSS 14844 KB
[2026-04-23 18:57:34] [1;33m[TEST][0m pulse endpoint shows non-zero total_requests
[2026-04-23 18:57:36] [0;32m[PASS][0m pulse total_requests=1588 samples=7
[2026-04-23 18:57:36] [1;33m[TEST][0m concurrent send-message agent-a→b and agent-b→a
[2026-04-23 18:57:53] [0;32m[PASS][0m concurrent bidirectional send-message completed
[2026-04-23 18:57:53] [1;33m[TEST][0m agent logs free of panic/fatal
[2026-04-23 18:57:54] [0;32m[PASS][0m no panic/fatal/race in recent logs

==========================================
Resilience Test Summary
==========================================
Passed: [0;32m7[0m
Failed: [0;31m1[0m
==========================================
```

### `test_sec_trust_grant_forgery.sh` (exit=1, 31s)

```
[2026-04-23 18:57:26] [1;33m[TEST][0m fresh stack
[2026-04-23 18:57:37] [1;33m[TEST][0m stand up a fresh sybil daemon identity inside agent-a
forger node_id: 
[2026-04-23 18:57:42] [0;31m[FAIL][0m forger daemon didn't register
time=2026-04-24T01:57:38.385Z level=INFO msg="daemon start: email address required: use -email you@example.com"
[2026-04-23 18:57:43] [1;33m[TEST][0m forger attempts trust grant to agent-b (unrequested)
[2026-04-23 18:57:47] [1;33m[TEST][0m agent-b does NOT auto-trust the forger
[2026-04-23 18:57:49] [0;32m[PASS][0m forger is NOT in trusted list
[2026-04-23 18:57:49] [1;33m[TEST][0m forger with a tampered identity file cannot impersonate
[2026-04-23 18:57:54] [1;33m[TEST][0m agent-b logs show signature verification guard
[2026-04-23 18:57:54] [1;33m[TEST][0m no explicit verification-failure log seen — trust path handled rejection instead
[2026-04-23 18:57:54] [1;33m[TEST][0m agent-b pending handshake count bounded
[2026-04-23 18:57:55] [0;32m[PASS][0m pending queue bounded (0)

Passed: 2  Failed: 1
```

### `test_sender_clean_restart_midflight.sh` (exit=1, 51s)

```
==========================================
Clean restart of agent-a mid-flight
==========================================
[2026-04-23 18:57:57] [0;32m[PASS][0m both agents registered
[2026-04-23 18:57:59] [1;33m[TEST][0m submit 3 tasks then restart agent-a cleanly
[2026-04-23 18:58:03] [0;32m[PASS][0m agent-a re-registered post-restart
[2026-04-23 18:58:03] [1;33m[TEST][0m agent-a task list --type submitted still works post-restart
[2026-04-23 18:58:04] [0;32m[PASS][0m task list ok
[2026-04-23 18:58:04] [1;33m[TEST][0m fresh task submit post-restart completes
[2026-04-23 18:58:24] [0;31m[FAIL][0m fresh task stuck post-restart (status=)
[2026-04-23 18:58:24] [1;33m[TEST][0m fresh send-file post-restart
[2026-04-23 18:58:36] [0;32m[PASS][0m file sha match post-restart
[2026-04-23 18:58:36] [1;33m[TEST][0m no panic/fatal
[2026-04-23 18:58:36] [0;32m[PASS][0m clean logs

Passed: 5  Failed: 1
```

### `test_splitbrain_divergence.sh` (exit=1, 27s)

```
==========================================
Split-brain divergence (2 rendezvous)
==========================================
[2026-04-23 18:58:32] [1;33m[TEST][0m Starting splitbrain stack
[2026-04-23 18:58:48] [1;33m[TEST][0m rendezvous-1 sees 2 agents
[2026-04-23 18:58:49] [0;31m[FAIL][0m rendezvous-1 sees 3 nodes — expected 2 (partition leaked)
[2026-04-23 18:58:49] [1;33m[TEST][0m rendezvous-2 sees 2 agents
[2026-04-23 18:58:51] [0;32m[PASS][0m rendezvous-2 has exactly 2 nodes (agent-c,d)
[2026-04-23 18:58:51] [1;33m[TEST][0m agent-a cannot lookup agent-c (cross-partition)
[2026-04-23 18:58:54] [0;32m[PASS][0m agent-a cannot resolve agent-c (partition holds)
[2026-04-23 18:58:54] [1;33m[TEST][0m agent-c cannot lookup agent-a (cross-partition)
[2026-04-23 18:58:55] [0;32m[PASS][0m agent-c cannot resolve agent-a (partition holds)
[2026-04-23 18:58:55] [1;33m[TEST][0m agent-a can lookup agent-b (same side)
[2026-04-23 18:58:55] [0;32m[PASS][0m same-side lookup works (agent-b=0:0000.0000.0002)
[2026-04-23 18:58:55] [1;33m[TEST][0m agent-c can lookup agent-d (same side)
[2026-04-23 18:58:56] [0;32m[PASS][0m same-side lookup works (agent-d=0:0000.0000.0001)
[2026-04-23 18:58:56] [1;33m[TEST][0m no panic/fatal in any daemon log
[2026-04-23 18:58:57] [0;32m[PASS][0m clean logs

==========================================
Split-brain divergence summary
==========================================
Passed: [0;32m6[0m
Failed: [0;31m1[0m
==========================================
```

### `test_register_identity_new_endpoint.sh` (exit=1, 162s)

```
==========================================
Identity re-register with new endpoint
==========================================
[2026-04-23 18:56:45] [0;32m[PASS][0m agents up
[2026-04-23 18:56:46] [0;32m[PASS][0m initial endpoint: 172.29.11.21:4000
[2026-04-23 18:56:46] [1;33m[TEST][0m stop agent-b, bring it back with a different listen port
Error response from daemon: container 8621cc9c4e349350ff110fb6e771c3a5772739464d0dd01bcffc299efd3bc32f is not running
[2026-04-23 18:58:56] [0;32m[PASS][0m new endpoint seen in registry: 172.29.11.21:4000
[2026-04-23 18:58:56] [1;33m[TEST][0m registry entry superseded: new endpoint reflects :4001
[2026-04-23 18:58:56] [0;31m[FAIL][0m endpoint still 172.29.11.21:4000 (expected suffix :4001, was 172.29.11.21:4000)
[2026-04-23 18:58:56] [1;33m[TEST][0m node_id remains the same (same identity)
[2026-04-23 18:58:57] [0;31m[FAIL][0m node_id changed: 2 -> 
[2026-04-23 18:58:57] [1;33m[TEST][0m only one registry entry for this identity (no stale duplicate)
[2026-04-23 18:58:57] [0;31m[FAIL][0m registry has 3 nodes — stale duplicate suspected
[2026-04-23 18:58:57] [1;33m[TEST][0m agent-a can still reach agent-b at the new endpoint
[2026-04-23 18:59:10] [0;31m[FAIL][0m ping failed after endpoint change — a may be caching old endpoint
[2026-04-23 18:59:10] [1;33m[TEST][0m no panic/fatal
[2026-04-23 18:59:11] [0;32m[PASS][0m clean logs

Passed: 4  Failed: 4
```

### `test_task_executor.sh` (exit=1, 23s)

```
[2026-04-23 18:59:38] [1;33m[TEST][0m start auto-accept worker on agent-b
[2026-04-23 18:59:39] [0;32m[PASS][0m worker started on agent-b
[2026-04-23 18:59:39] [1;33m[TEST][0m agent-a submits T1 (polo should allow)
[2026-04-23 18:59:40] [0;32m[PASS][0m T1 submitted: 0865bfa4-5c9d-d187-b6b8-322913776936
[2026-04-23 18:59:41] [1;33m[TEST][0m T1 reaches completed/succeeded on submitter
[2026-04-23 18:59:41] [0;32m[PASS][0m submitter sees T1 status=SUCCEEDED
[2026-04-23 18:59:41] [1;33m[TEST][0m pilotctl task result returns correlated payload
[2026-04-23 18:59:41] [0;32m[PASS][0m T1 result correlates: "done: compute-fibonacci"
[2026-04-23 18:59:41] [1;33m[TEST][0m polo gate rejects second a -> b submit with too-low score
[2026-04-23 18:59:42] [0;31m[FAIL][0m polo gate did not block (accepted=false message=Task rejected by polo gate: submitter polo below receiver polo)
[2026-04-23 18:59:42] [1;33m[TEST][0m enable-tasks on agent-a for reverse flow
[2026-04-23 18:59:44] [1;33m[TEST][0m agent-b submits B1 to agent-a (should be allowed)
[2026-04-23 18:59:45] [0;32m[PASS][0m B1 submitted: fe00ec74-598c-3f30-fc86-4de6ff9f7458
[2026-04-23 18:59:47] [1;33m[TEST][0m B1 completes on agent-b
[2026-04-23 18:59:47] [0;32m[PASS][0m agent-b sees B1 status=SUCCEEDED
[2026-04-23 18:59:47] [1;33m[TEST][0m balanced exchange restores polo, a can submit again
[2026-04-23 18:59:48] [0;32m[PASS][0m post-balance submit accepted: c091fbb6-aff7-a8e0-1850-3fcff9b2288c
[2026-04-23 18:59:48] [1;33m[TEST][0m post-balance task result correlates
[2026-04-23 18:59:49] [0;32m[PASS][0m post-balance result correlates
[2026-04-23 18:59:49] [1;33m[TEST][0m pilotctl task result on missing id returns clean error
[2026-04-23 18:59:50] [0;32m[PASS][0m missing-id handled cleanly
[2026-04-23 18:59:50] [1;33m[TEST][0m no panics/fatals in daemon logs
[2026-04-23 18:59:51] [0;32m[PASS][0m clean logs

==========================================
Task-executor test summary
==========================================
Passed: [0;32m12[0m
Failed: [0;31m1[0m
==========================================
```

### `test_tasks_and_edge.sh` (exit=1, 41s)

```
[2026-04-23 19:00:40] [0;32m[PASS][0m task queue ok
[2026-04-23 19:00:40] [1;33m[TEST][0m send-message type=json
[2026-04-23 19:00:41] [0;32m[PASS][0m send-message JSON ack ok
[2026-04-23 19:00:41] [1;33m[TEST][0m send-message type=binary
[2026-04-23 19:00:42] [0;32m[PASS][0m send-message binary ack ok
[2026-04-23 19:00:42] [1;33m[TEST][0m send-file and verify byte count
[2026-04-23 19:00:46] [0;32m[PASS][0m send-file 10240 bytes acked (10240)
[2026-04-23 19:00:46] [1;33m[TEST][0m inbox has at least 2 message entries (JSON + binary text)
[2026-04-23 19:00:47] [0;32m[PASS][0m inbox has 2 entries
[2026-04-23 19:00:47] [1;33m[TEST][0m received/ has the binary file delivered by send-file
[2026-04-23 19:00:47] [0;32m[PASS][0m received/ has 1 file(s)
[2026-04-23 19:00:47] [1;33m[TEST][0m inbox --clear empties the inbox
[2026-04-23 19:00:49] [0;32m[PASS][0m inbox cleared (was 2 now 0)
[2026-04-23 19:00:49] [1;33m[TEST][0m ping unknown hostname returns clear error
[2026-04-23 19:00:49] [0;32m[PASS][0m unknown hostname rejected cleanly
[2026-04-23 19:00:49] [1;33m[TEST][0m send missing --data flag returns invalid_argument
[2026-04-23 19:00:50] [0;32m[PASS][0m missing --data rejected with invalid_argument
[2026-04-23 19:00:50] [1;33m[TEST][0m set-hostname with bad characters rejected
[2026-04-23 19:00:51] [0;32m[PASS][0m invalid hostname rejected (status=error)
[2026-04-23 19:00:51] [1;33m[TEST][0m lookup of nonexistent node_id returns error
[2026-04-23 19:00:52] [0;32m[PASS][0m lookup of ghost node fails cleanly
[2026-04-23 19:00:52] [1;33m[TEST][0m pilotctl version
[2026-04-23 19:00:53] [0;32m[PASS][0m version: dev

==========================================
Tasks/Edge Test Summary
==========================================
Passed: [0;32m18[0m
Failed: [0;31m1[0m
==========================================
```

### `test_webhook_agent_registered.sh` (exit=1, 50s)

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
[2026-04-23 19:01:15] [1;33m[TEST][0m at least 2 registration webhooks after 2 agent restarts (got delta=0)
[2026-04-23 19:01:15] [0;31m[FAIL][0m expected delta>=2 got 0
[2026-04-23 19:01:15] [1;33m[TEST][0m canonical 'agent.registered' event name
service "webhook-sink" is not running
test_webhook_agent_registered.sh: line 72: [: : integer expression expected
[2026-04-23 19:01:15] [0;31m[FAIL][0m agent.registered NOT wired — daemon emits 'node.registered'/'node.reregistered' instead
Passed: 0  Failed: 2
```

### `test_webhook_file_delivered.sh` (exit=1, 101s)

```
[2026-04-23 19:00:38] [1;33m[TEST][0m fresh webhooks stack
[2026-04-23 19:02:18] [0;31m[FAIL][0m agents did not register
```

### `test_webhook_exactly_once_on_restart.sh` (exit=1, 104s)

```
[2026-04-23 19:02:19] [0;31m[FAIL][0m agents did not register
```

### `test_webhook_message_received.sh` (exit=1, 101s)

```
[2026-04-23 19:02:20] [0;31m[FAIL][0m agents did not register
```

### `test_webhook_pubsub_published.sh` (exit=1, 97s)

```
[2026-04-23 19:02:29] [0;31m[FAIL][0m agents did not register
```

### `test_webhook_task_completed.sh` (exit=1, 96s)

```
[2026-04-23 19:02:29] [0;31m[FAIL][0m agents did not register
```

### `test_webhook_task_submitted.sh` (exit=1, 96s)

```
[2026-04-23 19:02:32] [0;31m[FAIL][0m agents did not register
```

### `test_webhook_trust_changed.sh` (exit=1, 91s)

```
[2026-04-23 19:02:33] [0;31m[FAIL][0m agents did not register
```

### `test_webhook_tunnel_established.sh` (exit=1, 92s)

```
[2026-04-23 19:02:39] [0;31m[FAIL][0m agents did not register
```

