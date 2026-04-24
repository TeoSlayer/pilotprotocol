# Integration test run summary

- Run duration: 1575s
- Workers: 10
- Tests: 231 (pass=159, fail=72)
- Serial sum: 13214s (speedup = 8.39x)
- Utilization: w0=98.0% w1=85.8% w2=87.4% w3=77.3% w4=85.6% w5=78.2% w6=82.3% w7=77.5% w8=84.8% w9=82.2% 

| Status | Test | Duration | Exit |
|--------|------|----------|------|
| FAIL | `test_resilience.sh` | 1232s | 1 |
| FAIL | `test_dur_steady_10min.sh` | 614s | 1 |
| FAIL | `test_dur_steady_compressed_24h.sh` | 310s | 1 |
| FAIL | `test_chaos_loss30_all_ops.sh` | 210s | 1 |
| FAIL | `test_sender_clean_restart_midflight.sh` | 187s | 1 |
| FAIL | `test_ping_ghost_peer.sh` | 180s | 1 |
| FAIL | `test_chaos_delay200_all_ops.sh` | 171s | 1 |
| FAIL | `test_register_identity_new_endpoint.sh` | 156s | 1 |
| FAIL | `test_force_relay_task.sh` | 145s | 1 |
| FAIL | `test_splitbrain_divergence.sh` | 143s | 1 |
| FAIL | `test_splitbrain_heal.sh` | 130s | 1 |
| FAIL | `test_ring4_routing.sh` | 125s | 1 |
| FAIL | `test_rendezvous_restart_midflight.sh` | 124s | 1 |
| FAIL | `test_force_relay_pubsub.sh` | 116s | 1 |
| FAIL | `test_fanin_3agents_tasks.sh` | 103s | 1 |
| FAIL | `test_midrekey_task_results.sh` | 96s | 1 |
| FAIL | `test_beacon_restart_midflight.sh` | 89s | 1 |
| FAIL | `test_nat_asymmetric_routing.sh` | 88s | 1 |
| FAIL | `test_gateway_http_message.sh` | 84s | 1 |
| FAIL | `test_net_mutual_admiration_shipped.sh` | 77s | 1 |
| FAIL | `test_partition_heal.sh` | 73s | 1 |
| FAIL | `test_dur_shortcycle_policy_1m.sh` | 69s | 1 |
| FAIL | `test_task_sequential_burst.sh` | 68s | 1 |
| FAIL | `test_receiver_sigkill_midfile.sh` | 66s | 1 |
| FAIL | `test_net_data_exchange_policy_shipped.sh` | 56s | 1 |
| FAIL | `test_chaos_packet_loss.sh` | 52s | 1 |
| FAIL | `test_net_polo_scoped_per_network.sh` | 52s | 1 |
| FAIL | `test_net_trust_scoped_per_network.sh` | 51s | 1 |
| FAIL | `test_sender_sigkill_midfile.sh` | 51s | 1 |
| FAIL | `test_policy_connect_deny.sh` | 49s | 1 |
| FAIL | `test_webhook_exactly_once_on_restart.sh` | 48s | 1 |
| FAIL | `test_webhook_agent_registered.sh` | 47s | 1 |
| FAIL | `test_webhook_message_received.sh` | 46s | 1 |
| FAIL | `test_webhook_polo_updated.sh` | 46s | 1 |
| FAIL | `test_policy_datagram_score.sh` | 45s | 1 |
| FAIL | `test_webhook_task_completed.sh` | 44s | 1 |
| FAIL | `test_webhook_pubsub_published.sh` | 43s | 1 |
| FAIL | `test_webhook_tunnel_established.sh` | 38s | 1 |
| FAIL | `test_net_tithe_shipped.sh` | 37s | 1 |
| FAIL | `test_task_executor.sh` | 36s | 1 |
| FAIL | `test_webhook_file_delivered.sh` | 36s | 1 |
| FAIL | `test_net_burnout_shipped.sh` | 35s | 1 |
| FAIL | `test_net_stable_state_shipped.sh` | 35s | 1 |
| FAIL | `test_tasks_and_edge.sh` | 35s | 1 |
| FAIL | `test_gateway_trust_grant.sh` | 30s | 1 |
| FAIL | `test_net_gossip_tax_shipped.sh` | 28s | 1 |
| FAIL | `test_net_isolation_policy_scoping.sh` | 27s | 1 |
| FAIL | `test_net_lottery_shipped.sh` | 27s | 1 |
| FAIL | `test_net_karma_ledger_shipped.sh` | 25s | 1 |
| FAIL | `test_net_two_strikes_shipped.sh` | 25s | 1 |
| FAIL | `test_net_cooling_off_shipped.sh` | 23s | 1 |
| FAIL | `test_net_high_trust_society_shipped.sh` | 23s | 1 |
| FAIL | `test_net_half_life_shipped.sh` | 22s | 1 |
| FAIL | `test_net_ostracism_shipped.sh` | 22s | 1 |
| FAIL | `test_net_rotating_chairs_shipped.sh` | 21s | 1 |
| FAIL | `test_policy_cycle_fill_trust.sh` | 21s | 1 |
| FAIL | `test_sec_trust_grant_forgery.sh` | 21s | 1 |
| FAIL | `test_policy_cycle_webhook.sh` | 20s | 1 |
| FAIL | `test_policy_datagram_deny.sh` | 20s | 1 |
| FAIL | `test_net_anti_camping_shipped.sh` | 19s | 1 |
| FAIL | `test_net_cross_network_traffic_denied.sh` | 19s | 1 |
| FAIL | `test_net_meritocracy_shipped.sh` | 19s | 1 |
| FAIL | `test_net_pay_it_forward_shipped.sh` | 19s | 1 |
| FAIL | `test_net_small_circle_shipped.sh` | 19s | 1 |
| FAIL | `test_net_cold_shoulder_shipped.sh` | 18s | 1 |
| FAIL | `test_net_golden_hour_shipped.sh` | 18s | 1 |
| FAIL | `test_net_join_deny_per_network.sh` | 17s | 1 |
| FAIL | `test_net_aristocracy_shipped.sh` | 15s | 1 |
| FAIL | `test_sec_ipc_exhaustion.sh` | 15s | 1 |
| FAIL | `test_net_gift_economy_shipped.sh` | 14s | 1 |
| FAIL | `test_policy_join_allow.sh` | 14s | 1 |
| FAIL | `test_net_whale_hunt_shipped.sh` | 13s | 1 |
| PASS | `test_dur_idle_10min.sh` | 608s | 0 |
| PASS | `test_sec_rekey_flood.sh` | 495s | 0 |
| PASS | `test_size_file_100mb.sh` | 229s | 0 |
| PASS | `test_star5_hub_fanout.sh` | 156s | 0 |
| PASS | `test_star5_hub_fanin.sh` | 154s | 0 |
| PASS | `test_nat_address_restricted.sh` | 139s | 0 |
| PASS | `test_nat_udp_blocked.sh` | 126s | 0 |
| PASS | `test_nat_restricted_cone.sh` | 124s | 0 |
| PASS | `test_size_file_50mb.sh` | 124s | 0 |
| PASS | `test_nat_conntrack_timeout.sh` | 121s | 0 |
| PASS | `test_nat_cgn.sh` | 111s | 0 |
| PASS | `test_nat_rendezvous_natted.sh` | 107s | 0 |
| PASS | `test_policy_shipped_configs.sh` | 105s | 0 |
| PASS | `test_nat_plus_mtu.sh` | 85s | 0 |
| PASS | `test_nat_plus_latency.sh` | 84s | 0 |
| PASS | `test_nat_full_cone.sh` | 81s | 0 |
| PASS | `test_network_edge.sh` | 80s | 0 |
| PASS | `test_task_accept_expiry.sh` | 77s | 0 |
| PASS | `test_receiver_sigkill_midtask.sh` | 76s | 0 |
| PASS | `test_nat_egress_443_only.sh` | 73s | 0 |
| PASS | `test_nat_hairpin.sh` | 70s | 0 |
| PASS | `test_sec_sym_nat_spoof.sh` | 70s | 0 |
| PASS | `test_race_polo_read_write.sh` | 67s | 0 |
| PASS | `test_dur_idle_60s.sh` | 66s | 0 |
| PASS | `test_dur_periodic_60s.sh` | 66s | 0 |
| PASS | `test_nat_dual_symmetric.sh` | 66s | 0 |
| PASS | `test_sec_replay_after_rekey.sh` | 64s | 0 |
| PASS | `test_size_file_10mb.sh` | 64s | 0 |
| PASS | `test_nat_symmetric.sh` | 63s | 0 |
| PASS | `test_stress_edge.sh` | 63s | 0 |
| PASS | `test_nat_plus_bandwidth.sh` | 60s | 0 |
| PASS | `test_service_agent.sh` | 60s | 0 |
| PASS | `test_net_grudge_match_shipped.sh` | 59s | 0 |
| PASS | `test_send_file_concurrent.sh` | 55s | 0 |
| PASS | `test_nat_plus_reorder.sh` | 53s | 0 |
| PASS | `test_nat_stateful_firewall.sh` | 52s | 0 |
| PASS | `test_size_task_result_10mb.sh` | 51s | 0 |
| PASS | `test_webhook_trust_changed.sh` | 50s | 0 |
| PASS | `test_force_relay_send_file.sh` | 47s | 0 |
| PASS | `test_pubsub_fanout.sh` | 47s | 0 |
| PASS | `test_mixed_traffic_burst.sh` | 44s | 0 |
| PASS | `test_nat_plus_loss.sh` | 44s | 0 |
| PASS | `test_sec_sybil_reputation.sh` | 43s | 0 |
| PASS | `test_nat_partition_post_reg.sh` | 42s | 0 |
| PASS | `test_send_file_integrity.sh` | 42s | 0 |
| PASS | `test_force_relay_send_message.sh` | 41s | 0 |
| PASS | `test_nat_multihomed.sh` | 41s | 0 |
| PASS | `test_trust_revoke.sh` | 41s | 0 |
| PASS | `test_race_sendfile_rekey.sh` | 40s | 0 |
| PASS | `test_race_register_lookup.sh` | 39s | 0 |
| PASS | `test_peer_restarted_pubsub_sub.sh` | 38s | 0 |
| PASS | `test_results_after_submitter_died.sh` | 38s | 0 |
| PASS | `test_gateway_rotate_key.sh` | 35s | 0 |
| PASS | `test_size_pubsub_large.sh` | 35s | 0 |
| PASS | `test_task_description_integrity.sh` | 35s | 0 |
| PASS | `test_trust_grant_already_connected.sh` | 34s | 0 |
| PASS | `test_nat_ipv6_only.sh` | 33s | 0 |
| PASS | `test_net_sybil_gauntlet_shipped.sh` | 33s | 0 |
| PASS | `test_partition_midflight.sh` | 33s | 0 |
| PASS | `test_webhook_task_submitted.sh` | 33s | 0 |
| PASS | `test_size_file_500mb_reject.sh` | 32s | 0 |
| PASS | `test_task_execute_fifo.sh` | 32s | 0 |
| PASS | `test_net_cross_network_traffic_allowed.sh` | 31s | 0 |
| PASS | `test_task_concurrent_workers.sh` | 31s | 0 |
| PASS | `test_task_execute_flow.sh` | 31s | 0 |
| PASS | `test_task_polo_gate.sh` | 31s | 0 |
| PASS | `test_pubsub_service_agent.sh` | 30s | 0 |
| PASS | `test_task_message_chain.sh` | 30s | 0 |
| PASS | `test_fanout_5agents_pubsub.sh` | 29s | 0 |
| PASS | `test_mesh_3agents_crosstraffic.sh` | 29s | 0 |
| PASS | `test_race_trust_grant_revoke.sh` | 29s | 0 |
| PASS | `test_sec_beacon_amplification.sh` | 29s | 0 |
| PASS | `test_task_bidirectional_services.sh` | 29s | 0 |
| PASS | `test_trust_grant_fresh.sh` | 29s | 0 |
| PASS | `test_net_trust_decay_shipped.sh` | 28s | 0 |
| PASS | `test_task_file_results.sh` | 28s | 0 |
| PASS | `test_task_result_integrity.sh` | 28s | 0 |
| PASS | `test_obs_log_peer_rekeyed.sh` | 27s | 0 |
| PASS | `test_rendezvous_beacon_split.sh` | 27s | 0 |
| PASS | `test_task_accepted_restart_recovery.sh` | 27s | 0 |
| PASS | `test_flash_crowd_10agents_register.sh` | 26s | 0 |
| PASS | `test_policy_cycle_prune_trust.sh` | 26s | 0 |
| PASS | `test_sec_pubsub_spam.sh` | 26s | 0 |
| PASS | `test_race_topic_delete_publish.sh` | 24s | 0 |
| PASS | `test_task_progress_events.sh` | 24s | 0 |
| PASS | `test_gateway_pubsub_pub.sh` | 23s | 0 |
| PASS | `test_policy_join_score.sh` | 23s | 0 |
| PASS | `test_pubsub_publish_to_empty_topic.sh` | 23s | 0 |
| PASS | `test_task_decline.sh` | 23s | 0 |
| PASS | `test_task_polo_guarantee.sh` | 23s | 0 |
| PASS | `test_bidirectional.sh` | 22s | 0 |
| PASS | `test_gateway_task_result.sh` | 22s | 0 |
| PASS | `test_gateway_task_submit.sh` | 22s | 0 |
| PASS | `test_midrekey_task_submit.sh` | 22s | 0 |
| PASS | `test_obs_metric_encrypt_ok.sh` | 22s | 0 |
| PASS | `test_obs_tasklist_vs_disk.sh` | 22s | 0 |
| PASS | `test_policy_cycle_evict.sh` | 22s | 0 |
| PASS | `test_pubsub_subscribe_before_publisher.sh` | 22s | 0 |
| PASS | `test_task_policy_decline.sh` | 22s | 0 |
| PASS | `test_type_routed_service.sh` | 22s | 0 |
| PASS | `test_midrekey_send_file.sh` | 21s | 0 |
| PASS | `test_net_seniority_shipped.sh` | 21s | 0 |
| PASS | `test_task_invalid_states.sh` | 21s | 0 |
| PASS | `test_chaos_loss10_all_ops.sh` | 20s | 0 |
| PASS | `test_chaos_reorder_all_ops.sh` | 20s | 0 |
| PASS | `test_gateway_file.sh` | 20s | 0 |
| PASS | `test_gateway_lookup.sh` | 20s | 0 |
| PASS | `test_net_forgiveness_shipped.sh` | 20s | 0 |
| PASS | `test_net_meritocracy_rating_shipped.sh` | 20s | 0 |
| PASS | `test_peer_restarted_send_file.sh` | 20s | 0 |
| PASS | `test_peer_restarted_send_message.sh` | 20s | 0 |
| PASS | `test_polo_persistence_restart.sh` | 20s | 0 |
| PASS | `test_task_list_ordering.sh` | 20s | 0 |
| PASS | `test_inbox_ordering.sh` | 19s | 0 |
| PASS | `test_net_old_guard_shipped.sh` | 19s | 0 |
| PASS | `test_sec_malformed_frame.sh` | 19s | 0 |
| PASS | `test_task_persistence_restart.sh` | 19s | 0 |
| PASS | `test_fanout_3agents_pubsub.sh` | 18s | 0 |
| PASS | `test_gateway_register.sh` | 18s | 0 |
| PASS | `test_midrekey_send_message.sh` | 18s | 0 |
| PASS | `test_net_dunbar_150_shipped.sh` | 18s | 0 |
| PASS | `test_net_lifo_shipped.sh` | 18s | 0 |
| PASS | `test_obs_dashboard_polo_truth.sh` | 18s | 0 |
| PASS | `test_policy_connect_score.sh` | 18s | 0 |
| PASS | `test_pubsub_multi_publisher.sh` | 18s | 0 |
| PASS | `test_pubsub_topic_fifo.sh` | 18s | 0 |
| PASS | `test_race_submit_rekey.sh` | 18s | 0 |
| PASS | `test_disk_full_receiver.sh` | 17s | 0 |
| PASS | `test_gateway_pubsub_sub.sh` | 17s | 0 |
| PASS | `test_message_payload_integrity.sh` | 17s | 0 |
| PASS | `test_net_fifo_shipped.sh` | 17s | 0 |
| PASS | `test_send_file_hostile_names.sh` | 17s | 0 |
| PASS | `test_net_join_allow_per_network.sh` | 16s | 0 |
| PASS | `test_net_vouching_chain_shipped.sh` | 16s | 0 |
| PASS | `test_policy_datagram_allow.sh` | 16s | 0 |
| PASS | `test_policy_join_deny.sh` | 16s | 0 |
| PASS | `test_race_pubsub_late_sub.sh` | 16s | 0 |
| PASS | `test_cli.sh` | 15s | 0 |
| PASS | `test_policy_connect_allow.sh` | 15s | 0 |
| PASS | `test_race_submit_accept.sh` | 15s | 0 |
| PASS | `test_rotate_key_hot_path.sh` | 15s | 0 |
| PASS | `test_submit_to_unregistered_peer.sh` | 15s | 0 |
| PASS | `test_policy_connect_tag.sh` | 14s | 0 |
| PASS | `test_send_file_bidirectional_transform.sh` | 14s | 0 |
| PASS | `test_sec_spoofed_node_id.sh` | 13s | 0 |
| PASS | `test_beacon_ping.sh` | 12s | 0 |
| PASS | `test_sec_oversized_payload.sh` | 12s | 0 |
| PASS | `test_chain_abc_message.sh` | 11s | 0 |
| PASS | `test_chain_abc_task.sh` | 11s | 0 |
| PASS | `test_clock_rollback.sh` | 11s | 0 |
| PASS | `test_dashboard.sh` | 11s | 0 |
| PASS | `test_gateway_polo_read.sh` | 11s | 0 |
| PASS | `test_rotate_key.sh` | 11s | 0 |
| PASS | `test_size_message_10mb_reject.sh` | 11s | 0 |
| PASS | `test_gateway_ping.sh` | 10s | 0 |
| PASS | `test_3agent_lookup_propagation.sh` | 9s | 0 |
| PASS | `test_clock_skew_receiver.sh` | 9s | 0 |
| PASS | `test_fanout_3agents_file.sh` | 7s | 0 |
| PASS | `test_net_all_shipped_configs_load.sh` | 6s | 0 |

## Failed logs

### `test_rendezvous_restart_midflight.sh` (exit=1, 124s)

```
==========================================
Rendezvous restart mid-flight
==========================================
[2026-04-23 17:52:36] [1;33m[TEST][0m Starting p2p stack (clean)
[2026-04-23 17:52:43] [0;32m[PASS][0m both agents registered
[2026-04-23 17:52:44] [1;33m[TEST][0m warm-up task to establish tunnel + peer caches
[2026-04-23 17:52:46] [0;32m[PASS][0m tunnel warm (status=SUCCEEDED)
[2026-04-23 17:52:46] [1;33m[TEST][0m stop rendezvous container (keep agents up)
[2026-04-23 17:52:49] [0;32m[PASS][0m rendezvous stopped; still running: agent-a agent-b 
[2026-04-23 17:52:49] [1;33m[TEST][0m task a->b completes while rendezvous down (30s)
[2026-04-23 17:53:31] [0;31m[FAIL][0m submit during outage failed: {"code":"not_found","error":"cannot resolve \"agent-b\" — is the hostname correct and is there mutual trust? (see: pilotctl handshake)","message":"cannot resolve \"agent-b\" — is the hostname correct and is there mutual trust? (see: pilotctl handshake)","status":"error"}
[2026-04-23 17:53:31] [1;33m[TEST][0m send-file 2 KiB a->b while rendezvous down
[2026-04-23 17:53:52] [0;31m[FAIL][0m file mismatch under outage src=7b2bd4676b17... dst=... ack=
[2026-04-23 17:53:52] [1;33m[TEST][0m start rendezvous back up
[2026-04-23 17:53:53] [0;32m[PASS][0m both agents re-registered post-rendezvous-restart (total=2)
[2026-04-23 17:53:53] [1;33m[TEST][0m pilotctl find agent-b from agent-a resolves
[2026-04-23 17:54:00] [0;32m[PASS][0m lookup resolved: 0:0000.0000.0002
[2026-04-23 17:54:00] [1;33m[TEST][0m task a->b completes post-rendezvous-restart
[2026-04-23 17:54:40] [0;31m[FAIL][0m post-restart task stuck (status=)
[2026-04-23 17:54:40] [1;33m[TEST][0m no panics/fatals in agent logs
[2026-04-23 17:54:40] [0;32m[PASS][0m clean logs

==========================================
Rendezvous restart summary
==========================================
Passed: [0;32m6[0m
Failed: [0;31m3[0m
==========================================
```

### `test_force_relay_task.sh` (exit=1, 145s)

```
==========================================
Force relay: task submit+complete
==========================================
[2026-04-23 17:52:31] [1;33m[TEST][0m partition direct UDP
[2026-04-23 17:52:33] [0;32m[PASS][0m direct severed
[2026-04-23 17:52:43] [1;33m[TEST][0m task submit a->b via relay
[2026-04-23 17:52:43] [0;31m[FAIL][0m submit failed at door: {"code":"connection_failed","error":"submit: EOF","message":"submit: EOF","status":"error"}
[2026-04-23 17:52:43] [1;33m[TEST][0m task reaches completion via relay
[2026-04-23 17:54:42] [0;31m[FAIL][0m stuck at  — likely P1-010
[2026-04-23 17:54:42] [1;33m[TEST][0m no panic/fatal
[2026-04-23 17:54:43] [0;32m[PASS][0m clean logs

Passed: 2  Failed: 2
```

### `test_chaos_loss30_all_ops.sh` (exit=1, 210s)

```
==========================================
Chaos: 30% loss x all 7 op families (P1-010)
==========================================
[2026-04-23 17:52:20] [1;33m[TEST][0m fresh chaos-capable stack
[2026-04-23 17:52:27] [0;32m[PASS][0m both agents registered
[2026-04-23 17:52:29] [1;33m[TEST][0m apply 30% loss on agent-b eth0
[2026-04-23 17:52:30] [0;32m[PASS][0m netem 30% loss applied
[2026-04-23 17:52:30] [1;33m[TEST][0m ping a->b under 30% loss (long timeout)
[2026-04-23 17:52:46] [0;32m[PASS][0m ping ok
[2026-04-23 17:52:46] [1;33m[TEST][0m send-message under 30% loss
[2026-04-23 17:52:54] [0;32m[PASS][0m send-message ok
[2026-04-23 17:52:54] [1;33m[TEST][0m send-file 8 KiB under 30% loss (sha256 match or clean fail)
[2026-04-23 17:53:02] [0;32m[PASS][0m send-file sha match under 30% loss
[2026-04-23 17:53:02] [1;33m[TEST][0m task submit a->b under 30% loss (120s)
[2026-04-23 17:55:44] [0;31m[FAIL][0m task stuck (status=EXPIRED) — expected P1-010 finding
[2026-04-23 17:55:44] [1;33m[TEST][0m pubsub publish under 30% loss
[2026-04-23 17:55:44] [0;32m[PASS][0m publish ok
[2026-04-23 17:55:44] [1;33m[TEST][0m trust handshake under 30% loss
[2026-04-23 17:55:45] [0;32m[PASS][0m handshake ok
[2026-04-23 17:55:45] [1;33m[TEST][0m pilotctl find agent-b (registry lookup) under 30% loss
[2026-04-23 17:55:46] [0;32m[PASS][0m registry lookup ok
[2026-04-23 17:55:46] [1;33m[TEST][0m strip chaos and verify post-chaos ping works
[2026-04-23 17:55:47] [0;32m[PASS][0m post-chaos ping ok
[2026-04-23 17:55:47] [1;33m[TEST][0m no panic/fatal in agent logs
[2026-04-23 17:55:47] [0;32m[PASS][0m clean logs

Passed: 10  Failed: 1
```

### `test_gateway_http_message.sh` (exit=1, 84s)

```
==========================================
Gateway: HTTP/message round-trip via proxy
==========================================
[2026-04-23 17:54:47] [0;32m[PASS][0m agent-b pilot addr: 0:0000.0000.0002
[2026-04-23 17:54:47] [1;33m[TEST][0m map agent-b into gateway local subnet
[2026-04-23 17:54:47] [0;32m[PASS][0m mapped 0:0000.0000.0002 -> 10.4.0.1
[2026-04-23 17:54:47] [1;33m[TEST][0m send payload to 10.4.0.1:1001 (agent-b's data-exchange service)
[2026-04-23 17:56:03] [0;31m[FAIL][0m could not open TCP to 10.4.0.1:1001 via gateway
[2026-04-23 17:56:05] [1;33m[TEST][0m payload delivered to agent-b inbox
[2026-04-23 17:56:05] [0;31m[FAIL][0m payload not found in agent-b inbox; gateway proxy may not have delivered
time=2026-04-24T00:54:48.185Z level=INFO msg="gateway connected" subnet=10.4.0.0/16
time=2026-04-24T00:54:48.185Z level=INFO msg="gateway running"

Passed: 2  Failed: 2
```

### `test_splitbrain_heal.sh` (exit=1, 130s)

```
==========================================
Split-brain heal
==========================================
[2026-04-23 17:54:57] [1;33m[TEST][0m Starting splitbrain stack
[2026-04-23 17:55:47] [0;32m[PASS][0m 2+2 split confirmed
[2026-04-23 17:55:47] [1;33m[TEST][0m while split: a submits to c must fail cleanly
[2026-04-23 17:55:47] [0;32m[PASS][0m submit correctly failed under split (code=not_found)
[2026-04-23 17:55:47] [1;33m[TEST][0m heal: migrate agent-c and agent-d onto rendezvous-1
[2026-04-23 17:57:06] [0;31m[FAIL][0m heal failed — rv-1 sees 2 nodes
  c: Error response from daemon: No such container: pilot-w9-healed-agent-c
```

### `test_dur_steady_compressed_24h.sh` (exit=1, 310s)

```
==========================================
Duration: compressed 24h (1s cycle x 300s)
==========================================
[2026-04-23 17:52:26] [0;32m[PASS][0m both agents registered
[2026-04-23 17:52:26] [1;33m[TEST][0m write 1s-cycle expr_policy
[2026-04-23 17:52:26] [0;32m[PASS][0m policy written
[2026-04-23 17:52:26] [1;33m[TEST][0m create unmanaged network then attach expr_policy
[2026-04-23 17:52:28] [0;32m[PASS][0m network active (nid=1), policy attached, joined
[2026-04-23 17:52:29] [0;32m[PASS][0m T0 rss=11520KiB fds=9
[2026-04-23 17:52:29] [1;33m[TEST][0m run for 300s
[2026-04-23 17:57:29] [0;32m[PASS][0m run complete
    cycle ticks during run: 0 (expected ~300)
[2026-04-23 17:57:29] [1;33m[TEST][0m tick count within ±25% of 300
[2026-04-23 17:57:29] [0;31m[FAIL][0m tick count 0 outside [225, 375]
    delta rss=1920KiB fds=0
[2026-04-23 17:57:29] [1;33m[TEST][0m rss delta < 50 MiB
[2026-04-23 17:57:29] [0;32m[PASS][0m rss delta 1920KiB within budget
[2026-04-23 17:57:29] [1;33m[TEST][0m fd delta < 20
[2026-04-23 17:57:29] [0;32m[PASS][0m fd delta 0 within budget
[2026-04-23 17:57:29] [1;33m[TEST][0m no panics
[2026-04-23 17:57:30] [0;32m[PASS][0m clean logs

Passed: 8  Failed: 1
```

### `test_net_mutual_admiration_shipped.sh` (exit=1, 77s)

```
[2026-04-23 17:56:51] [0;32m[PASS][0m net=1
[2026-04-23 17:56:54] [1;33m[TEST][0m unilateral connect produces no score (until mutual)
[2026-04-23 17:58:04] [0;31m[FAIL][0m no mutual bonus: uni=0 mutual=0 (EXPECTED: increase on reciprocation)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_beacon_restart_midflight.sh` (exit=1, 89s)

```
==========================================
Beacon restart mid-flight
==========================================
[2026-04-23 17:57:11] [0;32m[PASS][0m both agents registered
[2026-04-23 17:57:12] [1;33m[TEST][0m warm task before beacon restart
[2026-04-23 17:57:14] [0;32m[PASS][0m warm ok
[2026-04-23 17:57:14] [1;33m[TEST][0m docker compose restart rendezvous (beacon container)
[2026-04-23 17:57:14] [0;32m[PASS][0m rendezvous+beacon container back online
[2026-04-23 17:57:14] [1;33m[TEST][0m both agents re-register post-beacon-restart
[2026-04-23 17:57:15] [0;32m[PASS][0m total_nodes=2
[2026-04-23 17:57:15] [1;33m[TEST][0m task still completes post-beacon-restart
[2026-04-23 17:58:34] [0;31m[FAIL][0m post-beacon task stuck (status=)
[2026-04-23 17:58:34] [1;33m[TEST][0m pilotctl lookup works post-beacon-restart
[2026-04-23 17:58:34] [0;32m[PASS][0m lookup ok: 0:0000.0000.0001
[2026-04-23 17:58:34] [1;33m[TEST][0m no panic/fatal in agent logs
[2026-04-23 17:58:35] [0;32m[PASS][0m clean logs

Passed: 6  Failed: 1
```

### `test_chaos_packet_loss.sh` (exit=1, 52s)

```
==========================================
Chaos: 30% packet loss on agent-b ingress
==========================================
[2026-04-23 17:57:50] [1;33m[TEST][0m start stack with NET_ADMIN overlay
[2026-04-23 17:57:55] [0;32m[PASS][0m both agents registered
[2026-04-23 17:57:55] [1;33m[TEST][0m agent-b has NET_ADMIN + iproute2 (tc qdisc show succeeds)
[2026-04-23 17:57:55] [0;32m[PASS][0m tc available
[2026-04-23 17:57:55] [1;33m[TEST][0m baseline (no chaos) task a->b completes
[2026-04-23 17:57:56] [0;32m[PASS][0m baseline task completed cleanly (status=SUCCEEDED)
[2026-04-23 17:57:56] [1;33m[TEST][0m apply 30% ingress+egress loss on agent-b eth0
[2026-04-23 17:57:57] [0;32m[PASS][0m netem applied: qdisc netem 8016: root refcnt 11 limit 1000 loss 30%
[2026-04-23 17:57:57] [1;33m[TEST][0m task a->b completes under 30% packet loss (60s timeout)
[2026-04-23 17:57:57] [0;31m[FAIL][0m submit under chaos failed: {"code":"connection_failed","error":"submit: EOF","message":"submit: EOF","status":"error"}
[2026-04-23 17:57:57] [1;33m[TEST][0m send-file 4 KiB completes under 30% loss
[2026-04-23 17:58:01] [0;32m[PASS][0m file round-trip intact (ack=ACK FILE 4096 bytes sha=c1c52e39ff29...)
[2026-04-23 17:58:01] [1;33m[TEST][0m strip netem qdisc and verify clean traffic again
[2026-04-23 17:58:01] [0;32m[PASS][0m netem removed cleanly
[2026-04-23 17:58:42] [0;31m[FAIL][0m post-chaos task stuck (status=)
[2026-04-23 17:58:42] [1;33m[TEST][0m no panic/fatal in daemon logs
[2026-04-23 17:58:42] [0;32m[PASS][0m clean logs

==========================================
Chaos smoke summary
==========================================
Passed: [0;32m7[0m
Failed: [0;31m2[0m
==========================================
```

### `test_dur_shortcycle_policy_1m.sh` (exit=1, 69s)

```
==========================================
Duration: short-cycle policy 5s x 60s
==========================================
[2026-04-23 17:58:38] [0;32m[PASS][0m both agents registered
[2026-04-23 17:58:38] [1;33m[TEST][0m write short-cycle expr_policy onto agent-a
[2026-04-23 17:58:38] [0;32m[PASS][0m policy written
[2026-04-23 17:58:38] [1;33m[TEST][0m create unmanaged network then attach expr_policy
[2026-04-23 17:58:39] [0;32m[PASS][0m network created (nid=1), policy attached, joined
[2026-04-23 17:58:39] [1;33m[TEST][0m run 60s and count cycle events
    cycle tick delta over 60s: 0 (expect >= 10)
[2026-04-23 17:59:41] [0;31m[FAIL][0m only 0 cycle ticks (expected >=10 for 5s cycle over 60s)
[2026-04-23 17:59:41] [1;33m[TEST][0m no panics
[2026-04-23 17:59:43] [0;32m[PASS][0m clean logs

Passed: 4  Failed: 1
```

### `test_fanin_3agents_tasks.sh` (exit=1, 103s)

```
  a-worker: 00:58:43.581517050 done tid=43072365-34ee-b9b7-2639-94691e61e112 desc=from-b:1
  a-worker: {
  a-worker:   "message": "Task accepted",
  a-worker:   "status": "ACCEPTED",
  a-worker:   "task_id": "26d23e64-7097-7104-7659-35d5f6c6979d"
  a-worker: }
  a-worker: {
  a-worker:   "sent_to": "0:0000.0000.0003",
  a-worker:   "sent_type": "text",
  a-worker:   "status": "SUCCEEDED",
  a-worker:   "task_id": "26d23e64-7097-7104-7659-35d5f6c6979d"
  a-worker: }
  a-worker: 00:58:43.679984175 done tid=26d23e64-7097-7104-7659-35d5f6c6979d desc=from-c:1
[2026-04-23 18:00:10] [1;33m[TEST][0m each submitter gets its own ack:* result
  mismatch role=b tid=673cc095-b268-5048-d695-b27ecff494b0 result=
  mismatch role=b tid=b47ac03a-3eca-85a0-58cc-9fabd1d026a6 result=
  mismatch role=b tid=bcd806e4-1588-9d0a-f8c4-d36231fd5497 result=
  mismatch role=c tid=34708559-1a85-34f1-82a0-6df89183f38d result=
  mismatch role=c tid=cc3bfcb8-03fc-21c6-648d-89b25f4ec445 result=
  mismatch role=c tid=e638bad8-2c9a-acf1-fdc5-36061ac2d75c result=
[2026-04-23 18:00:15] [0;31m[FAIL][0m 6 mis-routed results
[2026-04-23 18:00:15] [1;33m[TEST][0m no panics/fatals in daemon logs
[2026-04-23 18:00:15] [0;32m[PASS][0m clean logs

==========================================
Fan-in tasks summary
==========================================
Passed: [0;32m4[0m
Failed: [0;31m2[0m
==========================================
```

### `test_chaos_delay200_all_ops.sh` (exit=1, 171s)

```
==========================================
Chaos: 200ms delay x all 7 op families
==========================================
[2026-04-23 17:57:45] [0;32m[PASS][0m both agents registered
[2026-04-23 17:57:47] [1;33m[TEST][0m apply 200ms +/-50ms delay on agent-b eth0
[2026-04-23 17:57:48] [0;32m[PASS][0m netem delay applied
[2026-04-23 17:57:48] [1;33m[TEST][0m ping under 200ms delay
[2026-04-23 17:57:53] [0;32m[PASS][0m ping ok
[2026-04-23 17:57:53] [1;33m[TEST][0m send-message under delay
[2026-04-23 17:57:53] [0;32m[PASS][0m send-message ok
[2026-04-23 17:57:53] [1;33m[TEST][0m send-file 16 KiB under 200ms delay
[2026-04-23 17:57:55] [0;32m[PASS][0m send-file sha match
[2026-04-23 17:57:55] [1;33m[TEST][0m task submit under 200ms delay (90s)
[2026-04-23 18:00:23] [0;31m[FAIL][0m task stuck (status=EXPIRED)
[2026-04-23 18:00:23] [1;33m[TEST][0m pubsub publish under delay
[2026-04-23 18:00:23] [0;32m[PASS][0m publish ok
test_chaos_delay200_all_ops.sh: line 118: handshake: command not found
test_chaos_delay200_all_ops.sh: line 118: approve: command not found
[2026-04-23 18:00:23] [1;33m[TEST][0m trust handshake under delay (real CLI:  + receiver )
[2026-04-23 18:00:24] [0;32m[PASS][0m handshake ok
[2026-04-23 18:00:24] [1;33m[TEST][0m pilotctl find agent-b (registry lookup) under delay
[2026-04-23 18:00:24] [0;32m[PASS][0m registry lookup ok
[2026-04-23 18:00:24] [1;33m[TEST][0m strip delay and sanity ping
[2026-04-23 18:00:27] [0;32m[PASS][0m post-chaos ping ok
[2026-04-23 18:00:27] [1;33m[TEST][0m no panic/fatal
[2026-04-23 18:00:27] [0;32m[PASS][0m clean logs

Passed: 10  Failed: 1
```

### `test_gateway_trust_grant.sh` (exit=1, 30s)

```
==========================================
Gateway: trust grant agent-b
==========================================
[2026-04-23 18:01:12] [1;33m[TEST][0m gateway initiates handshake to agent-b
[2026-04-23 18:01:14] [0;32m[PASS][0m handshake sent
[2026-04-23 18:01:14] [1;33m[TEST][0m agent-b sees gateway in pending
[2026-04-23 18:01:16] [0;32m[PASS][0m agent-b has gateway in pending
jq: parse error: Invalid numeric literal at line 1, column 6
[2026-04-23 18:01:17] [1;33m[TEST][0m gateway trust list contains agent-b after approval
[2026-04-23 18:01:20] [0;31m[FAIL][0m agent-b (node_id=2) not in gateway trust list
{"data":{"trusted":[]},"status":"ok"}

Passed: 2  Failed: 1
```

### `test_force_relay_pubsub.sh` (exit=1, 116s)

```
==========================================
Force relay: pub/sub delivery
==========================================
[2026-04-23 17:59:52] [1;33m[TEST][0m subscribe on b (before partition)
[2026-04-23 17:59:58] [1;33m[TEST][0m partition direct UDP
[2026-04-23 18:00:04] [0;32m[PASS][0m direct severed
[2026-04-23 18:00:14] [1;33m[TEST][0m publish from a via relay
[2026-04-23 18:00:14] [0;32m[PASS][0m publish returned
[2026-04-23 18:00:14] [1;33m[TEST][0m subscriber on b receives event via relay
[2026-04-23 18:01:23] [0;31m[FAIL][0m event not received — likely P1-010
[2026-04-23 18:01:23] [1;33m[TEST][0m no panic/fatal
[2026-04-23 18:01:24] [0;32m[PASS][0m clean logs

Passed: 3  Failed: 1
```

### `test_dur_steady_10min.sh` (exit=1, 614s)

```
==========================================
Duration: steady 10 msg/s x 600s
==========================================
[2026-04-23 17:52:25] [0;32m[PASS][0m both agents registered
[2026-04-23 17:52:25] [1;33m[TEST][0m T=0 snapshot (agent-a)
[2026-04-23 17:52:25] [0;32m[PASS][0m T0: rss=11876KiB fds=9
[2026-04-23 17:52:26] [1;33m[TEST][0m start steady send loop 10/s for 600s
[2026-04-23 18:02:31] [1;33m[TEST][0m T=end snapshot (agent-a)
[2026-04-23 18:02:31] [0;32m[PASS][0m T1: rss=28492KiB fds=9
    delta: rss=16616KiB fds=0
[2026-04-23 18:02:31] [1;33m[TEST][0m rss delta < 100 MiB over 10 min of load
[2026-04-23 18:02:31] [0;32m[PASS][0m rss delta 16616KiB within budget
[2026-04-23 18:02:31] [1;33m[TEST][0m fd delta < 50
[2026-04-23 18:02:31] [0;32m[PASS][0m fd delta 0 within budget
[2026-04-23 18:02:32] [1;33m[TEST][0m expected send volume reached
[2026-04-23 18:02:32] [0;31m[FAIL][0m sent=1718 much less than target 6000
[2026-04-23 18:02:32] [1;33m[TEST][0m no panics / leaks in logs
[2026-04-23 18:02:33] [0;32m[PASS][0m clean logs

Passed: 6  Failed: 1
```

### `test_midrekey_task_results.sh` (exit=1, 96s)

```
==========================================
Mid-rekey: task results (P1-009 direct)
==========================================
[2026-04-23 18:01:16] [1;33m[TEST][0m fresh stack
[2026-04-23 18:01:22] [0;32m[PASS][0m agents up
[2026-04-23 18:01:22] [1;33m[TEST][0m submit + accept T1
[2026-04-23 18:01:25] [0;32m[PASS][0m T1 ACCEPTED on b
[2026-04-23 18:01:25] [1;33m[TEST][0m restart agent-b (rekey)
[2026-04-23 18:01:26] [0;32m[PASS][0m agent-b back, tunnel rekey window open
[2026-04-23 18:01:26] [1;33m[TEST][0m send-results during rekey window (no warm-up)
[2026-04-23 18:01:27] [1;33m[TEST][0m submitter observes terminal status within 45s
[2026-04-23 18:02:50] [0;31m[FAIL][0m stuck at EXPIRED — direct P1-009 regression
[2026-04-23 18:02:50] [1;33m[TEST][0m result text matches sender payload
[2026-04-23 18:02:50] [0;31m[FAIL][0m payload missing: 
[2026-04-23 18:02:50] [1;33m[TEST][0m no panic/fatal
[2026-04-23 18:02:50] [0;32m[PASS][0m clean logs

Passed: 4  Failed: 2
```

### `test_nat_asymmetric_routing.sh` (exit=1, 88s)

```
    #38 [agent-b] exporting to image
    #38 exporting layers done
    #38 exporting manifest sha256:d1ad86c65e21ddd4f6440337936df4a3dfdcb390a366500159ef2f57cfd3a1cf 0.0s done
    #38 exporting config sha256:69c2cb51ad98af0dcd595ece26d4bea868119ef41deffd352698bc0744a2b0bf 0.0s done
    #38 exporting attestation manifest sha256:6c11990fa4a4076ea6e6d54d44b6862162c488267fbf7b2a76b700f4a0be3d71 0.1s done
    #38 exporting manifest list sha256:d56761ceb77b5ec3dbddf1ec2336aa54dc3edbeb22d3135a8862186ee12b18eb 0.0s done
    #38 naming to docker.io/library/pilot-multi:latest done
    #38 unpacking to docker.io/library/pilot-multi:latest 0.0s done
    #38 DONE 0.2s
    
    #39 [rendezvous] resolving provenance for metadata file
    #39 DONE 0.1s
    
    #40 [agent-b] resolving provenance for metadata file
    #40 DONE 0.1s
    
    #41 [agent-a] resolving provenance for metadata file
    #41 DONE 0.1s
     pilot-multi:latest  Built
     pilot-w8-nat-gw-b  Built
     pilot-multi:latest  Built
     pilot-multi:latest  Built
     pilot-w8-nat-gw-a  Built
     Network pilot-w8_private-b  Creating
     Network pilot-w8_private-b  Created
     Network pilot-w8_public  Creating
     Network pilot-w8_public  Created
     Network pilot-w8_private-a  Creating
     Network pilot-w8_private-a  Error
    failed to create network pilot-w8_private-a: Error response from daemon: invalid pool request: Pool overlaps with other one on this address space
```

### `test_net_anti_camping_shipped.sh` (exit=1, 19s)

```
[2026-04-23 18:06:43] [0;32m[PASS][0m net=1
[2026-04-23 18:06:47] [1;33m[TEST][0m force cycles — expect b evicted after threshold
[2026-04-23 18:06:53] [0;31m[FAIL][0m b still in rankings after idle cycles (EXPECTED: evicted)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_aristocracy_shipped.sh` (exit=1, 15s)

```
[2026-04-23 18:07:02] [0;32m[PASS][0m net=1
[2026-04-23 18:07:05] [1;33m[TEST][0m tagged elite peer bypasses default deny
[2026-04-23 18:07:07] [0;31m[FAIL][0m elite tag denied (EXPECTED: elevated privilege for elite)
[2026-04-23 18:07:07] [1;33m[TEST][0m untagged peer access vs elite: asymmetric
[2026-04-23 18:07:09] [0;32m[PASS][0m untagged denied, elite allowed — asymmetric privilege confirmed
Passed: [0;32m2[0m  Failed: [0;31m1[0m
```

### `test_net_cold_shoulder_shipped.sh` (exit=1, 18s)

```
[2026-04-23 18:07:25] [0;32m[PASS][0m net=1
[2026-04-23 18:07:29] [1;33m[TEST][0m low-score peer traffic silently dropped
[2026-04-23 18:07:29] [0;31m[FAIL][0m traffic flowed from low-score peer (EXPECTED: cold-shoulder deny)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_burnout_shipped.sh` (exit=1, 35s)

```
[2026-04-23 18:07:04] [0;32m[PASS][0m net=1
[2026-04-23 18:07:07] [1;33m[TEST][0m generate burst traffic to trigger burnout cap
[2026-04-23 18:07:30] [1;33m[TEST][0m after burst, score is bounded or peer evicted (burnout cap)
[2026-04-23 18:07:30] [0;31m[FAIL][0m no burnout cap observed: score=->0 listed=1 (EXPECTED: score moved AND bounded, OR peer evicted)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_cooling_off_shipped.sh` (exit=1, 23s)

```
[2026-04-23 18:07:27] [0;32m[PASS][0m net=1
[2026-04-23 18:07:31] [1;33m[TEST][0m violating peer is in cooldown
[2026-04-23 18:07:35] [0;31m[FAIL][0m retry succeeded inside cooldown window (EXPECTED: deny)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_cross_network_traffic_denied.sh` (exit=1, 19s)

```
[2026-04-23 18:07:42] [1;33m[TEST][0m create strict network X (deny non-members)
[2026-04-23 18:07:47] [0;32m[PASS][0m net=1
[2026-04-23 18:07:47] [1;33m[TEST][0m agent-a joins X; agent-b stays out
[2026-04-23 18:07:51] [0;32m[PASS][0m agent-a is member of X
[2026-04-23 18:07:51] [1;33m[TEST][0m agent-b (non-member of X) dials agent-a — expect deny
[2026-04-23 18:07:52] [0;31m[FAIL][0m cross-network send succeeded despite X's deny rule (EXPECTED: deny)
    resolved "agent-a" → 0:0000.0000.0003
    sent 19 bytes (no response)
Passed: [0;32m2[0m  Failed: [0;31m1[0m
```

### `test_net_gift_economy_shipped.sh` (exit=1, 14s)

```
[2026-04-23 18:08:14] [0;32m[PASS][0m net=1
[2026-04-23 18:08:20] [1;33m[TEST][0m both sender and receiver accrue reward
[2026-04-23 18:08:20] [0;31m[FAIL][0m asymmetric rewards missing: A=0 B=0 (EXPECTED: both >0)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_data_exchange_policy_shipped.sh` (exit=1, 56s)

```
[2026-04-23 18:07:49] [0;32m[PASS][0m net=1
[2026-04-23 18:07:53] [1;33m[TEST][0m echo (port 7) is always allowed (allow-echo-dial rule)
[2026-04-23 18:08:22] [0;31m[FAIL][0m echo blocked (EXPECTED: port 7 always allowed)
[2026-04-23 18:08:23] [1;33m[TEST][0m port 1001 rejected when neither side has 'service' tag
[2026-04-23 18:08:27] [0;32m[PASS][0m 1001 send refused
[2026-04-23 18:08:27] [1;33m[TEST][0m port 1001 allowed once agent-b takes 'service' tag
[2026-04-23 18:08:30] [0;31m[FAIL][0m 1001 blocked with service tag (EXPECTED: allowed)
    resolved "agent-b" → 0:0000.0000.0003
    error: cannot connect to 0:0000.0000.0003 port 1001
    hint:  check that 0:0000.0000.0003 is reachable: pilotctl ping 0:0000.0000.0003
Passed: [0;32m2[0m  Failed: [0;31m2[0m
```

### `test_net_golden_hour_shipped.sh` (exit=1, 18s)

```
[2026-04-23 18:08:19] [0;32m[PASS][0m net=1
[2026-04-23 18:08:22] [1;33m[TEST][0m fresh-join actions accrue bonus
[2026-04-23 18:08:30] [0;31m[FAIL][0m no golden-hour bonus: early= late-delta=0 (EXPECTED: early>0 AND early>late-delta)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_half_life_shipped.sh` (exit=1, 22s)

```
[2026-04-23 18:08:32] [0;32m[PASS][0m net=1
[2026-04-23 18:08:43] [0;31m[FAIL][0m decay too weak or unseeded: 0 -> 0 (EXPECTED: S0>=4 AND S1<S0 AND S1<=1)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_gossip_tax_shipped.sh` (exit=1, 28s)

```
[2026-04-23 18:08:23] [0;32m[PASS][0m net=1
[2026-04-23 18:08:28] [1;33m[TEST][0m excessive pubsub publishes drain score
[2026-04-23 18:08:43] [0;31m[FAIL][0m no gossip tax: 0 -> 0 (EXPECTED: SC0>0 AND SC1<SC0 after high emit)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_high_trust_society_shipped.sh` (exit=1, 23s)

```
[2026-04-23 18:08:42] [0;32m[PASS][0m net=1
[2026-04-23 18:08:46] [1;33m[TEST][0m 5 connects from a->b — score should be +5
[2026-04-23 18:08:55] [0;31m[FAIL][0m score=0 (EXPECTED >= 5; score action not applied per connect)
[2026-04-23 18:08:55] [1;33m[TEST][0m cycle tick runs without panic under active policy
[2026-04-23 18:08:56] [0;32m[PASS][0m cycle ok
Passed: [0;32m2[0m  Failed: [0;31m1[0m
```

### `test_net_isolation_policy_scoping.sh` (exit=1, 27s)

```
[2026-04-23 18:08:40] [1;33m[TEST][0m create strict network (X)
[2026-04-23 18:08:44] [0;32m[PASS][0m net X = 1
[2026-04-23 18:08:44] [1;33m[TEST][0m create permissive network (Y)
[2026-04-23 18:08:49] [0;32m[PASS][0m net Y = 2
[2026-04-23 18:08:49] [1;33m[TEST][0m agent-a joins X; agent-b joins Y
[2026-04-23 18:08:54] [0;32m[PASS][0m memberships set
[2026-04-23 18:08:56] [1;33m[TEST][0m agent-b can reach agent-a on base network (Y's allow is permissive)
[2026-04-23 18:08:57] [0;32m[PASS][0m cross-scope base-network ping ok
[2026-04-23 18:08:57] [1;33m[TEST][0m X's deny is scoped to X (agent-a is member of X)
[2026-04-23 18:08:58] [0;32m[PASS][0m X runner has rules active
[2026-04-23 18:08:58] [1;33m[TEST][0m Y's allow is scoped to Y (agent-b is member of Y, not X)
[2026-04-23 18:08:59] [0;32m[PASS][0m Y runner has rules active
[2026-04-23 18:08:59] [1;33m[TEST][0m agent-a has NO runner for Y, agent-b has NO runner for X
[2026-04-23 18:09:01] [0;31m[FAIL][0m cross-scope status succeeded (leak): A->Y=ok  B->X=ok
Passed: [0;32m6[0m  Failed: [0;31m1[0m
```

### `test_net_join_deny_per_network.sh` (exit=1, 17s)

```
[2026-04-23 18:09:01] [0;32m[PASS][0m net=1
[2026-04-23 18:09:01] [1;33m[TEST][0m agent-b attempts to join — expect deny
[2026-04-23 18:09:03] [0;31m[FAIL][0m agent-b joined despite join-deny rule (EXPECTED: rejected)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_karma_ledger_shipped.sh` (exit=1, 25s)

```
[2026-04-23 18:09:01] [0;32m[PASS][0m net=1
[2026-04-23 18:09:06] [1;33m[TEST][0m 3 connects update karma ledger
[2026-04-23 18:09:11] [0;31m[FAIL][0m karma did not change (EXPECTED: monotonic increase)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_meritocracy_shipped.sh` (exit=1, 19s)

```
[2026-04-23 18:09:19] [0;32m[PASS][0m net=1
[2026-04-23 18:09:22] [1;33m[TEST][0m top-score peer is in rankings and surfaces merit
[2026-04-23 18:09:24] [0;31m[FAIL][0m no ranking surface (EXPECTED: rankings expose merit order)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_lottery_shipped.sh` (exit=1, 27s)

```
[2026-04-23 18:09:16] [0;32m[PASS][0m net=1
[2026-04-23 18:09:20] [1;33m[TEST][0m repeated connects yield non-deterministic pass/fail
[2026-04-23 18:09:29] [0;31m[FAIL][0m deterministic outcome pass=10 deny=0 (EXPECTED: probabilistic)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_ostracism_shipped.sh` (exit=1, 22s)

```
[2026-04-23 18:09:32] [0;32m[PASS][0m net=1
[2026-04-23 18:09:35] [1;33m[TEST][0m below-threshold peer is evicted on cycle
[2026-04-23 18:09:39] [0;31m[FAIL][0m low-score peer present (EXPECTED: ostracized/evicted)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_pay_it_forward_shipped.sh` (exit=1, 19s)

```
[2026-04-23 18:09:33] [0;32m[PASS][0m net=1
[2026-04-23 18:09:36] [1;33m[TEST][0m pubsub relay accrues forwarding reward
[2026-04-23 18:09:39] [0;31m[FAIL][0m no forwarding reward (EXPECTED: score bump on forward)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_rotating_chairs_shipped.sh` (exit=1, 21s)

```
[2026-04-23 18:09:37] [0;32m[PASS][0m net=1
[2026-04-23 18:09:41] [1;33m[TEST][0m rankings reorder across forced cycles
[2026-04-23 18:09:46] [0;31m[FAIL][0m ranking head static (0) across cycles (EXPECTED: rotation)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_small_circle_shipped.sh` (exit=1, 19s)

```
[2026-04-23 18:09:45] [0;32m[PASS][0m net=1
[2026-04-23 18:09:48] [1;33m[TEST][0m max_peers cap enforced (small-circle)
[2026-04-23 18:09:50] [0;31m[FAIL][0m cap=0 (EXPECTED: small positive cap, e.g. 10)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_polo_scoped_per_network.sh` (exit=1, 52s)

```
create_network_from_file: attempt 1 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 2s
create_network_from_file: attempt 2 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 4s
create_network_from_file: attempt 3 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 6s
create_network_from_file: attempt 4 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 8s
create_network_from_file: attempt 5 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 10s
create_network_from_file: create failed after 5 attempts: {"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}
[2026-04-23 18:10:13] [0;31m[FAIL][0m create X
```

### `test_net_stable_state_shipped.sh` (exit=1, 35s)

```
[2026-04-23 18:10:04] [0;32m[PASS][0m net=1
[2026-04-23 18:10:08] [1;33m[TEST][0m cycles converge peer count toward target
[2026-04-23 18:10:14] [0;31m[FAIL][0m peer count drifted or empty: 0 -> 0 (EXPECTED: C0>=1 AND |ΔC|<=2)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_tithe_shipped.sh` (exit=1, 37s)

```
[2026-04-23 18:10:06] [0;32m[PASS][0m net=1
[2026-04-23 18:10:10] [1;33m[TEST][0m tithe clips accumulated score on cycle
[2026-04-23 18:10:21] [0;31m[FAIL][0m no tithe: 0 -> 0 (EXPECTED: score decrease)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_two_strikes_shipped.sh` (exit=1, 25s)

```
[2026-04-23 18:10:15] [0;32m[PASS][0m net=1
[2026-04-23 18:10:19] [1;33m[TEST][0m two failed attempts evict peer
[2026-04-23 18:10:23] [0;31m[FAIL][0m peer still present after 2 strikes (EXPECTED: evicted)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_whale_hunt_shipped.sh` (exit=1, 13s)

```
[2026-04-23 18:10:25] [0;32m[PASS][0m net=1
[2026-04-23 18:10:28] [1;33m[TEST][0m high-score peer is flagged / taxed
[2026-04-23 18:10:29] [0;31m[FAIL][0m no whale-score rule visible (EXPECTED: rule keyed on high peer_score)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_trust_scoped_per_network.sh` (exit=1, 51s)

```
create_network_from_file: attempt 1 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 2s
create_network_from_file: attempt 2 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 4s
create_network_from_file: attempt 3 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 6s
create_network_from_file: attempt 4 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 8s
create_network_from_file: attempt 5 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 10s
create_network_from_file: create failed after 5 attempts: {"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}
[2026-04-23 18:10:47] [0;31m[FAIL][0m create X
```

### `test_policy_cycle_fill_trust.sh` (exit=1, 21s)

```
==========================================
Policy: cycle × fill_trust
==========================================
[2026-04-23 18:11:12] [0;32m[PASS][0m stack up
[2026-04-23 18:11:12] [1;33m[TEST][0m Apply fill_trust policy on agent-b
load_policy: network_id=1 policy=/tests/fixtures/policies/short_cycle_fill_trust.json (on agent-b)
[2026-04-23 18:11:16] [0;32m[PASS][0m policy loaded (net=1)
[2026-04-23 18:11:16] [1;33m[TEST][0m confirm agent-b starts with 0 trust links
[2026-04-23 18:11:16] [0;32m[PASS][0m trust set empty
[2026-04-23 18:11:16] [1;33m[TEST][0m force cycle
[2026-04-23 18:11:19] [0;32m[PASS][0m cycle forced
[2026-04-23 18:11:19] [1;33m[TEST][0m agent-b logged 'sent trust requests'
[2026-04-23 18:11:20] [0;32m[PASS][0m fill_trust fired
[2026-04-23 18:11:20] [1;33m[TEST][0m agent-a has a pending handshake from agent-b
[2026-04-23 18:11:24] [0;31m[FAIL][0m agent-a pending=0 (want >=1)
Passed: \033[0;32m5\033[0m  Failed: \033[0;31m1\033[0m
```

### `test_policy_cycle_webhook.sh` (exit=1, 20s)

```
==========================================
Policy: cycle × webhook
==========================================
[2026-04-23 18:11:27] [0;32m[PASS][0m stack up
[2026-04-23 18:11:27] [1;33m[TEST][0m start a local webhook sink inside agent-b container
[2026-04-23 18:11:30] [0;32m[PASS][0m sink listening on 127.0.0.1:18080
[2026-04-23 18:11:30] [1;33m[TEST][0m restart agent-b daemon with -webhook flag
[2026-04-23 18:11:30] [0;32m[PASS][0m agent-b relaunched with webhook
[2026-04-23 18:11:35] [1;33m[TEST][0m Apply webhook-on-cycle policy
load_policy: cannot resolve agent-b node_id
[2026-04-23 18:11:37] [0;31m[FAIL][0m load
```

### `test_policy_connect_deny.sh` (exit=1, 49s)

```
==========================================
Policy: connect × deny
==========================================
[2026-04-23 18:10:50] [1;33m[TEST][0m Starting stack
[2026-04-23 18:10:56] [0;32m[PASS][0m stack up
[2026-04-23 18:10:56] [1;33m[TEST][0m Apply deny-all connect policy on agent-b
load_policy: network_id=1 policy=/tests/fixtures/policies/deny_all_connect.json (on agent-b)
[2026-04-23 18:11:02] [0;32m[PASS][0m deny-all policy loaded (net=1)
[2026-04-23 18:11:03] [1;33m[TEST][0m echo under deny-all must fail (timeout or refusal)
[2026-04-23 18:11:11] [0;32m[PASS][0m echo refused/timed out under deny policy (rc=124)
[2026-04-23 18:11:11] [1;33m[TEST][0m agent-b logs syn.port_rejected OR port_rejected OR policy deny
assert_policy_event: agent=agent-b event=connect_deny pattern=syn\.port_rejected\|port %d not allowed\|port_rejected count=0 want>=1
[2026-04-23 18:11:14] [0;31m[FAIL][0m no deny events in agent-b logs (expected under deny-all connect)
[2026-04-23 18:11:14] [1;33m[TEST][0m send-message under deny-all must fail
[2026-04-23 18:11:23] [0;32m[PASS][0m send-message refused/timed out (rc=124)
[2026-04-23 18:11:23] [1;33m[TEST][0m send-file under deny-all must fail
[2026-04-23 18:11:37] [0;32m[PASS][0m send-file refused/timed out (rc=124)

==========================================
Passed: \033[0;32m5\033[0m  Failed: \033[0;31m1\033[0m
==========================================
```

### `test_partition_heal.sh` (exit=1, 73s)

```
==========================================
Partition then heal: queued ops complete
==========================================
[2026-04-23 18:10:38] [0;32m[PASS][0m both agents registered
[2026-04-23 18:10:42] [0;32m[PASS][0m IPs resolved a=172.29.17.20 b=172.29.17.21
[2026-04-23 18:10:42] [1;33m[TEST][0m pre-submit 3 tasks BEFORE partition (worker paused)
[2026-04-23 18:10:46] [0;32m[PASS][0m pre-submitted 3 task ids
[2026-04-23 18:10:46] [1;33m[TEST][0m install partition a<->b
[2026-04-23 18:10:49] [0;32m[PASS][0m partition effective
[2026-04-23 18:10:51] [1;33m[TEST][0m none of the submitted tasks already completed
[2026-04-23 18:10:51] [0;32m[PASS][0m 0/3 completed during split (correct)
[2026-04-23 18:10:51] [1;33m[TEST][0m heal partition
[2026-04-23 18:11:39] [0;31m[FAIL][0m heal did not restore path
```

### `test_policy_datagram_deny.sh` (exit=1, 20s)

```
==========================================
Policy: datagram × deny
==========================================
[2026-04-23 18:11:33] [0;32m[PASS][0m stack up
[2026-04-23 18:11:33] [1;33m[TEST][0m Apply deny-all datagram policy on agent-b
load_policy: network_id=1 policy=/tests/fixtures/policies/deny_all_datagram.json (on agent-b)
[2026-04-23 18:11:37] [0;32m[PASS][0m policy loaded (net=1)
[2026-04-23 18:11:37] [1;33m[TEST][0m send datagram under deny — expect failure / timeout
[2026-04-23 18:11:43] [0;32m[PASS][0m send rejected/timed out (rc=1)
[2026-04-23 18:11:43] [1;33m[TEST][0m agent-b logs datagram rejection
assert_policy_event: agent=agent-b event=datagram_deny pattern=datagram\.port_rejected\|datagram: rejected\|datagram.*not allowed count=0 want>=1
[2026-04-23 18:11:45] [0;31m[FAIL][0m no datagram_deny event observed
Passed: \033[0;32m3\033[0m  Failed: \033[0;31m1\033[0m
```

### `test_policy_join_allow.sh` (exit=1, 14s)

```
==========================================
Policy: join × allow (schema-level)
==========================================
[2026-04-23 18:11:40] [0;32m[PASS][0m stack up
[2026-04-23 18:11:40] [1;33m[TEST][0m Apply allow-join policy on agent-b
load_policy: network_id=1 policy=/tests/fixtures/policies/join_allow.json (on agent-b)
[2026-04-23 18:11:44] [0;32m[PASS][0m policy loaded (net=1)
[2026-04-23 18:11:44] [1;33m[TEST][0m agent-a joining managed network succeeds
[2026-04-23 18:11:45] [0;32m[PASS][0m join succeeded
[2026-04-23 18:11:45] [1;33m[TEST][0m agent-a member list contains agent-a and agent-b
[2026-04-23 18:11:47] [0;31m[FAIL][0m expected >=2 members, got 0
[2026-04-23 18:11:47] [1;33m[TEST][0m FINDING: join event firing not wired in daemon
    (documented in test comment header)
Passed: \033[0;32m3\033[0m  Failed: \033[0;31m1\033[0m
```

### `test_policy_datagram_score.sh` (exit=1, 45s)

```
==========================================
Policy: datagram × score
==========================================
[2026-04-23 18:11:34] [0;32m[PASS][0m stack up
[2026-04-23 18:11:34] [1;33m[TEST][0m Apply score-on-datagram policy on agent-b
load_policy: network_id=1 policy=/tests/fixtures/policies/score_on_datagram.json (on agent-b)
[2026-04-23 18:11:38] [0;32m[PASS][0m policy loaded (net=1)
[2026-04-23 18:11:38] [1;33m[TEST][0m baseline score (may be empty for fresh peer)
[2026-04-23 18:11:39] [0;32m[PASS][0m baseline score=0
[2026-04-23 18:11:39] [1;33m[TEST][0m drive 5 datagrams from agent-a
[2026-04-23 18:12:08] [0;32m[PASS][0m sent
[2026-04-23 18:12:11] [1;33m[TEST][0m peer score increased
[2026-04-23 18:12:12] [0;31m[FAIL][0m score not increased (base=0 new=0)
Passed: \033[0;32m4\033[0m  Failed: \033[0;31m1\033[0m
```

### `test_resilience.sh` (exit=1, 1232s)

```
==========================================
Resilience / restart / concurrency tests
==========================================
[2026-04-23 17:52:24] [1;33m[TEST][0m 50 parallel echo roundtrips from agent-a to agent-b
[2026-04-23 17:52:30] [0;32m[PASS][0m 50/50 echo roundtrips ok
[2026-04-23 17:52:30] [1;33m[TEST][0m restart agent-b and confirm it re-registers
[2026-04-23 17:52:39] [0;32m[PASS][0m agent-b re-registered (was 2, now 2)
[2026-04-23 17:52:39] [1;33m[TEST][0m echo to agent-b recovers after restart (poll ≤4min)
[2026-04-23 18:12:34] [0;31m[FAIL][0m post-restart echo never recovered in 4 minutes
[2026-04-23 18:12:34] [1;33m[TEST][0m restart rendezvous and confirm agents reconnect (≤4min)
[2026-04-23 18:12:37] [0;32m[PASS][0m both agents reconnected after rendezvous restart (total_nodes=3, ~1×5s)
[2026-04-23 18:12:37] [1;33m[TEST][0m agent-a process survived 60s+ of activity
[2026-04-23 18:12:39] [0;32m[PASS][0m agent-a pid 1 alive, RSS 15596 KB
[2026-04-23 18:12:39] [1;33m[TEST][0m pulse endpoint shows non-zero total_requests
[2026-04-23 18:12:40] [0;32m[PASS][0m pulse total_requests=1594 samples=4
[2026-04-23 18:12:40] [1;33m[TEST][0m concurrent send-message agent-a→b and agent-b→a
[2026-04-23 18:12:50] [0;32m[PASS][0m concurrent bidirectional send-message completed
[2026-04-23 18:12:50] [1;33m[TEST][0m agent logs free of panic/fatal
[2026-04-23 18:12:51] [0;32m[PASS][0m no panic/fatal/race in recent logs

==========================================
Resilience Test Summary
==========================================
Passed: [0;32m7[0m
Failed: [0;31m1[0m
==========================================
```

### `test_sec_ipc_exhaustion.sh` (exit=1, 15s)

```
[2026-04-23 18:12:54] [1;33m[TEST][0m fresh stack
[2026-04-23 18:13:01] [1;33m[TEST][0m attempt 10k concurrent IPC connections
successfully opened IPC conns: 4344
[2026-04-23 18:13:03] [1;33m[TEST][0m daemon still responds to pilotctl info from a NEW connection
[2026-04-23 18:13:05] [0;32m[PASS][0m daemon responsive after IPC exhaustion attempt
[2026-04-23 18:13:05] [1;33m[TEST][0m per-client cap enforced (OPEN should be well below 10000)
[2026-04-23 18:13:05] [0;31m[FAIL][0m no IPC cap detected (4344 conns opened) — see P2-002
[2026-04-23 18:13:05] [1;33m[TEST][0m no agent-a panic on accept() exhaustion
[2026-04-23 18:13:05] [0;32m[PASS][0m no panic/EMFILE in logs

Passed: 2  Failed: 1
```

### `test_receiver_sigkill_midfile.sh` (exit=1, 66s)

```
==========================================
SIGKILL agent-b mid-send-file
==========================================
[2026-04-23 18:12:30] [0;32m[PASS][0m both agents registered
[2026-04-23 18:12:32] [1;33m[TEST][0m prepare 4 MiB payload on agent-a
[2026-04-23 18:12:32] [0;32m[PASS][0m payload ready (3c49e459c8fce9f370064535eaac717de3b6cd72a680fb25449617add8724609)
[2026-04-23 18:12:32] [1;33m[TEST][0m start send-file in background, then SIGKILL agent-b
[2026-04-23 18:12:38] [0;32m[PASS][0m agent-b SIGKILL'd mid-transfer
[2026-04-23 18:12:38] [1;33m[TEST][0m send-file on agent-a returns (not hung)
[2026-04-23 18:12:41] [0;32m[PASS][0m send-file returned (rc=1)
[2026-04-23 18:12:41] [1;33m[TEST][0m sender did NOT claim success after receiver died
[2026-04-23 18:12:41] [0;32m[PASS][0m no false-success ack
[2026-04-23 18:12:41] [1;33m[TEST][0m no panic/fatal on agent-a
[2026-04-23 18:12:42] [0;32m[PASS][0m clean logs on a
[2026-04-23 18:12:42] [1;33m[TEST][0m restart agent-b
[2026-04-23 18:12:46] [0;32m[PASS][0m agent-b re-registered
[2026-04-23 18:12:46] [1;33m[TEST][0m no silent-corrupt partial file on agent-b
[2026-04-23 18:12:47] [0;32m[PASS][0m no partial file left (acceptable)
[2026-04-23 18:12:47] [1;33m[TEST][0m fresh send-file post-restart completes with sha match
[2026-04-23 18:13:26] [0;31m[FAIL][0m post-restart send mismatch src=f8a343b79b2e... dst=...

Passed: 8  Failed: 1
```

### `test_sec_trust_grant_forgery.sh` (exit=1, 21s)

```
[2026-04-23 18:13:18] [1;33m[TEST][0m fresh stack
[2026-04-23 18:13:23] [1;33m[TEST][0m stand up a fresh sybil daemon identity inside agent-a
forger node_id: 
[2026-04-23 18:13:27] [0;31m[FAIL][0m forger daemon didn't register
time=2026-04-24T01:13:24.303Z level=INFO msg="daemon start: email address required: use -email you@example.com"
[2026-04-23 18:13:28] [1;33m[TEST][0m forger attempts trust grant to agent-b (unrequested)
[2026-04-23 18:13:31] [1;33m[TEST][0m agent-b does NOT auto-trust the forger
[2026-04-23 18:13:32] [0;32m[PASS][0m forger is NOT in trusted list
[2026-04-23 18:13:32] [1;33m[TEST][0m forger with a tampered identity file cannot impersonate
[2026-04-23 18:13:36] [1;33m[TEST][0m agent-b logs show signature verification guard
[2026-04-23 18:13:37] [1;33m[TEST][0m no explicit verification-failure log seen — trust path handled rejection instead
[2026-04-23 18:13:37] [1;33m[TEST][0m agent-b pending handshake count bounded
[2026-04-23 18:13:38] [0;32m[PASS][0m pending queue bounded (0)

Passed: 2  Failed: 1
```

### `test_ping_ghost_peer.sh` (exit=1, 180s)

```
==========================================
Ping / send / submit to a ghost peer
==========================================
[2026-04-23 18:10:47] [1;33m[TEST][0m fresh stack
[2026-04-23 18:10:54] [0;32m[PASS][0m both agents registered
[2026-04-23 18:10:54] [1;33m[TEST][0m warm-up ping a->b so agent-a has cached crypto+endpoint
[2026-04-23 18:10:56] [0;32m[PASS][0m tunnel warm
[2026-04-23 18:10:56] [1;33m[TEST][0m SIGKILL agent-b (no graceful unregister)
[2026-04-23 18:10:59] [0;32m[PASS][0m agent-b is dead
[2026-04-23 18:10:59] [1;33m[TEST][0m ping a->b (ghost) fails within --timeout 4s
[2026-04-23 18:11:05] [0;32m[PASS][0m ping failed in 6s (rc=1)
[2026-04-23 18:11:05] [1;33m[TEST][0m send-message a->b (ghost) fails with clear error
[2026-04-23 18:11:15] [0;32m[PASS][0m send-message refused (rc=124)
[2026-04-23 18:11:15] [1;33m[TEST][0m task submit a->b (ghost) — must not report completion
[2026-04-23 18:11:31] [0;32m[PASS][0m submit to ghost peer refused at the front door
[2026-04-23 18:11:31] [1;33m[TEST][0m agent-a has no panic/fatal after ghost attempts
[2026-04-23 18:11:31] [0;32m[PASS][0m agent-a log clean
[2026-04-23 18:11:31] [1;33m[TEST][0m restart agent-b; ping a->b works again
[2026-04-23 18:13:47] [0;31m[FAIL][0m a's state poisoned — ping still fails after b came back

==========================================
Ghost-peer summary
==========================================
Passed: [0;32m7[0m
Failed: [0;31m1[0m
==========================================
```

### `test_sender_sigkill_midfile.sh` (exit=1, 51s)

```
==========================================
SIGKILL agent-a mid-send-file
==========================================
[2026-04-23 18:13:49] [0;32m[PASS][0m both agents registered
[2026-04-23 18:13:52] [1;33m[TEST][0m prepare 4 MiB payload on agent-a
[2026-04-23 18:13:59] [0;32m[PASS][0m payload ready
[2026-04-23 18:13:59] [1;33m[TEST][0m start send-file BG, SIGKILL agent-a
[2026-04-23 18:14:10] [0;32m[PASS][0m agent-a dead mid-transfer
[2026-04-23 18:14:10] [1;33m[TEST][0m agent-b has no falsely-complete partial file (wait up to 60s)
[2026-04-23 18:14:14] [0;32m[PASS][0m agent-b cleaned up partial
[2026-04-23 18:14:14] [1;33m[TEST][0m no panic/fatal on agent-b
[2026-04-23 18:14:14] [0;32m[PASS][0m clean logs
[2026-04-23 18:14:14] [1;33m[TEST][0m agent-b daemon responsive
[2026-04-23 18:14:16] [0;32m[PASS][0m daemon responsive
[2026-04-23 18:14:16] [1;33m[TEST][0m restart agent-a; fresh send-file completes
[2026-04-23 18:14:20] [0;32m[PASS][0m agent-a re-registered
[2026-04-23 18:14:29] [0;31m[FAIL][0m post-restart send mismatch

Passed: 7  Failed: 1
```

### `test_ring4_routing.sh` (exit=1, 125s)

```
    01:13:47.628292843 hop host=agent-b path=start,agent-b ttl=2
    resolved "agent-c" → 0:0000.0000.0003
    {
      "ack": "ACK JSON 56 bytes",
      "bytes": 56,
      "target": "0:0000.0000.0003",
      "type": "json"
    }
  === c ring.log ===
    01:13:49.084659594 hop host=agent-c path=start,agent-b,agent-c ttl=1
    resolved "agent-d" → 0:0000.0000.0002
    {
      "ack": "ACK JSON 64 bytes",
      "bytes": 64,
      "target": "0:0000.0000.0002",
      "type": "json"
    }
  === d ring.log ===
    01:13:50.663962428 hop host=agent-d path=start,agent-b,agent-c,agent-d ttl=0
[2026-04-23 18:14:37] [1;33m[TEST][0m final path shows all four hops in order
[2026-04-23 18:14:37] [0;31m[FAIL][0m path wrong: got '' want 'start,agent-b,agent-c,agent-d,agent-a'
[2026-04-23 18:14:37] [1;33m[TEST][0m no panics/fatals
[2026-04-23 18:14:38] [0;32m[PASS][0m clean logs

==========================================
Ring-4 routing summary
==========================================
Passed: [0;32m4[0m
Failed: [0;31m2[0m
==========================================
```

### `test_register_identity_new_endpoint.sh` (exit=1, 156s)

```
==========================================
Identity re-register with new endpoint
==========================================
[2026-04-23 18:12:38] [0;32m[PASS][0m agents up
[2026-04-23 18:12:40] [0;32m[PASS][0m initial endpoint: 172.29.16.21:4000
[2026-04-23 18:12:40] [1;33m[TEST][0m stop agent-b, bring it back with a different listen port
Error response from daemon: container dd6a3cb9bb8c073ddea7d0c8f95ecea66db179ba6ad5199aff3622460da624a9 is not running
[2026-04-23 18:14:47] [0;32m[PASS][0m new endpoint seen in registry: 172.29.16.21:4000
[2026-04-23 18:14:47] [1;33m[TEST][0m registry entry superseded: new endpoint reflects :4001
[2026-04-23 18:14:47] [0;31m[FAIL][0m endpoint still 172.29.16.21:4000 (expected suffix :4001, was 172.29.16.21:4000)
[2026-04-23 18:14:47] [1;33m[TEST][0m node_id remains the same (same identity)
[2026-04-23 18:14:47] [0;31m[FAIL][0m node_id changed: 2 -> 
[2026-04-23 18:14:47] [1;33m[TEST][0m only one registry entry for this identity (no stale duplicate)
[2026-04-23 18:14:50] [0;31m[FAIL][0m registry has 3 nodes — stale duplicate suspected
[2026-04-23 18:14:50] [1;33m[TEST][0m agent-a can still reach agent-b at the new endpoint
[2026-04-23 18:15:03] [0;31m[FAIL][0m ping failed after endpoint change — a may be caching old endpoint
[2026-04-23 18:15:03] [1;33m[TEST][0m no panic/fatal
[2026-04-23 18:15:04] [0;32m[PASS][0m clean logs

Passed: 4  Failed: 4
```

### `test_task_executor.sh` (exit=1, 36s)

```
[2026-04-23 18:15:55] [1;33m[TEST][0m start auto-accept worker on agent-b
[2026-04-23 18:16:00] [0;32m[PASS][0m worker started on agent-b
[2026-04-23 18:16:00] [1;33m[TEST][0m agent-a submits T1 (polo should allow)
[2026-04-23 18:16:01] [0;32m[PASS][0m T1 submitted: 14f8b723-2bf7-83f0-4190-03fc98fb61ee
[2026-04-23 18:16:02] [1;33m[TEST][0m T1 reaches completed/succeeded on submitter
[2026-04-23 18:16:02] [0;32m[PASS][0m submitter sees T1 status=SUCCEEDED
[2026-04-23 18:16:02] [1;33m[TEST][0m pilotctl task result returns correlated payload
[2026-04-23 18:16:03] [0;32m[PASS][0m T1 result correlates: "done: compute-fibonacci"
[2026-04-23 18:16:04] [1;33m[TEST][0m polo gate rejects second a -> b submit with too-low score
[2026-04-23 18:16:04] [0;31m[FAIL][0m polo gate did not block (accepted=false message=Task rejected by polo gate: submitter polo below receiver polo)
[2026-04-23 18:16:04] [1;33m[TEST][0m enable-tasks on agent-a for reverse flow
[2026-04-23 18:16:07] [1;33m[TEST][0m agent-b submits B1 to agent-a (should be allowed)
[2026-04-23 18:16:08] [0;32m[PASS][0m B1 submitted: ad003dad-cd63-9472-e12d-7d8711cd3489
[2026-04-23 18:16:12] [1;33m[TEST][0m B1 completes on agent-b
[2026-04-23 18:16:12] [0;32m[PASS][0m agent-b sees B1 status=SUCCEEDED
[2026-04-23 18:16:12] [1;33m[TEST][0m balanced exchange restores polo, a can submit again
[2026-04-23 18:16:13] [0;32m[PASS][0m post-balance submit accepted: 09bb8033-a171-f23a-d260-76662830cadb
[2026-04-23 18:16:14] [1;33m[TEST][0m post-balance task result correlates
[2026-04-23 18:16:14] [0;32m[PASS][0m post-balance result correlates
[2026-04-23 18:16:15] [1;33m[TEST][0m pilotctl task result on missing id returns clean error
[2026-04-23 18:16:15] [0;32m[PASS][0m missing-id handled cleanly
[2026-04-23 18:16:15] [1;33m[TEST][0m no panics/fatals in daemon logs
[2026-04-23 18:16:16] [0;32m[PASS][0m clean logs

==========================================
Task-executor test summary
==========================================
Passed: [0;32m12[0m
Failed: [0;31m1[0m
==========================================
```

### `test_sender_clean_restart_midflight.sh` (exit=1, 187s)

```
==========================================
Clean restart of agent-a mid-flight
==========================================
[2026-04-23 18:13:48] [0;32m[PASS][0m both agents registered
[2026-04-23 18:13:55] [1;33m[TEST][0m submit 3 tasks then restart agent-a cleanly
[2026-04-23 18:14:10] [0;32m[PASS][0m agent-a re-registered post-restart
[2026-04-23 18:14:10] [1;33m[TEST][0m agent-a task list --type submitted still works post-restart
[2026-04-23 18:14:12] [0;32m[PASS][0m task list ok
[2026-04-23 18:14:12] [1;33m[TEST][0m fresh task submit post-restart completes
[2026-04-23 18:16:35] [0;31m[FAIL][0m fresh task stuck post-restart (status=)
[2026-04-23 18:16:35] [1;33m[TEST][0m fresh send-file post-restart
[2026-04-23 18:16:39] [0;32m[PASS][0m file sha match post-restart
[2026-04-23 18:16:39] [1;33m[TEST][0m no panic/fatal
[2026-04-23 18:16:40] [0;32m[PASS][0m clean logs

Passed: 5  Failed: 1
```

### `test_splitbrain_divergence.sh` (exit=1, 143s)

```
==========================================
Split-brain divergence (2 rendezvous)
==========================================
[2026-04-23 18:14:31] [1;33m[TEST][0m Starting splitbrain stack
[2026-04-23 18:16:44] [1;33m[TEST][0m rendezvous-1 sees 2 agents
[2026-04-23 18:16:45] [0;31m[FAIL][0m rendezvous-1 sees 3 nodes — expected 2 (partition leaked)
[2026-04-23 18:16:45] [1;33m[TEST][0m rendezvous-2 sees 2 agents
[2026-04-23 18:16:46] [0;32m[PASS][0m rendezvous-2 has exactly 2 nodes (agent-c,d)
[2026-04-23 18:16:46] [1;33m[TEST][0m agent-a cannot lookup agent-c (cross-partition)
[2026-04-23 18:16:47] [0;32m[PASS][0m agent-a cannot resolve agent-c (partition holds)
[2026-04-23 18:16:47] [1;33m[TEST][0m agent-c cannot lookup agent-a (cross-partition)
[2026-04-23 18:16:48] [0;32m[PASS][0m agent-c cannot resolve agent-a (partition holds)
[2026-04-23 18:16:48] [1;33m[TEST][0m agent-a can lookup agent-b (same side)
[2026-04-23 18:16:49] [0;32m[PASS][0m same-side lookup works (agent-b=0:0000.0000.0002)
[2026-04-23 18:16:49] [1;33m[TEST][0m agent-c can lookup agent-d (same side)
[2026-04-23 18:16:49] [0;32m[PASS][0m same-side lookup works (agent-d=0:0000.0000.0001)
[2026-04-23 18:16:49] [1;33m[TEST][0m no panic/fatal in any daemon log
[2026-04-23 18:16:50] [0;32m[PASS][0m clean logs

==========================================
Split-brain divergence summary
==========================================
Passed: [0;32m6[0m
Failed: [0;31m1[0m
==========================================
```

### `test_tasks_and_edge.sh` (exit=1, 35s)

```
[2026-04-23 18:17:10] [0;32m[PASS][0m task queue ok
[2026-04-23 18:17:10] [1;33m[TEST][0m send-message type=json
[2026-04-23 18:17:11] [0;32m[PASS][0m send-message JSON ack ok
[2026-04-23 18:17:11] [1;33m[TEST][0m send-message type=binary
[2026-04-23 18:17:12] [0;32m[PASS][0m send-message binary ack ok
[2026-04-23 18:17:12] [1;33m[TEST][0m send-file and verify byte count
[2026-04-23 18:17:14] [0;32m[PASS][0m send-file 10240 bytes acked (10240)
[2026-04-23 18:17:14] [1;33m[TEST][0m inbox has at least 2 message entries (JSON + binary text)
[2026-04-23 18:17:15] [0;32m[PASS][0m inbox has 2 entries
[2026-04-23 18:17:15] [1;33m[TEST][0m received/ has the binary file delivered by send-file
[2026-04-23 18:17:16] [0;32m[PASS][0m received/ has 1 file(s)
[2026-04-23 18:17:16] [1;33m[TEST][0m inbox --clear empties the inbox
[2026-04-23 18:17:17] [0;32m[PASS][0m inbox cleared (was 2 now 0)
[2026-04-23 18:17:18] [1;33m[TEST][0m ping unknown hostname returns clear error
[2026-04-23 18:17:18] [0;32m[PASS][0m unknown hostname rejected cleanly
[2026-04-23 18:17:18] [1;33m[TEST][0m send missing --data flag returns invalid_argument
[2026-04-23 18:17:19] [0;32m[PASS][0m missing --data rejected with invalid_argument
[2026-04-23 18:17:19] [1;33m[TEST][0m set-hostname with bad characters rejected
[2026-04-23 18:17:20] [0;32m[PASS][0m invalid hostname rejected (status=error)
[2026-04-23 18:17:20] [1;33m[TEST][0m lookup of nonexistent node_id returns error
[2026-04-23 18:17:21] [0;32m[PASS][0m lookup of ghost node fails cleanly
[2026-04-23 18:17:21] [1;33m[TEST][0m pilotctl version
[2026-04-23 18:17:22] [0;32m[PASS][0m version: dev

==========================================
Tasks/Edge Test Summary
==========================================
Passed: [0;32m18[0m
Failed: [0;31m1[0m
==========================================
```

### `test_webhook_agent_registered.sh` (exit=1, 47s)

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
[2026-04-23 18:17:50] [1;33m[TEST][0m at least 2 registration webhooks after 2 agent restarts (got delta=0)
[2026-04-23 18:17:50] [0;31m[FAIL][0m expected delta>=2 got 0
[2026-04-23 18:17:50] [1;33m[TEST][0m canonical 'agent.registered' event name
service "webhook-sink" is not running
test_webhook_agent_registered.sh: line 72: [: : integer expression expected
[2026-04-23 18:17:50] [0;31m[FAIL][0m agent.registered NOT wired — daemon emits 'node.registered'/'node.reregistered' instead
Passed: 0  Failed: 2
```

### `test_webhook_file_delivered.sh` (exit=1, 36s)

```
[2026-04-23 18:17:17] [1;33m[TEST][0m fresh webhooks stack
[2026-04-23 18:17:26] [0;32m[PASS][0m both agents registered
[2026-04-23 18:17:26] [1;33m[TEST][0m configure agent-a webhook -> http://webhook-sink:18080/a
[2026-04-23 18:17:28] [0;32m[PASS][0m webhook set on agent-a
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
[2026-04-23 18:17:41] [1;33m[TEST][0m agent-a sends file to agent-b
[2026-04-23 18:17:41] [0;32m[PASS][0m send-file ok
service "webhook-sink" is not running
[2026-04-23 18:17:50] [1;33m[TEST][0m exactly one file.delivered webhook (delta=0)
[2026-04-23 18:17:50] [0;31m[FAIL][0m expected delta=1 got delta=0 (event likely not wired in pkg/daemon/webhook emit sites)

==========================================
Passed: 3  Failed: 1
==========================================
```

### `test_task_sequential_burst.sh` (exit=1, 68s)

```
==========================================
Task sequential-burst round-trip (5 tasks)
==========================================
[2026-04-23 18:16:47] [1;33m[TEST][0m Starting p2p stack (clean)
[2026-04-23 18:16:56] [0;32m[PASS][0m both agents registered
[2026-04-23 18:16:58] [1;33m[TEST][0m start auto-accept worker on agent-b
[2026-04-23 18:17:01] [0;32m[PASS][0m worker started
[2026-04-23 18:17:02] [1;33m[TEST][0m submit 5 tasks a->b with reverse rebalance after each
[2026-04-23 18:17:43] [0;32m[PASS][0m 5 tasks submitted + rebalanced
[2026-04-23 18:17:43] [1;33m[TEST][0m all 5 tasks COMPLETED on agent-a
  burst-5 (61388b20-dcd0-e291-8fdf-34eca6f7e65f) status=ACCEPTED
[2026-04-23 18:17:46] [0;31m[FAIL][0m only 4/5 COMPLETED
[2026-04-23 18:17:46] [1;33m[TEST][0m each result correlates to its burst-i description
[2026-04-23 18:17:52] [0;32m[PASS][0m all 5 results correlate
[2026-04-23 18:17:52] [1;33m[TEST][0m submitted list preserves burst order
[2026-04-23 18:17:53] [0;32m[PASS][0m submitted list is in burst-1..burst-5 order
[2026-04-23 18:17:53] [1;33m[TEST][0m worker accept log shows burst-1..burst-5 in submission order
[2026-04-23 18:17:54] [0;32m[PASS][0m worker accepted in submission order
[2026-04-23 18:17:54] [1;33m[TEST][0m no panics/fatals in daemon logs
[2026-04-23 18:17:54] [0;32m[PASS][0m clean logs

==========================================
Sequential-burst test summary
==========================================
Passed: [0;32m7[0m
Failed: [0;31m1[0m
==========================================
```

### `test_webhook_exactly_once_on_restart.sh` (exit=1, 48s)

```
[2026-04-23 18:17:26] [0;32m[PASS][0m agent-a webhook set
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
[2026-04-23 18:17:39] [1;33m[TEST][0m submit T1 a->b
[2026-04-23 18:17:40] [0;32m[PASS][0m T1=fc2afc3c-fe62-ff10-76fa-ce6b204c5a89
[2026-04-23 18:17:40] [1;33m[TEST][0m agent-b accepts T1, no results yet
[2026-04-23 18:17:43] [0;32m[PASS][0m status=ACCEPTED
[2026-04-23 18:17:43] [1;33m[TEST][0m restart agent-b between ACCEPTED and SUCCEEDED
[2026-04-23 18:17:44] [0;32m[PASS][0m agent-b back online
[2026-04-23 18:17:50] [0;32m[PASS][0m T1 final status=SUCCEEDED
service "webhook-sink" is not running
[2026-04-23 18:17:58] [1;33m[TEST][0m exactly ONE task.completed webhook after restart (delta=0)
[2026-04-23 18:17:58] [0;31m[FAIL][0m NO DELIVERY: delta=0 — event likely not wired, or lost during restart
Passed: 5  Failed: 1
```

### `test_webhook_message_received.sh` (exit=1, 46s)

```
[2026-04-23 18:17:33] [0;32m[PASS][0m both agents registered
[2026-04-23 18:17:33] [1;33m[TEST][0m configure agent-b webhook
[2026-04-23 18:17:34] [0;32m[PASS][0m webhook set
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
[2026-04-23 18:17:49] [1;33m[TEST][0m agent-a sends exactly one message to agent-b
[2026-04-23 18:17:50] [0;32m[PASS][0m send-message ok
service "webhook-sink" is not running
[2026-04-23 18:18:02] [1;33m[TEST][0m exactly one message.received webhook (delta=0)
[2026-04-23 18:18:02] [0;31m[FAIL][0m expected delta=1 got 0
Passed: 3  Failed: 1
```

### `test_webhook_pubsub_published.sh` (exit=1, 43s)

```
[2026-04-23 18:17:35] [0;32m[PASS][0m agent-b webhook set
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
[2026-04-23 18:17:51] [1;33m[TEST][0m agent-a publishes one event to agent-b on topic 'sensor/wh'
[2026-04-23 18:17:51] [0;32m[PASS][0m publish ok
service "webhook-sink" is not running
[2026-04-23 18:18:04] [1;33m[TEST][0m exactly one pubsub.published webhook (delta=0)
[2026-04-23 18:18:04] [0;31m[FAIL][0m expected delta=1 got 0
Passed: 2  Failed: 1
```

### `test_webhook_polo_updated.sh` (exit=1, 46s)

```
[2026-04-23 18:17:36] [0;32m[PASS][0m webhooks set
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
[2026-04-23 18:17:51] [1;33m[TEST][0m submit one task to trigger a polo delta
service "webhook-sink" is not running
[2026-04-23 18:18:05] [1;33m[TEST][0m exactly one polo.updated webhook (delta=0)
[2026-04-23 18:18:05] [0;31m[FAIL][0m expected delta=1 got 0 (event likely not wired)
Passed: 1  Failed: 1
```

### `test_webhook_task_completed.sh` (exit=1, 44s)

```
[2026-04-23 18:17:37] [0;32m[PASS][0m both agents registered
[2026-04-23 18:17:37] [0;32m[PASS][0m agent-a webhook set (submitter observes completion)
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
[2026-04-23 18:17:53] [1;33m[TEST][0m agent-a submits one task, waits for completion
[2026-04-23 18:17:54] [0;32m[PASS][0m task reached status=SUCCEEDED
service "webhook-sink" is not running
[2026-04-23 18:18:06] [1;33m[TEST][0m exactly one task.completed webhook (delta=0)
[2026-04-23 18:18:06] [0;31m[FAIL][0m expected delta=1 got 0 (event likely not wired)
Passed: 3  Failed: 1
```

### `test_webhook_tunnel_established.sh` (exit=1, 38s)

```
[2026-04-23 18:18:00] [0;32m[PASS][0m webhooks set
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
[2026-04-23 18:18:11] [1;33m[TEST][0m agent-a pings agent-b (warms tunnel)
[2026-04-23 18:18:13] [0;32m[PASS][0m ping ok
service "webhook-sink" is not running
[2026-04-23 18:18:25] [1;33m[TEST][0m at least 2 tunnel.established webhooks (one per side) (delta=0)
[2026-04-23 18:18:25] [0;31m[FAIL][0m expected delta>=2 got 0
Passed: 2  Failed: 1
```

