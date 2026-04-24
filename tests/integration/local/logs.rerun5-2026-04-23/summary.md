# Integration test run summary

- Run duration: 2549s
- Workers: 6
- Tests: 231 (pass=159, fail=72)

| Status | Test | Duration | Exit |
|--------|------|----------|------|
| FAIL | `test_resilience.sh` | 1217s | 1 |
| FAIL | `test_dur_steady_10min.sh` | 609s | 1 |
| FAIL | `test_dur_steady_compressed_24h.sh` | 304s | 1 |
| FAIL | `test_cli.sh` | 274s | 1 |
| FAIL | `test_size_task_result_10mb.sh` | 204s | 1 |
| FAIL | `test_chaos_loss30_all_ops.sh` | 153s | 1 |
| FAIL | `test_force_relay_task.sh` | 121s | 1 |
| FAIL | `test_rendezvous_restart_midflight.sh` | 111s | 1 |
| FAIL | `test_gateway_http_message.sh` | 92s | 1 |
| FAIL | `test_splitbrain_heal.sh` | 82s | 1 |
| FAIL | `test_net_mutual_admiration_shipped.sh` | 76s | 1 |
| FAIL | `test_beacon_restart_midflight.sh` | 75s | 1 |
| FAIL | `test_force_relay_pubsub.sh` | 65s | 1 |
| FAIL | `test_dur_shortcycle_policy_1m.sh` | 64s | 1 |
| FAIL | `test_ring4_routing.sh` | 61s | 1 |
| FAIL | `test_midrekey_task_results.sh` | 60s | 1 |
| FAIL | `test_fanin_3agents_tasks.sh` | 59s | 1 |
| FAIL | `test_webhook_trust_changed.sh` | 48s | 1 |
| FAIL | `test_partition_heal.sh` | 46s | 1 |
| FAIL | `test_chaos_packet_loss.sh` | 44s | 1 |
| FAIL | `test_ping_ghost_peer.sh` | 43s | 1 |
| FAIL | `test_net_data_exchange_policy_shipped.sh` | 38s | 1 |
| FAIL | `test_policy_datagram_score.sh` | 37s | 1 |
| FAIL | `test_webhook_polo_updated.sh` | 37s | 1 |
| FAIL | `test_net_polo_scoped_per_network.sh` | 35s | 1 |
| FAIL | `test_net_trust_scoped_per_network.sh` | 35s | 1 |
| FAIL | `test_policy_connect_deny.sh` | 35s | 1 |
| FAIL | `test_webhook_message_received.sh` | 34s | 1 |
| FAIL | `test_webhook_tunnel_established.sh` | 34s | 1 |
| FAIL | `test_sender_clean_restart_midflight.sh` | 28s | 1 |
| FAIL | `test_webhook_pubsub_published.sh` | 27s | 1 |
| FAIL | `test_race_sendfile_rekey.sh` | 23s | 1 |
| FAIL | `test_gateway_trust_grant.sh` | 18s | 1 |
| FAIL | `test_force_relay_send_file.sh` | 17s | 1 |
| FAIL | `test_chaos_delay200_all_ops.sh` | 16s | 1 |
| FAIL | `test_sec_trust_grant_forgery.sh` | 16s | 1 |
| FAIL | `test_policy_join_score.sh` | 14s | 1 |
| FAIL | `test_task_executor.sh` | 14s | 1 |
| FAIL | `test_partition_midflight.sh` | 13s | 1 |
| FAIL | `test_policy_cycle_webhook.sh` | 13s | 1 |
| FAIL | `test_policy_datagram_deny.sh` | 13s | 1 |
| FAIL | `test_tasks_and_edge.sh` | 13s | 1 |
| FAIL | `test_net_anti_camping_shipped.sh` | 12s | 1 |
| FAIL | `test_net_burnout_shipped.sh` | 12s | 1 |
| FAIL | `test_net_golden_hour_shipped.sh` | 11s | 1 |
| FAIL | `test_net_gossip_tax_shipped.sh` | 11s | 1 |
| FAIL | `test_net_high_trust_society_shipped.sh` | 11s | 1 |
| FAIL | `test_net_tithe_shipped.sh` | 11s | 1 |
| FAIL | `test_policy_cycle_evict.sh` | 11s | 1 |
| FAIL | `test_beacon_ping.sh` | 10s | 1 |
| FAIL | `test_policy_cycle_fill_trust.sh` | 10s | 1 |
| FAIL | `test_disk_full_receiver.sh` | 9s | 1 |
| FAIL | `test_net_half_life_shipped.sh` | 9s | 1 |
| FAIL | `test_net_isolation_policy_scoping.sh` | 9s | 1 |
| FAIL | `test_net_karma_ledger_shipped.sh` | 9s | 1 |
| FAIL | `test_policy_join_allow.sh` | 9s | 1 |
| FAIL | `test_net_cooling_off_shipped.sh` | 8s | 1 |
| FAIL | `test_net_gift_economy_shipped.sh` | 8s | 1 |
| FAIL | `test_sec_ipc_exhaustion.sh` | 8s | 1 |
| FAIL | `test_nat_rendezvous_natted.sh` | 7s | 1 |
| FAIL | `test_net_cross_network_traffic_denied.sh` | 7s | 1 |
| FAIL | `test_net_lottery_shipped.sh` | 7s | 1 |
| FAIL | `test_net_meritocracy_rating_shipped.sh` | 7s | 1 |
| FAIL | `test_net_pay_it_forward_shipped.sh` | 7s | 1 |
| FAIL | `test_net_rotating_chairs_shipped.sh` | 7s | 1 |
| FAIL | `test_net_whale_hunt_shipped.sh` | 7s | 1 |
| FAIL | `test_net_cold_shoulder_shipped.sh` | 6s | 1 |
| FAIL | `test_net_meritocracy_shipped.sh` | 6s | 1 |
| FAIL | `test_net_small_circle_shipped.sh` | 6s | 1 |
| FAIL | `test_net_stable_state_shipped.sh` | 6s | 1 |
| FAIL | `test_register_identity_new_endpoint.sh` | 6s | 1 |
| FAIL | `test_net_join_deny_per_network.sh` | 5s | 1 |
| PASS | `test_dur_idle_10min.sh` | 604s | 0 |
| PASS | `test_sec_rekey_flood.sh` | 299s | 0 |
| PASS | `test_size_file_100mb.sh` | 137s | 0 |
| PASS | `test_policy_shipped_configs.sh` | 103s | 0 |
| PASS | `test_nat_conntrack_timeout.sh` | 84s | 0 |
| PASS | `test_task_accept_expiry.sh` | 78s | 0 |
| PASS | `test_receiver_sigkill_midtask.sh` | 77s | 0 |
| PASS | `test_race_polo_read_write.sh` | 76s | 0 |
| PASS | `test_nat_address_restricted.sh` | 73s | 0 |
| PASS | `test_nat_full_cone.sh` | 66s | 0 |
| PASS | `test_dur_idle_60s.sh` | 64s | 0 |
| PASS | `test_dur_periodic_60s.sh` | 63s | 0 |
| PASS | `test_nat_udp_blocked.sh` | 58s | 0 |
| PASS | `test_nat_restricted_cone.sh` | 57s | 0 |
| PASS | `test_nat_dual_symmetric.sh` | 50s | 0 |
| PASS | `test_size_file_50mb.sh` | 47s | 0 |
| PASS | `test_net_grudge_match_shipped.sh` | 43s | 0 |
| PASS | `test_sec_sybil_reputation.sh` | 40s | 0 |
| PASS | `test_nat_hairpin.sh` | 39s | 0 |
| PASS | `test_nat_symmetric.sh` | 39s | 0 |
| PASS | `test_pubsub_fanout.sh` | 38s | 0 |
| PASS | `test_nat_cgn.sh` | 37s | 0 |
| PASS | `test_webhook_agent_registered.sh` | 37s | 0 |
| PASS | `test_webhook_exactly_once_on_restart.sh` | 34s | 0 |
| PASS | `test_sender_sigkill_midfile.sh` | 32s | 0 |
| PASS | `test_race_register_lookup.sh` | 31s | 0 |
| PASS | `test_sec_replay_after_rekey.sh` | 31s | 0 |
| PASS | `test_nat_egress_443_only.sh` | 30s | 0 |
| PASS | `test_nat_partition_post_reg.sh` | 30s | 0 |
| PASS | `test_webhook_task_completed.sh` | 29s | 0 |
| PASS | `test_nat_asymmetric_routing.sh` | 28s | 0 |
| PASS | `test_star5_hub_fanin.sh` | 28s | 0 |
| PASS | `test_trust_revoke.sh` | 28s | 0 |
| PASS | `test_peer_restarted_pubsub_sub.sh` | 27s | 0 |
| PASS | `test_gateway_rotate_key.sh` | 26s | 0 |
| PASS | `test_results_after_submitter_died.sh` | 26s | 0 |
| PASS | `test_nat_plus_mtu.sh` | 25s | 0 |
| PASS | `test_nat_plus_bandwidth.sh` | 24s | 0 |
| PASS | `test_nat_plus_latency.sh` | 24s | 0 |
| PASS | `test_nat_plus_loss.sh` | 24s | 0 |
| PASS | `test_splitbrain_divergence.sh` | 24s | 0 |
| PASS | `test_webhook_file_delivered.sh` | 24s | 0 |
| PASS | `test_webhook_task_submitted.sh` | 24s | 0 |
| PASS | `test_bidirectional.sh` | 23s | 0 |
| PASS | `test_nat_stateful_firewall.sh` | 23s | 0 |
| PASS | `test_nat_plus_reorder.sh` | 22s | 0 |
| PASS | `test_sec_pubsub_spam.sh` | 22s | 0 |
| PASS | `test_gateway_pubsub_sub.sh` | 21s | 0 |
| PASS | `test_race_topic_delete_publish.sh` | 21s | 0 |
| PASS | `test_receiver_sigkill_midfile.sh` | 21s | 0 |
| PASS | `test_sec_sym_nat_spoof.sh` | 21s | 0 |
| PASS | `test_force_relay_send_message.sh` | 20s | 0 |
| PASS | `test_gateway_pubsub_pub.sh` | 20s | 0 |
| PASS | `test_trust_grant_already_connected.sh` | 20s | 0 |
| PASS | `test_nat_multihomed.sh` | 19s | 0 |
| PASS | `test_service_agent.sh` | 19s | 0 |
| PASS | `test_fanout_5agents_pubsub.sh` | 18s | 0 |
| PASS | `test_pubsub_service_agent.sh` | 18s | 0 |
| PASS | `test_gateway_ping.sh` | 17s | 0 |
| PASS | `test_gateway_task_result.sh` | 17s | 0 |
| PASS | `test_obs_log_peer_rekeyed.sh` | 17s | 0 |
| PASS | `test_stress_edge.sh` | 17s | 0 |
| PASS | `test_task_polo_gate.sh` | 17s | 0 |
| PASS | `test_task_sequential_burst.sh` | 17s | 0 |
| PASS | `test_gateway_polo_read.sh` | 15s | 0 |
| PASS | `test_gateway_task_submit.sh` | 15s | 0 |
| PASS | `test_mesh_3agents_crosstraffic.sh` | 15s | 0 |
| PASS | `test_network_edge.sh` | 15s | 0 |
| PASS | `test_policy_cycle_prune_trust.sh` | 15s | 0 |
| PASS | `test_pubsub_subscribe_before_publisher.sh` | 15s | 0 |
| PASS | `test_race_pubsub_late_sub.sh` | 15s | 0 |
| PASS | `test_sec_beacon_amplification.sh` | 15s | 0 |
| PASS | `test_send_file_concurrent.sh` | 15s | 0 |
| PASS | `test_star5_hub_fanout.sh` | 15s | 0 |
| PASS | `test_pubsub_publish_to_empty_topic.sh` | 14s | 0 |
| PASS | `test_pubsub_topic_fifo.sh` | 14s | 0 |
| PASS | `test_race_submit_rekey.sh` | 14s | 0 |
| PASS | `test_rendezvous_beacon_split.sh` | 14s | 0 |
| PASS | `test_trust_grant_fresh.sh` | 14s | 0 |
| PASS | `test_fanout_3agents_pubsub.sh` | 13s | 0 |
| PASS | `test_obs_metric_encrypt_ok.sh` | 13s | 0 |
| PASS | `test_race_trust_grant_revoke.sh` | 13s | 0 |
| PASS | `test_size_pubsub_large.sh` | 13s | 0 |
| PASS | `test_task_file_results.sh` | 13s | 0 |
| PASS | `test_chaos_loss10_all_ops.sh` | 12s | 0 |
| PASS | `test_chaos_reorder_all_ops.sh` | 12s | 0 |
| PASS | `test_nat_ipv6_only.sh` | 12s | 0 |
| PASS | `test_peer_restarted_send_message.sh` | 12s | 0 |
| PASS | `test_race_submit_accept.sh` | 12s | 0 |
| PASS | `test_task_bidirectional_services.sh` | 12s | 0 |
| PASS | `test_task_message_chain.sh` | 12s | 0 |
| PASS | `test_mixed_traffic_burst.sh` | 11s | 0 |
| PASS | `test_policy_connect_score.sh` | 11s | 0 |
| PASS | `test_task_progress_events.sh` | 11s | 0 |
| PASS | `test_task_result_integrity.sh` | 11s | 0 |
| PASS | `test_type_routed_service.sh` | 11s | 0 |
| PASS | `test_midrekey_send_message.sh` | 10s | 0 |
| PASS | `test_obs_dashboard_polo_truth.sh` | 10s | 0 |
| PASS | `test_obs_tasklist_vs_disk.sh` | 10s | 0 |
| PASS | `test_policy_connect_tag.sh` | 10s | 0 |
| PASS | `test_sec_malformed_frame.sh` | 10s | 0 |
| PASS | `test_send_file_integrity.sh` | 10s | 0 |
| PASS | `test_task_concurrent_workers.sh` | 10s | 0 |
| PASS | `test_task_policy_decline.sh` | 10s | 0 |
| PASS | `test_chain_abc_task.sh` | 9s | 0 |
| PASS | `test_midrekey_task_submit.sh` | 9s | 0 |
| PASS | `test_net_cross_network_traffic_allowed.sh` | 9s | 0 |
| PASS | `test_net_sybil_gauntlet_shipped.sh` | 9s | 0 |
| PASS | `test_net_two_strikes_shipped.sh` | 9s | 0 |
| PASS | `test_net_vouching_chain_shipped.sh` | 9s | 0 |
| PASS | `test_peer_restarted_send_file.sh` | 9s | 0 |
| PASS | `test_polo_persistence_restart.sh` | 9s | 0 |
| PASS | `test_pubsub_multi_publisher.sh` | 9s | 0 |
| PASS | `test_sec_spoofed_node_id.sh` | 9s | 0 |
| PASS | `test_size_file_500mb_reject.sh` | 9s | 0 |
| PASS | `test_task_accepted_restart_recovery.sh` | 9s | 0 |
| PASS | `test_task_description_integrity.sh` | 9s | 0 |
| PASS | `test_task_invalid_states.sh` | 9s | 0 |
| PASS | `test_task_polo_guarantee.sh` | 9s | 0 |
| PASS | `test_chain_abc_message.sh` | 8s | 0 |
| PASS | `test_midrekey_send_file.sh` | 8s | 0 |
| PASS | `test_net_aristocracy_shipped.sh` | 8s | 0 |
| PASS | `test_rotate_key_hot_path.sh` | 8s | 0 |
| PASS | `test_send_file_bidirectional_transform.sh` | 8s | 0 |
| PASS | `test_task_execute_fifo.sh` | 8s | 0 |
| PASS | `test_task_execute_flow.sh` | 8s | 0 |
| PASS | `test_task_list_ordering.sh` | 8s | 0 |
| PASS | `test_task_persistence_restart.sh` | 8s | 0 |
| PASS | `test_3agent_lookup_propagation.sh` | 7s | 0 |
| PASS | `test_clock_rollback.sh` | 7s | 0 |
| PASS | `test_inbox_ordering.sh` | 7s | 0 |
| PASS | `test_net_forgiveness_shipped.sh` | 7s | 0 |
| PASS | `test_net_ostracism_shipped.sh` | 7s | 0 |
| PASS | `test_net_trust_decay_shipped.sh` | 7s | 0 |
| PASS | `test_policy_datagram_allow.sh` | 7s | 0 |
| PASS | `test_sec_oversized_payload.sh` | 7s | 0 |
| PASS | `test_send_file_hostile_names.sh` | 7s | 0 |
| PASS | `test_clock_skew_receiver.sh` | 6s | 0 |
| PASS | `test_dashboard.sh` | 6s | 0 |
| PASS | `test_message_payload_integrity.sh` | 6s | 0 |
| PASS | `test_net_dunbar_150_shipped.sh` | 6s | 0 |
| PASS | `test_net_fifo_shipped.sh` | 6s | 0 |
| PASS | `test_net_lifo_shipped.sh` | 6s | 0 |
| PASS | `test_net_old_guard_shipped.sh` | 6s | 0 |
| PASS | `test_net_seniority_shipped.sh` | 6s | 0 |
| PASS | `test_policy_connect_allow.sh` | 6s | 0 |
| PASS | `test_policy_join_deny.sh` | 6s | 0 |
| PASS | `test_rotate_key.sh` | 6s | 0 |
| PASS | `test_task_decline.sh` | 6s | 0 |
| PASS | `test_fanout_3agents_file.sh` | 5s | 0 |
| PASS | `test_flash_crowd_10agents_register.sh` | 5s | 0 |
| PASS | `test_gateway_file.sh` | 5s | 0 |
| PASS | `test_gateway_lookup.sh` | 5s | 0 |
| PASS | `test_gateway_register.sh` | 5s | 0 |
| PASS | `test_net_join_allow_per_network.sh` | 5s | 0 |
| PASS | `test_size_file_10mb.sh` | 5s | 0 |
| PASS | `test_size_message_10mb_reject.sh` | 5s | 0 |
| PASS | `test_submit_to_unregistered_peer.sh` | 5s | 0 |
| PASS | `test_net_all_shipped_configs_load.sh` | 3s | 0 |

## Failed logs

### `test_beacon_ping.sh` (exit=1, 10s)

```
==========================================
Beacon liveness ping (discover-as-ping)
==========================================
[2026-04-23 16:40:55] [1;33m[TEST][0m bring stack up clean
[2026-04-23 16:40:59] [0;32m[PASS][0m both agents registered (total_nodes=2) — implies beacon discover round-trip ok
[2026-04-23 16:40:59] [1;33m[TEST][0m beacon UDP port 9001 reachable from agent-a
[2026-04-23 16:40:59] [0;32m[PASS][0m UDP socket to beacon openable
[2026-04-23 16:40:59] [1;33m[TEST][0m agent-a has a non-empty observed endpoint (discover reply accepted)
[2026-04-23 16:40:59] [0;31m[FAIL][0m agent-a has no registered endpoint — beacon round-trip likely failed
{"data":{"address":"0:0000.0000.0002","authenticated_peers":0,"bytes_recv":0,"bytes_sent":0,"conn_list":[],"connections":0,"email":"agent-a@p2p.test","encrypt":true,"encrypted_peers":0,"handshake_pending_count":0,"hostname":"agent-a","identity":true,"networks":null,"node_id":2,"peer_list":[],"peers":0,"pkts_recv":0,"pkts_sent":0,"ports":5,"public_key":"ii03shdN9a/EsXIySPX4blyxycAsHJLEfDzX6aPWBhY=","tunnel_encryption_failure":0,"tunnel_encryption_success":0,"uptime_secs":1,"version":"dev"},"statu[2026-04-23 16:40:59] [1;33m[TEST][0m stop rendezvous (hosts beacon at :9001) and verify probe fails
[2026-04-23 16:41:05] [0;32m[PASS][0m no beacon reply after stop (expected)

==========================================
Beacon ping summary
==========================================
Passed: [0;32m3[0m
Failed: [0;31m1[0m
==========================================
```

### `test_chaos_delay200_all_ops.sh` (exit=1, 16s)

```
==========================================
Chaos: 200ms delay x all 7 op families
==========================================
[2026-04-23 16:41:05] [0;32m[PASS][0m both agents registered
[2026-04-23 16:41:06] [1;33m[TEST][0m apply 200ms +/-50ms delay on agent-b eth0
[2026-04-23 16:41:06] [0;32m[PASS][0m netem delay applied
[2026-04-23 16:41:06] [1;33m[TEST][0m ping under 200ms delay
[2026-04-23 16:41:11] [0;32m[PASS][0m ping ok
[2026-04-23 16:41:11] [1;33m[TEST][0m send-message under delay
[2026-04-23 16:41:12] [0;32m[PASS][0m send-message ok
[2026-04-23 16:41:12] [1;33m[TEST][0m send-file 16 KiB under 200ms delay
[2026-04-23 16:41:13] [0;32m[PASS][0m send-file sha match
[2026-04-23 16:41:13] [1;33m[TEST][0m task submit under 200ms delay (90s)
[2026-04-23 16:41:14] [0;31m[FAIL][0m task stuck (status=)
[2026-04-23 16:41:14] [1;33m[TEST][0m pubsub publish under delay
[2026-04-23 16:41:14] [0;32m[PASS][0m publish ok
test_chaos_delay200_all_ops.sh: line 118: handshake: command not found
test_chaos_delay200_all_ops.sh: line 118: approve: command not found
[2026-04-23 16:41:14] [1;33m[TEST][0m trust handshake under delay (real CLI:  + receiver )
[2026-04-23 16:41:14] [0;32m[PASS][0m handshake ok
[2026-04-23 16:41:14] [1;33m[TEST][0m pilotctl find agent-b (registry lookup) under delay
[2026-04-23 16:41:14] [0;32m[PASS][0m registry lookup ok
[2026-04-23 16:41:14] [1;33m[TEST][0m strip delay and sanity ping
[2026-04-23 16:41:16] [0;32m[PASS][0m post-chaos ping ok
[2026-04-23 16:41:16] [1;33m[TEST][0m no panic/fatal
[2026-04-23 16:41:16] [0;32m[PASS][0m clean logs

Passed: 10  Failed: 1
```

### `test_disk_full_receiver.sh` (exit=1, 9s)

```
==========================================
Disk-full receiver
==========================================
[2026-04-23 16:41:35] [0;32m[PASS][0m both agents registered
[2026-04-23 16:41:35] [1;33m[TEST][0m prepare disk-full at agent-b:/root/.pilot/received
[2026-04-23 16:41:35] [0;32m[PASS][0m disk effectively full (free=262144 bytes)
[2026-04-23 16:41:35] [1;33m[TEST][0m send-file 2 MiB to full receiver — expect clean failure
[2026-04-23 16:41:38] [0;31m[FAIL][0m CORRUPTION: sender ok but dst size=262144 sha=393a8da0c4bd...
[2026-04-23 16:41:38] [1;33m[TEST][0m agent-b daemon still responsive
[2026-04-23 16:41:39] [0;32m[PASS][0m daemon responsive
[2026-04-23 16:41:39] [1;33m[TEST][0m no partial file kept as complete
[2026-04-23 16:41:39] [0;31m[FAIL][0m truncated file left on disk: name=df2m-20260423-234138.667-000001.dat size=262144
[2026-04-23 16:41:39] [1;33m[TEST][0m free space and send small file successfully
[2026-04-23 16:41:40] [0;32m[PASS][0m post-recovery send ok
[2026-04-23 16:41:40] [1;33m[TEST][0m no panic/fatal in daemon logs
[2026-04-23 16:41:40] [0;32m[PASS][0m clean logs

Passed: 5  Failed: 2
```

### `test_chaos_packet_loss.sh` (exit=1, 44s)

```
==========================================
Chaos: 30% packet loss on agent-b ingress
==========================================
[2026-04-23 16:41:06] [1;33m[TEST][0m start stack with NET_ADMIN overlay
[2026-04-23 16:41:09] [0;32m[PASS][0m both agents registered
[2026-04-23 16:41:09] [1;33m[TEST][0m agent-b has NET_ADMIN + iproute2 (tc qdisc show succeeds)
[2026-04-23 16:41:10] [0;32m[PASS][0m tc available
[2026-04-23 16:41:10] [1;33m[TEST][0m baseline (no chaos) task a->b completes
[2026-04-23 16:41:11] [0;32m[PASS][0m baseline task completed cleanly (status=SUCCEEDED)
[2026-04-23 16:41:11] [1;33m[TEST][0m apply 30% ingress+egress loss on agent-b eth0
[2026-04-23 16:41:11] [0;32m[PASS][0m netem applied: qdisc netem 8004: root refcnt 11 limit 1000 loss 30%
[2026-04-23 16:41:11] [1;33m[TEST][0m task a->b completes under 30% packet loss (60s timeout)
[2026-04-23 16:41:11] [0;31m[FAIL][0m submit under chaos failed: {"code":"connection_failed","error":"submit: EOF","message":"submit: EOF","status":"error"}
[2026-04-23 16:41:11] [1;33m[TEST][0m send-file 4 KiB completes under 30% loss
[2026-04-23 16:41:16] [0;32m[PASS][0m file round-trip intact (ack=ACK FILE 4096 bytes sha=96f8946bad1a...)
[2026-04-23 16:41:16] [1;33m[TEST][0m strip netem qdisc and verify clean traffic again
[2026-04-23 16:41:16] [0;32m[PASS][0m netem removed cleanly
[2026-04-23 16:41:50] [0;31m[FAIL][0m post-chaos task stuck (status=)
[2026-04-23 16:41:50] [1;33m[TEST][0m no panic/fatal in daemon logs
[2026-04-23 16:41:50] [0;32m[PASS][0m clean logs

==========================================
Chaos smoke summary
==========================================
Passed: [0;32m7[0m
Failed: [0;31m2[0m
==========================================
```

### `test_beacon_restart_midflight.sh` (exit=1, 75s)

```
==========================================
Beacon restart mid-flight
==========================================
[2026-04-23 16:40:59] [0;32m[PASS][0m both agents registered
[2026-04-23 16:40:59] [1;33m[TEST][0m warm task before beacon restart
[2026-04-23 16:41:00] [0;32m[PASS][0m warm ok
[2026-04-23 16:41:00] [1;33m[TEST][0m docker compose restart rendezvous (beacon container)
[2026-04-23 16:41:01] [0;32m[PASS][0m rendezvous+beacon container back online
[2026-04-23 16:41:01] [1;33m[TEST][0m both agents re-register post-beacon-restart
[2026-04-23 16:41:01] [0;32m[PASS][0m total_nodes=2
[2026-04-23 16:41:01] [1;33m[TEST][0m task still completes post-beacon-restart
[2026-04-23 16:42:09] [0;31m[FAIL][0m post-beacon task stuck (status=)
[2026-04-23 16:42:09] [1;33m[TEST][0m pilotctl lookup works post-beacon-restart
[2026-04-23 16:42:09] [0;32m[PASS][0m lookup ok: 0:0000.0000.0001
[2026-04-23 16:42:09] [1;33m[TEST][0m no panic/fatal in agent logs
[2026-04-23 16:42:09] [0;32m[PASS][0m clean logs

Passed: 6  Failed: 1
```

### `test_dur_shortcycle_policy_1m.sh` (exit=1, 64s)

```
==========================================
Duration: short-cycle policy 5s x 60s
==========================================
[2026-04-23 16:42:13] [0;32m[PASS][0m both agents registered
[2026-04-23 16:42:13] [1;33m[TEST][0m write short-cycle expr_policy onto agent-a
[2026-04-23 16:42:13] [0;32m[PASS][0m policy written
[2026-04-23 16:42:13] [1;33m[TEST][0m create unmanaged network then attach expr_policy
[2026-04-23 16:42:14] [0;32m[PASS][0m network created (nid=1), policy attached, joined
[2026-04-23 16:42:14] [1;33m[TEST][0m run 60s and count cycle events
    cycle tick delta over 60s: 0 (expect >= 10)
[2026-04-23 16:43:14] [0;31m[FAIL][0m only 0 cycle ticks (expected >=10 for 5s cycle over 60s)
[2026-04-23 16:43:14] [1;33m[TEST][0m no panics
[2026-04-23 16:43:14] [0;32m[PASS][0m clean logs

Passed: 4  Failed: 1
```

### `test_chaos_loss30_all_ops.sh` (exit=1, 153s)

```
==========================================
Chaos: 30% loss x all 7 op families (P1-010)
==========================================
[2026-04-23 16:41:04] [1;33m[TEST][0m fresh chaos-capable stack
[2026-04-23 16:41:07] [0;32m[PASS][0m both agents registered
[2026-04-23 16:41:09] [1;33m[TEST][0m apply 30% loss on agent-b eth0
[2026-04-23 16:41:09] [0;32m[PASS][0m netem 30% loss applied
[2026-04-23 16:41:09] [1;33m[TEST][0m ping a->b under 30% loss (long timeout)
[2026-04-23 16:41:17] [0;32m[PASS][0m ping ok
[2026-04-23 16:41:17] [1;33m[TEST][0m send-message under 30% loss
[2026-04-23 16:41:18] [0;32m[PASS][0m send-message ok
[2026-04-23 16:41:18] [1;33m[TEST][0m send-file 8 KiB under 30% loss (sha256 match or clean fail)
[2026-04-23 16:41:19] [0;32m[PASS][0m send-file sha match under 30% loss
[2026-04-23 16:41:19] [1;33m[TEST][0m task submit a->b under 30% loss (120s)
[2026-04-23 16:43:33] [0;31m[FAIL][0m task stuck (status=EXPIRED) — expected P1-010 finding
[2026-04-23 16:43:33] [1;33m[TEST][0m pubsub publish under 30% loss
[2026-04-23 16:43:35] [0;32m[PASS][0m publish ok
[2026-04-23 16:43:35] [1;33m[TEST][0m trust handshake under 30% loss
[2026-04-23 16:43:35] [0;32m[PASS][0m handshake ok
[2026-04-23 16:43:35] [1;33m[TEST][0m pilotctl find agent-b (registry lookup) under 30% loss
[2026-04-23 16:43:35] [0;32m[PASS][0m registry lookup ok
[2026-04-23 16:43:35] [1;33m[TEST][0m strip chaos and verify post-chaos ping works
[2026-04-23 16:43:36] [0;32m[PASS][0m post-chaos ping ok
[2026-04-23 16:43:36] [1;33m[TEST][0m no panic/fatal in agent logs
[2026-04-23 16:43:36] [0;32m[PASS][0m clean logs

Passed: 10  Failed: 1
```

### `test_fanin_3agents_tasks.sh` (exit=1, 59s)

```
  a-worker:   "task_id": "0e12d598-58d4-023a-252b-d25716db938c"
  a-worker: }
  a-worker: 23:43:20.158782137 done tid=0e12d598-58d4-023a-252b-d25716db938c desc=from-b:2
  a-worker: {
  a-worker:   "message": "Task accepted",
  a-worker:   "status": "ACCEPTED",
  a-worker:   "task_id": "76df2725-3ec2-4cf2-7097-b1bc768d9ff7"
  a-worker: }
  a-worker: {
  a-worker:   "sent_to": "0:0000.0000.0003",
  a-worker:   "sent_type": "text",
  a-worker:   "status": "SUCCEEDED",
  a-worker:   "task_id": "76df2725-3ec2-4cf2-7097-b1bc768d9ff7"
  a-worker: }
  a-worker: 23:43:20.216267845 done tid=76df2725-3ec2-4cf2-7097-b1bc768d9ff7 desc=from-c:2
[2026-04-23 16:44:12] [1;33m[TEST][0m each submitter gets its own ack:* result
test_fanin_3agents_tasks.sh: line 122: ${role^^}_TIDS: bad substitution
test_fanin_3agents_tasks.sh: line 122: ${}: bad substitution
test_fanin_3agents_tasks.sh: line 122: ${role^^}_TIDS: bad substitution
test_fanin_3agents_tasks.sh: line 122: ${}: bad substitution
[2026-04-23 16:44:12] [0;32m[PASS][0m results correctly routed to each submitter
[2026-04-23 16:44:12] [1;33m[TEST][0m no panics/fatals in daemon logs
[2026-04-23 16:44:12] [0;32m[PASS][0m clean logs

==========================================
Fan-in tasks summary
==========================================
Passed: [0;32m5[0m
Failed: [0;31m1[0m
==========================================
```

### `test_force_relay_send_file.sh` (exit=1, 17s)

```
==========================================
Force beacon-relay path: send-file
(expected-red if P1-010 still open)
==========================================
[2026-04-23 16:44:18] [1;33m[TEST][0m fresh chaos-capable stack
[2026-04-23 16:44:21] [0;32m[PASS][0m agents up
[2026-04-23 16:44:23] [1;33m[TEST][0m iptables DROP direct UDP a<->b (both directions)
[2026-04-23 16:44:23] [0;32m[PASS][0m direct path severed; beacon relay is the only route
[2026-04-23 16:44:33] [1;33m[TEST][0m send-file 32 KiB via relay path
[2026-04-23 16:44:34] [0;32m[PASS][0m file relayed intact (rc=0)
[2026-04-23 16:44:34] [1;33m[TEST][0m beacon relay stats show forwarded>0
[2026-04-23 16:44:34] [0;31m[FAIL][0m beacon has no relay forwards: {"total_nodes":2,"active_nodes":2,"total_requests":25,"req_per_day":0,"uptime_secs":15,"hourly":[{"ts":1776987858,"total_nodes":0,"online_nodes":0,"total_requests":0}],"daily":[{"ts":1776987858,"total_nodes":0,"online_nodes":0,"total_requests":0}],"probes":{"beacon":{"last_success":1776987869223},"dashboard":{"last_success":1776987869223},"metrics":{"last_success":1776987869223},"registry":{"last_success":1776987869223}}}
[2026-04-23 16:44:34] [1;33m[TEST][0m no panic/fatal in logs
[2026-04-23 16:44:34] [0;32m[PASS][0m clean logs

Passed: 4  Failed: 1
```

### `test_force_relay_pubsub.sh` (exit=1, 65s)

```
==========================================
Force relay: pub/sub delivery
==========================================
[2026-04-23 16:44:18] [1;33m[TEST][0m subscribe on b (before partition)
[2026-04-23 16:44:21] [1;33m[TEST][0m partition direct UDP
[2026-04-23 16:44:21] [0;32m[PASS][0m direct severed
[2026-04-23 16:44:31] [1;33m[TEST][0m publish from a via relay
[2026-04-23 16:44:31] [0;32m[PASS][0m publish returned
[2026-04-23 16:44:31] [1;33m[TEST][0m subscriber on b receives event via relay
[2026-04-23 16:45:17] [0;31m[FAIL][0m event not received — likely P1-010
[2026-04-23 16:45:17] [1;33m[TEST][0m no panic/fatal
[2026-04-23 16:45:17] [0;32m[PASS][0m clean logs

Passed: 3  Failed: 1
```

### `test_cli.sh` (exit=1, 274s)

```
{
  "node_id": 71771,
  "type": "set_visibility_ok",
  "visibility": "private"
}
[2026-04-23 16:45:51] [0;32m[PASS][0m Visibility toggle works
[2026-04-23 16:45:51] [1;33m[TEST][0m Testing tag management
tags set: #test #integration #docker
tags cleared
[2026-04-23 16:45:51] [0;32m[PASS][0m Tag management works
[2026-04-23 16:45:51] [1;33m[TEST][0m Checking configuration
[2026-04-23 16:45:51] [0;32m[PASS][0m Configuration retrieved successfully
[2026-04-23 16:45:51] [1;33m[TEST][0m Deregistering from network
{
  "type": "deregister_ok"
}
[2026-04-23 16:45:51] [0;32m[PASS][0m Successfully deregistered from network

=========================================
Test Summary
=========================================
Passed: [0;32m16[0m
Failed: [0;31m5[0m
=========================================

[1;33m[CLEANUP][0m Stopping daemon...
[1;33m[CLEANUP][0m Last daemon errors:
time=2026-04-23T16:41:17.239-07:00 level=WARN msg="failed to save account file" error="create account dir: mkdir /root: read-only file system"
time=2026-04-23T16:41:17.300-07:00 level=WARN msg="failed to save identity" error="create identity dir: mkdir /root: read-only file system"
[1;33m[CLEANUP][0m Daemon stopped.
```

### `test_force_relay_task.sh` (exit=1, 121s)

```
==========================================
Force relay: task submit+complete
==========================================
[2026-04-23 16:45:00] [1;33m[TEST][0m partition direct UDP
[2026-04-23 16:45:00] [0;32m[PASS][0m direct severed
[2026-04-23 16:45:10] [1;33m[TEST][0m task submit a->b via relay
[2026-04-23 16:45:10] [0;31m[FAIL][0m submit failed at door: {"code":"connection_failed","error":"submit: EOF","message":"submit: EOF","status":"error"}
[2026-04-23 16:45:10] [1;33m[TEST][0m task reaches completion via relay
[2026-04-23 16:46:55] [0;31m[FAIL][0m stuck at  — likely P1-010
[2026-04-23 16:46:55] [1;33m[TEST][0m no panic/fatal
[2026-04-23 16:46:55] [0;32m[PASS][0m clean logs

Passed: 2  Failed: 2
```

### `test_gateway_http_message.sh` (exit=1, 92s)

```
==========================================
Gateway: HTTP/message round-trip via proxy
==========================================
[2026-04-23 16:45:39] [0;32m[PASS][0m agent-b pilot addr: 0:0000.0000.0002
[2026-04-23 16:45:39] [1;33m[TEST][0m map agent-b into gateway local subnet
[2026-04-23 16:45:39] [0;32m[PASS][0m mapped 0:0000.0000.0002 -> 10.4.0.1
[2026-04-23 16:45:39] [1;33m[TEST][0m send payload to 10.4.0.1:1001 (agent-b's data-exchange service)
[2026-04-23 16:46:54] [0;31m[FAIL][0m could not open TCP to 10.4.0.1:1001 via gateway
[2026-04-23 16:46:56] [1;33m[TEST][0m payload delivered to agent-b inbox
[2026-04-23 16:46:56] [0;31m[FAIL][0m payload not found in agent-b inbox; gateway proxy may not have delivered
time=2026-04-23T23:45:39.877Z level=INFO msg="gateway connected" subnet=10.4.0.0/16
time=2026-04-23T23:45:39.878Z level=INFO msg="gateway running"

Passed: 2  Failed: 2
```

### `test_gateway_trust_grant.sh` (exit=1, 18s)

```
==========================================
Gateway: trust grant agent-b
==========================================
[2026-04-23 16:47:33] [1;33m[TEST][0m gateway initiates handshake to agent-b
[2026-04-23 16:47:33] [0;32m[PASS][0m handshake sent
[2026-04-23 16:47:33] [1;33m[TEST][0m agent-b sees gateway in pending
[2026-04-23 16:47:33] [0;32m[PASS][0m agent-b has gateway in pending
jq: parse error: Invalid numeric literal at line 1, column 6
[2026-04-23 16:47:34] [1;33m[TEST][0m gateway trust list contains agent-b after approval
[2026-04-23 16:47:36] [0;31m[FAIL][0m agent-b (node_id=1) not in gateway trust list
{"data":{"trusted":[]},"status":"ok"}

Passed: 2  Failed: 1
```

### `test_dur_steady_compressed_24h.sh` (exit=1, 304s)

```
==========================================
Duration: compressed 24h (1s cycle x 300s)
==========================================
[2026-04-23 16:42:57] [0;32m[PASS][0m both agents registered
[2026-04-23 16:42:57] [1;33m[TEST][0m write 1s-cycle expr_policy
[2026-04-23 16:42:57] [0;32m[PASS][0m policy written
[2026-04-23 16:42:57] [1;33m[TEST][0m create unmanaged network then attach expr_policy
[2026-04-23 16:42:58] [0;32m[PASS][0m network active (nid=1), policy attached, joined
[2026-04-23 16:42:58] [0;32m[PASS][0m T0 rss=10056KiB fds=9
[2026-04-23 16:42:58] [1;33m[TEST][0m run for 300s
[2026-04-23 16:47:58] [0;32m[PASS][0m run complete
    cycle ticks during run: 0 (expected ~300)
[2026-04-23 16:47:58] [1;33m[TEST][0m tick count within ±25% of 300
[2026-04-23 16:47:58] [0;31m[FAIL][0m tick count 0 outside [225, 375]
    delta rss=0KiB fds=0
[2026-04-23 16:47:58] [1;33m[TEST][0m rss delta < 50 MiB
[2026-04-23 16:47:58] [0;32m[PASS][0m rss delta 0KiB within budget
[2026-04-23 16:47:58] [1;33m[TEST][0m fd delta < 20
[2026-04-23 16:47:58] [0;32m[PASS][0m fd delta 0 within budget
[2026-04-23 16:47:58] [1;33m[TEST][0m no panics
[2026-04-23 16:47:58] [0;32m[PASS][0m clean logs

Passed: 8  Failed: 1
```

### `test_midrekey_task_results.sh` (exit=1, 60s)

```
==========================================
Mid-rekey: task results (P1-009 direct)
==========================================
[2026-04-23 16:47:42] [1;33m[TEST][0m fresh stack
[2026-04-23 16:47:46] [0;32m[PASS][0m agents up
[2026-04-23 16:47:46] [1;33m[TEST][0m submit + accept T1
[2026-04-23 16:47:48] [0;32m[PASS][0m T1 ACCEPTED on b
[2026-04-23 16:47:48] [1;33m[TEST][0m restart agent-b (rekey)
[2026-04-23 16:47:48] [0;32m[PASS][0m agent-b back, tunnel rekey window open
[2026-04-23 16:47:48] [1;33m[TEST][0m send-results during rekey window (no warm-up)
[2026-04-23 16:47:48] [1;33m[TEST][0m submitter observes terminal status within 45s
[2026-04-23 16:48:41] [0;31m[FAIL][0m stuck at ACCEPTED — direct P1-009 regression
[2026-04-23 16:48:41] [1;33m[TEST][0m result text matches sender payload
[2026-04-23 16:48:41] [0;31m[FAIL][0m payload missing: 
[2026-04-23 16:48:41] [1;33m[TEST][0m no panic/fatal
[2026-04-23 16:48:42] [0;32m[PASS][0m clean logs

Passed: 4  Failed: 2
```

### `test_dur_steady_10min.sh` (exit=1, 609s)

```
==========================================
Duration: steady 10 msg/s x 600s
==========================================
[2026-04-23 16:42:48] [0;32m[PASS][0m both agents registered
[2026-04-23 16:42:48] [1;33m[TEST][0m T=0 snapshot (agent-a)
[2026-04-23 16:42:49] [0;32m[PASS][0m T0: rss=11744KiB fds=9
[2026-04-23 16:42:49] [1;33m[TEST][0m start steady send loop 10/s for 600s
[2026-04-23 16:52:54] [1;33m[TEST][0m T=end snapshot (agent-a)
[2026-04-23 16:52:54] [0;32m[PASS][0m T1: rss=31720KiB fds=9
    delta: rss=19976KiB fds=0
[2026-04-23 16:52:54] [1;33m[TEST][0m rss delta < 100 MiB over 10 min of load
[2026-04-23 16:52:54] [0;32m[PASS][0m rss delta 19976KiB within budget
[2026-04-23 16:52:54] [1;33m[TEST][0m fd delta < 50
[2026-04-23 16:52:54] [0;32m[PASS][0m fd delta 0 within budget
[2026-04-23 16:52:54] [1;33m[TEST][0m expected send volume reached
[2026-04-23 16:52:54] [0;31m[FAIL][0m sent=3417 much less than target 6000
[2026-04-23 16:52:54] [1;33m[TEST][0m no panics / leaks in logs
[2026-04-23 16:52:54] [0;32m[PASS][0m clean logs

Passed: 6  Failed: 1
```

### `test_nat_rendezvous_natted.sh` (exit=1, 7s)

```
    ------
     > [agent-b builder 4/4] RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /bin/pilot-rendezvous ./cmd/rendezvous &&     CGO_ENABLED=0 go build -ldflags="-s -w" -o /bin/pilot-daemon ./cmd/daemon &&     CGO_ENABLED=0 go build -ldflags="-s -w" -o /bin/pilotctl ./cmd/pilotctl &&     CGO_ENABLED=0 go build -ldflags="-s -w" -o /bin/pilot-gateway ./cmd/gateway:
    4.069 go: downloading github.com/expr-lang/expr v1.17.8
    5.667 # github.com/TeoSlayer/pilotprotocol/pkg/daemon
    5.667 pkg/daemon/daemon.go:586:4: d.publicEndpoint undefined (type *Daemon has no field or method publicEndpoint)
    ------
    Dockerfile.multi:4
    
    --------------------
    
       3 |     COPY . .
    
       4 | >>> RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /bin/pilot-rendezvous ./cmd/rendezvous && \
    
       5 | >>>     CGO_ENABLED=0 go build -ldflags="-s -w" -o /bin/pilot-daemon ./cmd/daemon && \
    
       6 | >>>     CGO_ENABLED=0 go build -ldflags="-s -w" -o /bin/pilotctl ./cmd/pilotctl && \
    
       7 | >>>     CGO_ENABLED=0 go build -ldflags="-s -w" -o /bin/pilot-gateway ./cmd/gateway
    
       8 |     
    
    --------------------
    
    target agent-a: failed to solve: process "/bin/sh -c CGO_ENABLED=0 go build -ldflags=\"-s -w\" -o /bin/pilot-rendezvous ./cmd/rendezvous &&     CGO_ENABLED=0 go build -ldflags=\"-s -w\" -o /bin/pilot-daemon ./cmd/daemon &&     CGO_ENABLED=0 go build -ldflags=\"-s -w\" -o /bin/pilotctl ./cmd/pilotctl &&     CGO_ENABLED=0 go build -ldflags=\"-s -w\" -o /bin/pilot-gateway ./cmd/gateway" did not complete successfully: exit code: 1
    
    
    
    View build details: docker-desktop://dashboard/build/desktop-linux/desktop-linux/0w42ey7dfyp7kip6bycpspric
    
```

### `test_net_anti_camping_shipped.sh` (exit=1, 12s)

```
[2026-04-23 16:58:00] [0;32m[PASS][0m net=1
[2026-04-23 16:58:03] [1;33m[TEST][0m force cycles — expect b evicted after threshold
[2026-04-23 16:58:08] [0;31m[FAIL][0m b still in rankings after idle cycles (EXPECTED: evicted)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_cold_shoulder_shipped.sh` (exit=1, 6s)

```
[2026-04-23 16:58:21] [0;32m[PASS][0m net=1
[2026-04-23 16:58:24] [1;33m[TEST][0m low-score peer traffic silently dropped
[2026-04-23 16:58:24] [0;31m[FAIL][0m traffic flowed from low-score peer (EXPECTED: cold-shoulder deny)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_burnout_shipped.sh` (exit=1, 12s)

```
[2026-04-23 16:58:20] [0;32m[PASS][0m net=1
[2026-04-23 16:58:23] [1;33m[TEST][0m generate burst traffic to trigger burnout cap
[2026-04-23 16:58:28] [1;33m[TEST][0m after burst, score is bounded or peer evicted (burnout cap)
[2026-04-23 16:58:28] [0;31m[FAIL][0m no burnout cap observed: score=->0 listed=1 (EXPECTED: score moved AND bounded, OR peer evicted)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_cooling_off_shipped.sh` (exit=1, 8s)

```
[2026-04-23 16:58:28] [0;32m[PASS][0m net=1
[2026-04-23 16:58:30] [1;33m[TEST][0m violating peer is in cooldown
[2026-04-23 16:58:32] [0;31m[FAIL][0m retry succeeded inside cooldown window (EXPECTED: deny)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_cross_network_traffic_denied.sh` (exit=1, 7s)

```
[2026-04-23 16:58:35] [1;33m[TEST][0m create strict network X (deny non-members)
[2026-04-23 16:58:37] [0;32m[PASS][0m net=1
[2026-04-23 16:58:37] [1;33m[TEST][0m agent-a joins X; agent-b stays out
[2026-04-23 16:58:39] [0;32m[PASS][0m agent-a is member of X
[2026-04-23 16:58:39] [1;33m[TEST][0m agent-b (non-member of X) dials agent-a — expect deny
[2026-04-23 16:58:39] [0;31m[FAIL][0m cross-network send succeeded despite X's deny rule (EXPECTED: deny)
    resolved "agent-a" → 0:0000.0000.0002
    sent 19 bytes (no response)
Passed: [0;32m2[0m  Failed: [0;31m1[0m
```

### `test_net_gift_economy_shipped.sh` (exit=1, 8s)

```
[2026-04-23 16:58:56] [0;32m[PASS][0m net=1
[2026-04-23 16:59:00] [1;33m[TEST][0m both sender and receiver accrue reward
[2026-04-23 16:59:00] [0;31m[FAIL][0m asymmetric rewards missing: A=0 B= (EXPECTED: both >0)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_golden_hour_shipped.sh` (exit=1, 11s)

```
[2026-04-23 16:58:57] [0;32m[PASS][0m net=1
[2026-04-23 16:59:00] [1;33m[TEST][0m fresh-join actions accrue bonus
[2026-04-23 16:59:05] [0;31m[FAIL][0m no golden-hour bonus: early= late-delta=0 (EXPECTED: early>0 AND early>late-delta)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_gossip_tax_shipped.sh` (exit=1, 11s)

```
[2026-04-23 16:59:04] [0;32m[PASS][0m net=1
[2026-04-23 16:59:06] [1;33m[TEST][0m excessive pubsub publishes drain score
[2026-04-23 16:59:11] [0;31m[FAIL][0m no gossip tax: 0 -> 0 (EXPECTED: SC0>0 AND SC1<SC0 after high emit)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_data_exchange_policy_shipped.sh` (exit=1, 38s)

```
[2026-04-23 16:58:41] [0;32m[PASS][0m net=1
[2026-04-23 16:58:43] [1;33m[TEST][0m echo (port 7) is always allowed (allow-echo-dial rule)
[2026-04-23 16:59:12] [0;31m[FAIL][0m echo blocked (EXPECTED: port 7 always allowed)
[2026-04-23 16:59:12] [1;33m[TEST][0m port 1001 rejected when neither side has 'service' tag
[2026-04-23 16:59:13] [0;32m[PASS][0m 1001 send refused
[2026-04-23 16:59:13] [1;33m[TEST][0m port 1001 allowed once agent-b takes 'service' tag
[2026-04-23 16:59:15] [0;31m[FAIL][0m 1001 blocked with service tag (EXPECTED: allowed)
    resolved "agent-b" → 0:0000.0000.0002
    error: cannot connect to 0:0000.0000.0002 port 1001
    hint:  check that 0:0000.0000.0002 is reachable: pilotctl ping 0:0000.0000.0002
Passed: [0;32m2[0m  Failed: [0;31m2[0m
```

### `test_net_half_life_shipped.sh` (exit=1, 9s)

```
[2026-04-23 16:59:14] [0;32m[PASS][0m net=1
[2026-04-23 16:59:19] [0;31m[FAIL][0m decay too weak or unseeded:  ->  (EXPECTED: S0>=4 AND S1<S0 AND S1<=1)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_high_trust_society_shipped.sh` (exit=1, 11s)

```
[2026-04-23 16:59:16] [0;32m[PASS][0m net=1
[2026-04-23 16:59:19] [1;33m[TEST][0m 5 connects from a->b — score should be +5
[2026-04-23 16:59:22] [0;31m[FAIL][0m score=0 (EXPECTED >= 5; score action not applied per connect)
[2026-04-23 16:59:22] [1;33m[TEST][0m cycle tick runs without panic under active policy
[2026-04-23 16:59:22] [0;32m[PASS][0m cycle ok
Passed: [0;32m2[0m  Failed: [0;31m1[0m
```

### `test_net_isolation_policy_scoping.sh` (exit=1, 9s)

```
[2026-04-23 16:59:19] [1;33m[TEST][0m create strict network (X)
[2026-04-23 16:59:20] [0;32m[PASS][0m net X = 1
[2026-04-23 16:59:20] [1;33m[TEST][0m create permissive network (Y)
[2026-04-23 16:59:21] [0;32m[PASS][0m net Y = 2
[2026-04-23 16:59:21] [1;33m[TEST][0m agent-a joins X; agent-b joins Y
[2026-04-23 16:59:23] [0;32m[PASS][0m memberships set
[2026-04-23 16:59:24] [1;33m[TEST][0m agent-b can reach agent-a on base network (Y's allow is permissive)
[2026-04-23 16:59:25] [0;32m[PASS][0m cross-scope base-network ping ok
[2026-04-23 16:59:25] [1;33m[TEST][0m X's deny is scoped to X (agent-a is member of X)
[2026-04-23 16:59:25] [0;32m[PASS][0m X runner has rules active
[2026-04-23 16:59:25] [1;33m[TEST][0m Y's allow is scoped to Y (agent-b is member of Y, not X)
[2026-04-23 16:59:25] [0;32m[PASS][0m Y runner has rules active
[2026-04-23 16:59:25] [1;33m[TEST][0m agent-a has NO runner for Y, agent-b has NO runner for X
[2026-04-23 16:59:25] [0;31m[FAIL][0m cross-scope status succeeded (leak): A->Y=ok  B->X=ok
Passed: [0;32m6[0m  Failed: [0;31m1[0m
```

### `test_net_join_deny_per_network.sh` (exit=1, 5s)

```
[2026-04-23 16:59:26] [0;32m[PASS][0m net=1
[2026-04-23 16:59:26] [1;33m[TEST][0m agent-b attempts to join — expect deny
[2026-04-23 16:59:28] [0;31m[FAIL][0m agent-b joined despite join-deny rule (EXPECTED: rejected)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_karma_ledger_shipped.sh` (exit=1, 9s)

```
[2026-04-23 16:59:29] [0;32m[PASS][0m net=1
[2026-04-23 16:59:32] [1;33m[TEST][0m 3 connects update karma ledger
[2026-04-23 16:59:34] [0;31m[FAIL][0m karma did not change (EXPECTED: monotonic increase)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_lottery_shipped.sh` (exit=1, 7s)

```
[2026-04-23 16:59:32] [0;32m[PASS][0m net=1
[2026-04-23 16:59:34] [1;33m[TEST][0m repeated connects yield non-deterministic pass/fail
[2026-04-23 16:59:35] [0;31m[FAIL][0m deterministic outcome pass=10 deny=0 (EXPECTED: probabilistic)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_meritocracy_rating_shipped.sh` (exit=1, 7s)

```
[2026-04-23 16:59:36] [0;32m[PASS][0m net=1
[2026-04-23 16:59:38] [1;33m[TEST][0m rating surface exposed per peer
[2026-04-23 16:59:39] [0;31m[FAIL][0m no rating surface (EXPECTED: per-peer rating)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_meritocracy_shipped.sh` (exit=1, 6s)

```
[2026-04-23 16:59:38] [0;32m[PASS][0m net=1
[2026-04-23 16:59:41] [1;33m[TEST][0m top-score peer is in rankings and surfaces merit
[2026-04-23 16:59:41] [0;31m[FAIL][0m no ranking surface (EXPECTED: rankings expose merit order)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_pay_it_forward_shipped.sh` (exit=1, 7s)

```
[2026-04-23 16:59:49] [0;32m[PASS][0m net=1
[2026-04-23 16:59:52] [1;33m[TEST][0m pubsub relay accrues forwarding reward
[2026-04-23 16:59:53] [0;31m[FAIL][0m no forwarding reward (EXPECTED: score bump on forward)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_rotating_chairs_shipped.sh` (exit=1, 7s)

```
[2026-04-23 16:59:54] [0;32m[PASS][0m net=1
[2026-04-23 16:59:56] [1;33m[TEST][0m rankings reorder across forced cycles
[2026-04-23 16:59:57] [0;31m[FAIL][0m ranking head static (0) across cycles (EXPECTED: rotation)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_small_circle_shipped.sh` (exit=1, 6s)

```
[2026-04-23 17:00:01] [0;32m[PASS][0m net=1
[2026-04-23 17:00:03] [1;33m[TEST][0m max_peers cap enforced (small-circle)
[2026-04-23 17:00:03] [0;31m[FAIL][0m cap=0 (EXPECTED: small positive cap, e.g. 10)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_stable_state_shipped.sh` (exit=1, 6s)

```
[2026-04-23 17:00:04] [0;32m[PASS][0m net=1
[2026-04-23 17:00:07] [1;33m[TEST][0m cycles converge peer count toward target
[2026-04-23 17:00:07] [0;31m[FAIL][0m peer count drifted or empty: 0 -> 0 (EXPECTED: C0>=1 AND |ΔC|<=2)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_tithe_shipped.sh` (exit=1, 11s)

```
[2026-04-23 17:00:12] [0;32m[PASS][0m net=1
[2026-04-23 17:00:14] [1;33m[TEST][0m tithe clips accumulated score on cycle
[2026-04-23 17:00:19] [0;31m[FAIL][0m no tithe: 0 -> 0 (EXPECTED: score decrease)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_polo_scoped_per_network.sh` (exit=1, 35s)

```
create_network_from_file: attempt 1 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 2s
create_network_from_file: attempt 2 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 4s
create_network_from_file: attempt 3 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 6s
create_network_from_file: attempt 4 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 8s
create_network_from_file: attempt 5 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 10s
create_network_from_file: create failed after 5 attempts: {"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}
[2026-04-23 17:00:23] [0;31m[FAIL][0m create X
```

### `test_net_whale_hunt_shipped.sh` (exit=1, 7s)

```
[2026-04-23 17:00:28] [0;32m[PASS][0m net=1
[2026-04-23 17:00:30] [1;33m[TEST][0m high-score peer is flagged / taxed
[2026-04-23 17:00:30] [0;31m[FAIL][0m no whale-score rule visible (EXPECTED: rule keyed on high peer_score)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_net_trust_scoped_per_network.sh` (exit=1, 35s)

```
create_network_from_file: attempt 1 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 2s
create_network_from_file: attempt 2 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 4s
create_network_from_file: attempt 3 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 6s
create_network_from_file: attempt 4 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 8s
create_network_from_file: attempt 5 failed ({"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}), retrying in 10s
create_network_from_file: create failed after 5 attempts: {"code":"connection_failed","error":"network create: registry: request failed","message":"network create: registry: request failed","status":"error"}
[2026-04-23 17:00:49] [0;31m[FAIL][0m create X
```

### `test_net_mutual_admiration_shipped.sh` (exit=1, 76s)

```
[2026-04-23 16:59:39] [0;32m[PASS][0m net=1
[2026-04-23 16:59:42] [1;33m[TEST][0m unilateral connect produces no score (until mutual)
[2026-04-23 17:00:52] [0;31m[FAIL][0m no mutual bonus: uni=0 mutual=0 (EXPECTED: increase on reciprocation)
Passed: [0;32m1[0m  Failed: [0;31m1[0m
```

### `test_partition_midflight.sh` (exit=1, 13s)

```
==========================================
Partition a<->b mid-flight (iptables DROP)
==========================================
[2026-04-23 17:00:53] [0;32m[PASS][0m both agents registered
[2026-04-23 17:00:54] [0;32m[PASS][0m resolved agent-a=172.29.10.20 agent-b=172.29.10.21
[2026-04-23 17:00:54] [1;33m[TEST][0m install bidirectional partition a<->b
[2026-04-23 17:00:55] [0;32m[PASS][0m partition is effective
[2026-04-23 17:00:55] [1;33m[TEST][0m pilotctl ping bounded-fail under partition (--timeout 4s)
[2026-04-23 17:00:56] [0;31m[FAIL][0m ping did not bound: rc=0 dt=1s
[2026-04-23 17:00:56] [1;33m[TEST][0m send-message under partition must not claim delivery
[2026-04-23 17:00:57] [0;32m[PASS][0m send-message did not false-ack
[2026-04-23 17:00:57] [1;33m[TEST][0m send-file under partition — must fail/timeout cleanly
[2026-04-23 17:00:57] [0;32m[PASS][0m send-file did not deliver and terminated in 0s
[2026-04-23 17:00:57] [1;33m[TEST][0m task submit under partition must not mark completed
[2026-04-23 17:00:57] [0;32m[PASS][0m task did not falsely complete (status=<no-record>)
[2026-04-23 17:00:57] [1;33m[TEST][0m publish under partition — must fail bounded, not spin
[2026-04-23 17:00:58] [0;32m[PASS][0m publish bounded in 1s
[2026-04-23 17:00:58] [1;33m[TEST][0m heal partition and ping a->b recovers
[2026-04-23 17:00:59] [0;32m[PASS][0m ping recovered post-heal
[2026-04-23 17:00:59] [1;33m[TEST][0m no panic/fatal in logs during partition
[2026-04-23 17:00:59] [0;32m[PASS][0m clean logs

Passed: 9  Failed: 1
```

### `test_policy_cycle_evict.sh` (exit=1, 11s)

```
==========================================
Policy: cycle × evict
==========================================
[2026-04-23 17:01:19] [0;32m[PASS][0m stack up
[2026-04-23 17:01:19] [1;33m[TEST][0m Apply tag-then-evict policy on agent-b
load_policy: network_id=1 policy=/tests/fixtures/policies/short_cycle_evict.json (on agent-b)
[2026-04-23 17:01:20] [0;32m[PASS][0m policy loaded (net=1)
[2026-04-23 17:01:20] [1;33m[TEST][0m bootstrap peer set via cycle
[2026-04-23 17:01:21] [1;33m[TEST][0m connect agent-a → agent-b to trigger 'stale' tag
[2026-04-23 17:01:23] [1;33m[TEST][0m agent-a has tag 'stale' after connect
[2026-04-23 17:01:23] [0;32m[PASS][0m tags=["stale"]
[2026-04-23 17:01:23] [1;33m[TEST][0m force cycle -> evict stale peers
[2026-04-23 17:01:26] [0;31m[FAIL][0m peer_count did not shrink (1 -> 1)
[2026-04-23 17:01:26] [1;33m[TEST][0m agent-b logged 'policy: evicted peers'
[2026-04-23 17:01:26] [0;32m[PASS][0m evict fired
Passed: \033[0;32m4\033[0m  Failed: \033[0;31m1\033[0m
```

### `test_policy_cycle_fill_trust.sh` (exit=1, 10s)

```
==========================================
Policy: cycle × fill_trust
==========================================
[2026-04-23 17:01:20] [0;32m[PASS][0m stack up
[2026-04-23 17:01:20] [1;33m[TEST][0m Apply fill_trust policy on agent-b
load_policy: network_id=1 policy=/tests/fixtures/policies/short_cycle_fill_trust.json (on agent-b)
[2026-04-23 17:01:21] [0;32m[PASS][0m policy loaded (net=1)
[2026-04-23 17:01:21] [1;33m[TEST][0m confirm agent-b starts with 0 trust links
[2026-04-23 17:01:21] [0;32m[PASS][0m trust set empty
[2026-04-23 17:01:21] [1;33m[TEST][0m force cycle
[2026-04-23 17:01:24] [0;32m[PASS][0m cycle forced
[2026-04-23 17:01:24] [1;33m[TEST][0m agent-b logged 'sent trust requests'
[2026-04-23 17:01:24] [0;32m[PASS][0m fill_trust fired
[2026-04-23 17:01:24] [1;33m[TEST][0m agent-a has a pending handshake from agent-b
[2026-04-23 17:01:27] [0;31m[FAIL][0m agent-a pending=0 (want >=1)
Passed: \033[0;32m5\033[0m  Failed: \033[0;31m1\033[0m
```

### `test_partition_heal.sh` (exit=1, 46s)

```
==========================================
Partition then heal: queued ops complete
==========================================
[2026-04-23 17:00:52] [0;32m[PASS][0m both agents registered
[2026-04-23 17:00:54] [0;32m[PASS][0m IPs resolved a=172.29.14.20 b=172.29.14.21
[2026-04-23 17:00:54] [1;33m[TEST][0m pre-submit 3 tasks BEFORE partition (worker paused)
[2026-04-23 17:00:55] [0;32m[PASS][0m pre-submitted 3 task ids
[2026-04-23 17:00:55] [1;33m[TEST][0m install partition a<->b
[2026-04-23 17:00:56] [0;32m[PASS][0m partition effective
[2026-04-23 17:00:57] [1;33m[TEST][0m none of the submitted tasks already completed
[2026-04-23 17:00:57] [0;32m[PASS][0m 0/3 completed during split (correct)
[2026-04-23 17:00:57] [1;33m[TEST][0m heal partition
[2026-04-23 17:01:32] [0;31m[FAIL][0m heal did not restore path
```

### `test_policy_connect_deny.sh` (exit=1, 35s)

```
==========================================
Policy: connect × deny
==========================================
[2026-04-23 17:01:01] [1;33m[TEST][0m Starting stack
[2026-04-23 17:01:05] [0;32m[PASS][0m stack up
[2026-04-23 17:01:05] [1;33m[TEST][0m Apply deny-all connect policy on agent-b
load_policy: network_id=1 policy=/tests/fixtures/policies/deny_all_connect.json (on agent-b)
[2026-04-23 17:01:06] [0;32m[PASS][0m deny-all policy loaded (net=1)
[2026-04-23 17:01:07] [1;33m[TEST][0m echo under deny-all must fail (timeout or refusal)
[2026-04-23 17:01:15] [0;32m[PASS][0m echo refused/timed out under deny policy (rc=124)
[2026-04-23 17:01:15] [1;33m[TEST][0m agent-b logs syn.port_rejected OR port_rejected OR policy deny
assert_policy_event: agent=agent-b event=connect_deny pattern=syn\.port_rejected\|port %d not allowed\|port_rejected count=0 want>=1
[2026-04-23 17:01:17] [0;31m[FAIL][0m no deny events in agent-b logs (expected under deny-all connect)
[2026-04-23 17:01:17] [1;33m[TEST][0m send-message under deny-all must fail
[2026-04-23 17:01:25] [0;32m[PASS][0m send-message refused/timed out (rc=124)
[2026-04-23 17:01:25] [1;33m[TEST][0m send-file under deny-all must fail
[2026-04-23 17:01:36] [0;32m[PASS][0m send-file refused/timed out (rc=124)

==========================================
Passed: \033[0;32m5\033[0m  Failed: \033[0;31m1\033[0m
==========================================
```

### `test_ping_ghost_peer.sh` (exit=1, 43s)

```
==========================================
Ping / send / submit to a ghost peer
==========================================
[2026-04-23 17:00:53] [1;33m[TEST][0m fresh stack
[2026-04-23 17:00:57] [0;32m[PASS][0m both agents registered
[2026-04-23 17:00:57] [1;33m[TEST][0m warm-up ping a->b so agent-a has cached crypto+endpoint
[2026-04-23 17:00:58] [0;32m[PASS][0m tunnel warm
[2026-04-23 17:00:58] [1;33m[TEST][0m SIGKILL agent-b (no graceful unregister)
[2026-04-23 17:01:00] [0;32m[PASS][0m agent-b is dead
[2026-04-23 17:01:00] [1;33m[TEST][0m ping a->b (ghost) fails within --timeout 4s
[2026-04-23 17:01:05] [0;31m[FAIL][0m ping did not bound its own timeout: rc=0 delta=5s
[2026-04-23 17:01:05] [1;33m[TEST][0m send-message a->b (ghost) fails with clear error
[2026-04-23 17:01:15] [0;32m[PASS][0m send-message refused (rc=124)
[2026-04-23 17:01:15] [1;33m[TEST][0m task submit a->b (ghost) — must not report completion
[2026-04-23 17:01:30] [0;32m[PASS][0m submit to ghost peer refused at the front door
[2026-04-23 17:01:30] [1;33m[TEST][0m agent-a has no panic/fatal after ghost attempts
[2026-04-23 17:01:30] [0;32m[PASS][0m agent-a log clean
[2026-04-23 17:01:30] [1;33m[TEST][0m restart agent-b; ping a->b works again
[2026-04-23 17:01:36] [0;32m[PASS][0m ping a->b restored after ghost recovered

==========================================
Ghost-peer summary
==========================================
Passed: [0;32m7[0m
Failed: [0;31m1[0m
==========================================
```

### `test_policy_cycle_webhook.sh` (exit=1, 13s)

```
==========================================
Policy: cycle × webhook
==========================================
[2026-04-23 17:01:30] [0;32m[PASS][0m stack up
[2026-04-23 17:01:30] [1;33m[TEST][0m start a local webhook sink inside agent-b container
[2026-04-23 17:01:32] [0;32m[PASS][0m sink listening on 127.0.0.1:18080
[2026-04-23 17:01:32] [1;33m[TEST][0m restart agent-b daemon with -webhook flag
[2026-04-23 17:01:32] [0;32m[PASS][0m agent-b relaunched with webhook
[2026-04-23 17:01:37] [1;33m[TEST][0m Apply webhook-on-cycle policy
load_policy: cannot resolve agent-b node_id
[2026-04-23 17:01:38] [0;31m[FAIL][0m load
```

### `test_policy_join_allow.sh` (exit=1, 9s)

```
==========================================
Policy: join × allow (schema-level)
==========================================
[2026-04-23 17:01:38] [0;32m[PASS][0m stack up
[2026-04-23 17:01:38] [1;33m[TEST][0m Apply allow-join policy on agent-b
load_policy: network_id=1 policy=/tests/fixtures/policies/join_allow.json (on agent-b)
[2026-04-23 17:01:40] [0;32m[PASS][0m policy loaded (net=1)
[2026-04-23 17:01:40] [1;33m[TEST][0m agent-a joining managed network succeeds
[2026-04-23 17:01:40] [0;32m[PASS][0m join succeeded
[2026-04-23 17:01:40] [1;33m[TEST][0m agent-a member list contains agent-a and agent-b
[2026-04-23 17:01:42] [0;31m[FAIL][0m expected >=2 members, got 0
[2026-04-23 17:01:42] [1;33m[TEST][0m FINDING: join event firing not wired in daemon
    (documented in test comment header)
Passed: \033[0;32m3\033[0m  Failed: \033[0;31m1\033[0m
```

### `test_policy_datagram_deny.sh` (exit=1, 13s)

```
==========================================
Policy: datagram × deny
==========================================
[2026-04-23 17:01:36] [0;32m[PASS][0m stack up
[2026-04-23 17:01:36] [1;33m[TEST][0m Apply deny-all datagram policy on agent-b
load_policy: network_id=1 policy=/tests/fixtures/policies/deny_all_datagram.json (on agent-b)
[2026-04-23 17:01:37] [0;32m[PASS][0m policy loaded (net=1)
[2026-04-23 17:01:37] [1;33m[TEST][0m send datagram under deny — expect failure / timeout
[2026-04-23 17:01:42] [0;32m[PASS][0m send rejected/timed out (rc=1)
[2026-04-23 17:01:42] [1;33m[TEST][0m agent-b logs datagram rejection
assert_policy_event: agent=agent-b event=datagram_deny pattern=datagram\.port_rejected\|datagram: rejected\|datagram.*not allowed count=0 want>=1
[2026-04-23 17:01:44] [0;31m[FAIL][0m no datagram_deny event observed
Passed: \033[0;32m3\033[0m  Failed: \033[0;31m1\033[0m
```

### `test_policy_join_score.sh` (exit=1, 14s)

```
==========================================
Policy: join × score
==========================================
[2026-04-23 17:01:41] [0;32m[PASS][0m stack up
[2026-04-23 17:01:41] [1;33m[TEST][0m Apply score-on-join policy on agent-b
load_policy: network_id=1 policy=/tests/fixtures/policies/join_score.json (on agent-b)
[2026-04-23 17:01:42] [0;32m[PASS][0m policy loaded (net=1)
[2026-04-23 17:01:42] [1;33m[TEST][0m agent-a joins the network
[2026-04-23 17:01:50] [1;33m[TEST][0m agent-a peer score on agent-b reflects +10 join delta
[2026-04-23 17:01:51] [0;31m[FAIL][0m score=0 (want >=10). FINDING: EventJoin not fired by daemon; directive is unreachable.
Passed: \033[0;32m2\033[0m  Failed: \033[0;31m1\033[0m
```

### `test_policy_datagram_score.sh` (exit=1, 37s)

```
==========================================
Policy: datagram × score
==========================================
[2026-04-23 17:01:38] [0;32m[PASS][0m stack up
[2026-04-23 17:01:38] [1;33m[TEST][0m Apply score-on-datagram policy on agent-b
load_policy: network_id=1 policy=/tests/fixtures/policies/score_on_datagram.json (on agent-b)
[2026-04-23 17:01:40] [0;32m[PASS][0m policy loaded (net=1)
[2026-04-23 17:01:40] [1;33m[TEST][0m baseline score (may be empty for fresh peer)
[2026-04-23 17:01:40] [0;32m[PASS][0m baseline score=0
[2026-04-23 17:01:40] [1;33m[TEST][0m drive 5 datagrams from agent-a
[2026-04-23 17:02:07] [0;32m[PASS][0m sent
[2026-04-23 17:02:10] [1;33m[TEST][0m peer score increased
[2026-04-23 17:02:10] [0;31m[FAIL][0m score not increased (base=0 new=0)
Passed: \033[0;32m4\033[0m  Failed: \033[0;31m1\033[0m
```

### `test_race_sendfile_rekey.sh` (exit=1, 23s)

```
==========================================
Race: send-file during forced rekey
==========================================
[2026-04-23 17:02:27] [0;32m[PASS][0m both agents registered
[2026-04-23 17:02:27] [1;33m[TEST][0m create 20 MiB random source on agent-a
[2026-04-23 17:02:29] [0;32m[PASS][0m source ready size=20971520 sha=cd76c063cfe6...
[2026-04-23 17:02:29] [1;33m[TEST][0m launch send-file in background
[2026-04-23 17:02:29] [1;33m[TEST][0m restart agent-b to force rekey mid-transfer
[2026-04-23 17:02:31] [0;32m[PASS][0m agent-b restarted node_id=2
[2026-04-23 17:02:31] [1;33m[TEST][0m wait for sender to return (up to 90 s)
[2026-04-23 17:02:42] [0;32m[PASS][0m sender returned
[2026-04-23 17:02:42] [1;33m[TEST][0m sender reports success OR loud error (never silent corruption)
[2026-04-23 17:02:42] [0;31m[FAIL][0m ambiguous result ok=ok ack= err= raw={"data":{"bytes":20971520,"destination":"0:0000.0000.0002","filename":"rekey-race.bin"},"status":"ok"}
SENDER_DONE
[2026-04-23 17:02:42] [1;33m[TEST][0m no panics in daemon logs
[2026-04-23 17:02:43] [0;32m[PASS][0m clean logs

==========================================
Passed: 5  Failed: 1
==========================================
```

### `test_register_identity_new_endpoint.sh` (exit=1, 6s)

```
==========================================
Identity re-register with new endpoint
==========================================
[2026-04-23 17:03:01] [0;32m[PASS][0m agents up
[2026-04-23 17:03:01] [0;31m[FAIL][0m could not read agent-b endpoint from lookup
```

### `test_sec_ipc_exhaustion.sh` (exit=1, 8s)

```
[2026-04-23 17:03:42] [1;33m[TEST][0m fresh stack
[2026-04-23 17:03:45] [1;33m[TEST][0m attempt 10k concurrent IPC connections
successfully opened IPC conns: 4600
[2026-04-23 17:03:47] [1;33m[TEST][0m daemon still responds to pilotctl info from a NEW connection
[2026-04-23 17:03:49] [0;32m[PASS][0m daemon responsive after IPC exhaustion attempt
[2026-04-23 17:03:49] [1;33m[TEST][0m per-client cap enforced (OPEN should be well below 10000)
[2026-04-23 17:03:49] [0;31m[FAIL][0m no IPC cap detected (4600 conns opened) — see P2-002
[2026-04-23 17:03:49] [1;33m[TEST][0m no agent-a panic on accept() exhaustion
[2026-04-23 17:03:49] [0;32m[PASS][0m no panic/EMFILE in logs

Passed: 2  Failed: 1
```

### `test_ring4_routing.sh` (exit=1, 61s)

```
    00:03:55.143676750 hop host=agent-b path=start,agent-b ttl=2
    resolved "agent-c" → 0:0000.0000.0001
    {
      "ack": "ACK JSON 56 bytes",
      "bytes": 56,
      "target": "0:0000.0000.0001",
      "type": "json"
    }
  === c ring.log ===
    00:03:55.616381333 hop host=agent-c path=start,agent-b,agent-c ttl=1
    resolved "agent-d" → 0:0000.0000.0005
    {
      "ack": "ACK JSON 64 bytes",
      "bytes": 64,
      "target": "0:0000.0000.0005",
      "type": "json"
    }
  === d ring.log ===
    00:03:56.058771958 hop host=agent-d path=start,agent-b,agent-c,agent-d ttl=0
[2026-04-23 17:04:22] [1;33m[TEST][0m final path shows all four hops in order
[2026-04-23 17:04:22] [0;31m[FAIL][0m path wrong: got '' want 'start,agent-b,agent-c,agent-d,agent-a'
[2026-04-23 17:04:22] [1;33m[TEST][0m no panics/fatals
[2026-04-23 17:04:22] [0;32m[PASS][0m clean logs

==========================================
Ring-4 routing summary
==========================================
Passed: [0;32m4[0m
Failed: [0;31m2[0m
==========================================
```

### `test_sec_trust_grant_forgery.sh` (exit=1, 16s)

```
[2026-04-23 17:04:34] [1;33m[TEST][0m fresh stack
[2026-04-23 17:04:37] [1;33m[TEST][0m stand up a fresh sybil daemon identity inside agent-a
forger node_id: 
[2026-04-23 17:04:41] [0;31m[FAIL][0m forger daemon didn't register
time=2026-04-24T00:04:37.878Z level=INFO msg="daemon start: email address required: use -email you@example.com"
[2026-04-23 17:04:41] [1;33m[TEST][0m forger attempts trust grant to agent-b (unrequested)
[2026-04-23 17:04:44] [1;33m[TEST][0m agent-b does NOT auto-trust the forger
[2026-04-23 17:04:44] [0;32m[PASS][0m forger is NOT in trusted list
[2026-04-23 17:04:44] [1;33m[TEST][0m forger with a tampered identity file cannot impersonate
[2026-04-23 17:04:48] [1;33m[TEST][0m agent-b logs show signature verification guard
[2026-04-23 17:04:49] [1;33m[TEST][0m no explicit verification-failure log seen — trust path handled rejection instead
[2026-04-23 17:04:49] [1;33m[TEST][0m agent-b pending handshake count bounded
[2026-04-23 17:04:49] [0;32m[PASS][0m pending queue bounded (0)

Passed: 2  Failed: 1
```

### `test_rendezvous_restart_midflight.sh` (exit=1, 111s)

```
==========================================
Rendezvous restart mid-flight
==========================================
[2026-04-23 17:03:03] [1;33m[TEST][0m Starting p2p stack (clean)
[2026-04-23 17:03:07] [0;32m[PASS][0m both agents registered
[2026-04-23 17:03:07] [1;33m[TEST][0m warm-up task to establish tunnel + peer caches
[2026-04-23 17:03:08] [0;32m[PASS][0m tunnel warm (status=SUCCEEDED)
[2026-04-23 17:03:08] [1;33m[TEST][0m stop rendezvous container (keep agents up)
[2026-04-23 17:03:11] [0;32m[PASS][0m rendezvous stopped; still running: agent-a agent-b 
[2026-04-23 17:03:11] [1;33m[TEST][0m task a->b completes while rendezvous down (30s)
[2026-04-23 17:03:48] [0;31m[FAIL][0m submit during outage failed: {"code":"not_found","error":"cannot resolve \"agent-b\" — is the hostname correct and is there mutual trust? (see: pilotctl handshake)","message":"cannot resolve \"agent-b\" — is the hostname correct and is there mutual trust? (see: pilotctl handshake)","status":"error"}
[2026-04-23 17:03:48] [1;33m[TEST][0m send-file 2 KiB a->b while rendezvous down
[2026-04-23 17:04:09] [0;31m[FAIL][0m file mismatch under outage src=6cd8c1c0a02e... dst=... ack=
[2026-04-23 17:04:09] [1;33m[TEST][0m start rendezvous back up
[2026-04-23 17:04:10] [0;32m[PASS][0m both agents re-registered post-rendezvous-restart (total=2)
[2026-04-23 17:04:10] [1;33m[TEST][0m pilotctl find agent-b from agent-a resolves
[2026-04-23 17:04:17] [0;32m[PASS][0m lookup resolved: 0:0000.0000.0002
[2026-04-23 17:04:17] [1;33m[TEST][0m task a->b completes post-rendezvous-restart
[2026-04-23 17:04:54] [0;31m[FAIL][0m post-restart task stuck (status=)
[2026-04-23 17:04:54] [1;33m[TEST][0m no panics/fatals in agent logs
[2026-04-23 17:04:54] [0;32m[PASS][0m clean logs

==========================================
Rendezvous restart summary
==========================================
Passed: [0;32m6[0m
Failed: [0;31m3[0m
==========================================
```

### `test_sender_clean_restart_midflight.sh` (exit=1, 28s)

```
==========================================
Clean restart of agent-a mid-flight
==========================================
[2026-04-23 17:05:07] [0;32m[PASS][0m both agents registered
[2026-04-23 17:05:09] [1;33m[TEST][0m submit 3 tasks then restart agent-a cleanly
[2026-04-23 17:05:11] [0;32m[PASS][0m agent-a re-registered post-restart
[2026-04-23 17:05:11] [1;33m[TEST][0m agent-a task list --type submitted still works post-restart
[2026-04-23 17:05:11] [0;32m[PASS][0m task list ok
[2026-04-23 17:05:11] [1;33m[TEST][0m fresh task submit post-restart completes
[2026-04-23 17:05:28] [0;31m[FAIL][0m fresh task stuck post-restart (status=)
[2026-04-23 17:05:28] [1;33m[TEST][0m fresh send-file post-restart
[2026-04-23 17:05:30] [0;32m[PASS][0m file sha match post-restart
[2026-04-23 17:05:30] [1;33m[TEST][0m no panic/fatal
[2026-04-23 17:05:30] [0;32m[PASS][0m clean logs

Passed: 5  Failed: 1
```

### `test_splitbrain_heal.sh` (exit=1, 82s)

```
==========================================
Split-brain heal
==========================================
[2026-04-23 17:06:18] [1;33m[TEST][0m Starting splitbrain stack
[2026-04-23 17:06:22] [0;32m[PASS][0m 2+2 split confirmed
[2026-04-23 17:06:23] [1;33m[TEST][0m while split: a submits to c must fail cleanly
[2026-04-23 17:06:23] [0;32m[PASS][0m submit correctly failed under split (code=not_found)
[2026-04-23 17:06:23] [1;33m[TEST][0m heal: migrate agent-c and agent-d onto rendezvous-1
[2026-04-23 17:07:39] [0;31m[FAIL][0m heal failed — rv-1 sees 2 nodes
  c: Error response from daemon: No such container: pilot-w5-healed-agent-c
```

### `test_task_executor.sh` (exit=1, 14s)

```
[2026-04-23 17:08:12] [1;33m[TEST][0m start auto-accept worker on agent-b
[2026-04-23 17:08:14] [0;32m[PASS][0m worker started on agent-b
[2026-04-23 17:08:14] [1;33m[TEST][0m agent-a submits T1 (polo should allow)
[2026-04-23 17:08:14] [0;32m[PASS][0m T1 submitted: 7b597ce3-c2ce-94a8-76ab-a06c01388218
[2026-04-23 17:08:15] [1;33m[TEST][0m T1 reaches completed/succeeded on submitter
[2026-04-23 17:08:15] [0;32m[PASS][0m submitter sees T1 status=SUCCEEDED
[2026-04-23 17:08:15] [1;33m[TEST][0m pilotctl task result returns correlated payload
[2026-04-23 17:08:15] [0;32m[PASS][0m T1 result correlates: "done: compute-fibonacci"
[2026-04-23 17:08:15] [1;33m[TEST][0m polo gate rejects second a -> b submit with too-low score
[2026-04-23 17:08:16] [0;31m[FAIL][0m polo gate did not block (accepted=false message=Task rejected by polo gate: submitter polo below receiver polo)
[2026-04-23 17:08:16] [1;33m[TEST][0m enable-tasks on agent-a for reverse flow
[2026-04-23 17:08:17] [1;33m[TEST][0m agent-b submits B1 to agent-a (should be allowed)
[2026-04-23 17:08:18] [0;32m[PASS][0m B1 submitted: 75e94193-86d8-6ed6-7509-5689136f4f3d
[2026-04-23 17:08:19] [1;33m[TEST][0m B1 completes on agent-b
[2026-04-23 17:08:19] [0;32m[PASS][0m agent-b sees B1 status=SUCCEEDED
[2026-04-23 17:08:19] [1;33m[TEST][0m balanced exchange restores polo, a can submit again
[2026-04-23 17:08:19] [0;32m[PASS][0m post-balance submit accepted: 9440975e-c4ad-b897-83ec-f25cd7b23ee1
[2026-04-23 17:08:21] [1;33m[TEST][0m post-balance task result correlates
[2026-04-23 17:08:21] [0;32m[PASS][0m post-balance result correlates
[2026-04-23 17:08:21] [1;33m[TEST][0m pilotctl task result on missing id returns clean error
[2026-04-23 17:08:21] [0;32m[PASS][0m missing-id handled cleanly
[2026-04-23 17:08:21] [1;33m[TEST][0m no panics/fatals in daemon logs
[2026-04-23 17:08:21] [0;32m[PASS][0m clean logs

==========================================
Task-executor test summary
==========================================
Passed: [0;32m12[0m
Failed: [0;31m1[0m
==========================================
```

### `test_size_task_result_10mb.sh` (exit=1, 204s)

```
==========================================
Large payload: 10 MiB task result
==========================================
[2026-04-23 17:05:47] [0;32m[PASS][0m both agents registered
[2026-04-23 17:05:47] [1;33m[TEST][0m agent-a submits task
[2026-04-23 17:05:47] [0;32m[PASS][0m tid=c203c58f-6147-5a8f-fe16-1e158d29e1f3
[2026-04-23 17:05:47] [1;33m[TEST][0m agent-b accepts
[2026-04-23 17:05:48] [0;32m[PASS][0m accepted
[2026-04-23 17:05:48] [1;33m[TEST][0m agent-b builds 10 MiB result and sends
[2026-04-23 17:05:48] [0;32m[PASS][0m result sz=10485760 sha=2f778f13322a...
[2026-04-23 17:06:11] [0;32m[PASS][0m send-results ok
[2026-04-23 17:06:11] [1;33m[TEST][0m agent-a sees status SUCCEEDED within 120s
[2026-04-23 17:09:06] [0;31m[FAIL][0m status='EXPIRED' (expected SUCCEEDED)
[2026-04-23 17:09:06] [1;33m[TEST][0m result sha256 matches on submitter side
    best-effort sha: a=e3b0c44298fc... want=2f778f13322a...
[2026-04-23 17:09:07] [0;32m[PASS][0m status propagated; sha check best-effort only
[2026-04-23 17:09:07] [1;33m[TEST][0m no panics
[2026-04-23 17:09:07] [0;32m[PASS][0m clean logs

Passed: 7  Failed: 1
```

### `test_tasks_and_edge.sh` (exit=1, 13s)

```
[2026-04-23 17:09:13] [0;32m[PASS][0m task queue ok
[2026-04-23 17:09:13] [1;33m[TEST][0m send-message type=json
[2026-04-23 17:09:13] [0;32m[PASS][0m send-message JSON ack ok
[2026-04-23 17:09:13] [1;33m[TEST][0m send-message type=binary
[2026-04-23 17:09:13] [0;32m[PASS][0m send-message binary ack ok
[2026-04-23 17:09:13] [1;33m[TEST][0m send-file and verify byte count
[2026-04-23 17:09:14] [0;32m[PASS][0m send-file 10240 bytes acked (10240)
[2026-04-23 17:09:14] [1;33m[TEST][0m inbox has at least 2 message entries (JSON + binary text)
[2026-04-23 17:09:14] [0;32m[PASS][0m inbox has 2 entries
[2026-04-23 17:09:14] [1;33m[TEST][0m received/ has the binary file delivered by send-file
[2026-04-23 17:09:14] [0;32m[PASS][0m received/ has 1 file(s)
[2026-04-23 17:09:14] [1;33m[TEST][0m inbox --clear empties the inbox
[2026-04-23 17:09:15] [0;32m[PASS][0m inbox cleared (was 2 now 0)
[2026-04-23 17:09:15] [1;33m[TEST][0m ping unknown hostname returns clear error
[2026-04-23 17:09:15] [0;32m[PASS][0m unknown hostname rejected cleanly
[2026-04-23 17:09:15] [1;33m[TEST][0m send missing --data flag returns invalid_argument
[2026-04-23 17:09:15] [0;32m[PASS][0m missing --data rejected with invalid_argument
[2026-04-23 17:09:15] [1;33m[TEST][0m set-hostname with bad characters rejected
[2026-04-23 17:09:16] [0;32m[PASS][0m invalid hostname rejected (status=error)
[2026-04-23 17:09:16] [1;33m[TEST][0m lookup of nonexistent node_id returns error
[2026-04-23 17:09:16] [0;32m[PASS][0m lookup of ghost node fails cleanly
[2026-04-23 17:09:16] [1;33m[TEST][0m pilotctl version
[2026-04-23 17:09:16] [0;32m[PASS][0m version: dev

==========================================
Tasks/Edge Test Summary
==========================================
Passed: [0;32m18[0m
Failed: [0;31m1[0m
==========================================
```

### `test_webhook_message_received.sh` (exit=1, 34s)

```
[2026-04-23 17:09:32] [0;32m[PASS][0m both agents registered
[2026-04-23 17:09:32] [1;33m[TEST][0m configure agent-b webhook
[2026-04-23 17:09:32] [0;32m[PASS][0m webhook set
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
[2026-04-23 17:09:44] [1;33m[TEST][0m agent-a sends exactly one message to agent-b
[2026-04-23 17:09:45] [0;32m[PASS][0m send-message ok
service "webhook-sink" is not running
[2026-04-23 17:09:57] [1;33m[TEST][0m exactly one message.received webhook (delta=0)
[2026-04-23 17:09:57] [0;31m[FAIL][0m expected delta=1 got 0
Passed: 3  Failed: 1
```

### `test_webhook_polo_updated.sh` (exit=1, 37s)

```
[2026-04-23 17:09:42] [0;32m[PASS][0m webhooks set
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
[2026-04-23 17:09:54] [1;33m[TEST][0m submit one task to trigger a polo delta
service "webhook-sink" is not running
[2026-04-23 17:10:07] [1;33m[TEST][0m exactly one polo.updated webhook (delta=0)
[2026-04-23 17:10:07] [0;31m[FAIL][0m expected delta=1 got 0 (event likely not wired)
Passed: 1  Failed: 1
```

### `test_webhook_pubsub_published.sh` (exit=1, 27s)

```
[2026-04-23 17:09:54] [0;32m[PASS][0m agent-b webhook set
[2026-04-23 17:09:54] [1;33m[TEST][0m agent-a publishes one event to agent-b on topic 'sensor/wh'
[2026-04-23 17:09:54] [0;32m[PASS][0m publish ok
[2026-04-23 17:10:06] [1;33m[TEST][0m exactly one pubsub.published webhook (delta=0)
[2026-04-23 17:10:06] [0;31m[FAIL][0m expected delta=1 got 0
Passed: 2  Failed: 1
```

### `test_webhook_tunnel_established.sh` (exit=1, 34s)

```
[2026-04-23 17:10:17] [0;32m[PASS][0m webhooks set
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
[2026-04-23 17:10:28] [1;33m[TEST][0m agent-a pings agent-b (warms tunnel)
[2026-04-23 17:10:30] [0;32m[PASS][0m ping ok
service "webhook-sink" is not running
[2026-04-23 17:10:42] [1;33m[TEST][0m at least 2 tunnel.established webhooks (one per side) (delta=0)
[2026-04-23 17:10:42] [0;31m[FAIL][0m expected delta>=2 got 0
Passed: 2  Failed: 1
```

### `test_webhook_trust_changed.sh` (exit=1, 48s)

```
[2026-04-23 17:10:07] [0;32m[PASS][0m webhooks set on a+b
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
[2026-04-23 17:10:18] [1;33m[TEST][0m handshake a->b (trust granted)
service "webhook-sink" is not running
[2026-04-23 17:10:33] [1;33m[TEST][0m at least one grant event observed (got=)
test_webhook_trust_changed.sh: line 63: [: : integer expression expected
[2026-04-23 17:10:33] [0;31m[FAIL][0m no grant event fired
[2026-04-23 17:10:33] [1;33m[TEST][0m untrust b on agent-a (trust revoked)
service "webhook-sink" is not running
service "webhook-sink" is not running
[2026-04-23 17:10:46] [0;31m[FAIL][0m no revoke event fired
[2026-04-23 17:10:46] [1;33m[TEST][0m canonical 'trust.changed' event present
service "webhook-sink" is not running
test_webhook_trust_changed.sh: line 81: [: : integer expression expected
[2026-04-23 17:10:46] [0;31m[FAIL][0m trust.changed NOT wired (saw only handshake.* and trust.revoked variants)
Passed: 1  Failed: 3
```

### `test_resilience.sh` (exit=1, 1217s)

```
==========================================
Resilience / restart / concurrency tests
==========================================
[2026-04-23 17:03:09] [1;33m[TEST][0m 50 parallel echo roundtrips from agent-a to agent-b
[2026-04-23 17:03:15] [0;32m[PASS][0m 50/50 echo roundtrips ok
[2026-04-23 17:03:15] [1;33m[TEST][0m restart agent-b and confirm it re-registers
[2026-04-23 17:03:24] [0;32m[PASS][0m agent-b re-registered (was 2, now 2)
[2026-04-23 17:03:24] [1;33m[TEST][0m echo to agent-b recovers after restart (poll ≤4min)
[2026-04-23 17:23:05] [0;31m[FAIL][0m post-restart echo never recovered in 4 minutes
[2026-04-23 17:23:05] [1;33m[TEST][0m restart rendezvous and confirm agents reconnect (≤4min)
[2026-04-23 17:23:06] [0;32m[PASS][0m both agents reconnected after rendezvous restart (total_nodes=2, ~1×5s)
[2026-04-23 17:23:06] [1;33m[TEST][0m agent-a process survived 60s+ of activity
[2026-04-23 17:23:06] [0;32m[PASS][0m agent-a pid 1 alive, RSS 15612 KB
[2026-04-23 17:23:06] [1;33m[TEST][0m pulse endpoint shows non-zero total_requests
[2026-04-23 17:23:06] [0;31m[FAIL][0m pulse flat: total_requests=1068 samples=0
[2026-04-23 17:23:06] [1;33m[TEST][0m concurrent send-message agent-a→b and agent-b→a
[2026-04-23 17:23:22] [0;32m[PASS][0m concurrent bidirectional send-message completed
[2026-04-23 17:23:22] [1;33m[TEST][0m agent logs free of panic/fatal
[2026-04-23 17:23:22] [0;32m[PASS][0m no panic/fatal/race in recent logs

==========================================
Resilience Test Summary
==========================================
Passed: [0;32m6[0m
Failed: [0;31m2[0m
==========================================
```

