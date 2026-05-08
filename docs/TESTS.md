# Pilot Protocol — Test Reference

## Running Tests

```bash
go test -parallel 4 -count=1 ./tests/
```

**IMPORTANT:** `-parallel 4` is required. Unlimited parallelism exhausts UDP ports/sockets.

## Test Infrastructure

**testenv.go** — In-process test environment
- `NewTestEnv(t)`: Spawns beacon + registry on OS-assigned ports
- `AddDaemon()`: Creates in-process daemon + IPC driver
- `resolveLocalAddr()`: Converts wildcard to `127.0.0.1`
- `setClientSigner()`: Configure registry auth signing

## Test Files by Category

### Protocol & Wire Format
| File | Tests |
|------|-------|
| protocol_test.go | Address parsing/string conversion, socket address formatting |
| protocol_version_test.go | Protocol version validation |
| frame_test.go | Packet header construction, flags, checksums |
| event_wire_test.go | Event stream wire protocol serialization |

### Transport & Reliability
| File | Tests |
|------|-------|
| retransmit_test.go | TCP-style retransmission on packet loss |
| sack_test.go | Selective acknowledgment (SACK) |
| window_test.go | Sliding window flow control |
| zerowindow_test.go | Receiver zero-window probing |
| nagle_test.go | Nagle algorithm (delay small segments) |
| segmentation_test.go | Auto-fragmentation for large payloads |
| datagram_test.go | Unreliable datagram delivery |

### Security & Encryption
| File | Tests |
|------|-------|
| crypto_test.go | Ed25519 key gen, signing, encoding, identity persistence |
| secure_test.go | X25519+AES-256-GCM encrypted connections (port 443) |
| secure_unit_test.go | Low-level encryption/decryption |
| secure_auth_test.go | Authenticated secure connections |
| tunnel_encrypt_test.go | Tunnel-level encryption (all inter-daemon packets) |
| handshake_test.go | P2P trust negotiation (Ed25519 signed mutual handshake) |
| key_lifecycle_test.go | Key rotation and lifecycle management |
| syn_trust_gate_test.go | SYN trust gating (only trusted peers can connect) |

### Features & Services
| File | Tests |
|------|-------|
| dataexchange_test.go | Typed frame protocol (port 1001) |
| eventstream_test.go | Pub/sub event broker (port 1002) |
| tasksubmit_test.go | Task submission with polo scoring (port 1003) |
| task_exec_test.go | Task execution lifecycle |
| task_files_test.go | Task file persistence and management |

### Network Operations
| File | Tests |
|------|-------|
| integration_test.go | Full end-to-end daemon communication |
| concurrent_test.go | Multiple concurrent connections/messages |
| nat_traversal_test.go | STUN + NAT hole-punching (beacon relay) |
| broadcast_test.go | Broadcast messaging |
| network_test.go | Network creation and isolation |
| network_policy_test.go | Network policy enforcement |
| auto_join_test.go | Auto-join networks on startup |
| invite_acceptance_test.go | Network invite acceptance/rejection |
| pilotctl_network_test.go | Network operations via pilotctl |

### Lifecycle & Reliability
| File | Tests |
|------|-------|
| lifecycle_test.go | Connection states (SYN/ACK, graceful FIN shutdown) |
| shutdown_test.go | Daemon shutdown, pending connection cleanup |
| stress_test.go | High-volume message stress |
| limits_test.go | Edge cases (max node ID, address overflow) |
| peer_resilience_test.go | Peer reconnection and resilience |
| health_endpoint_test.go | Health endpoint responses |
| driver_listener_test.go | Driver listener lifecycle |

### Persistence & State
| File | Tests |
|------|-------|
| persistence_test.go | Registry snapshot atomic writes |
| snapshot_test.go | Snapshot format and restoration |
| replication_test.go | Hot-standby registry replication |
| identity_test.go | Identity file loading/saving |
| config_test.go | JSON config file parsing |

### Privacy, Trust & Discovery
| File | Tests |
|------|-------|
| privacy_test.go | Nodes private by default, trust-gated resolution |
| hostname_privacy_test.go | Hostname privacy with trust gates |
| admin_token_test.go | Admin operations require token |
| hostname_test.go | Claim/release hostnames, registration feedback |
| reregistration_test.go | Re-register after restart |
| tags_test.go | Tagged node metadata |
| email_required_test.go | Email required for registration |

### Enterprise & RBAC
| File | Tests |
|------|-------|
| rbac_test.go | Role-based access control |
| enterprise_gate_test.go | Enterprise feature gating |
| audit_test.go | Audit trail for admin operations |
| admin_cli_test.go | Admin CLI operations |
| registry_hardening_test.go | Registry security hardening |

### Advanced
| File | Tests |
|------|-------|
| ipv6_test.go | IPv6 beacon support (SKIPPED) |
| ratelimit_test.go | Sliding window rate limiter |
| polo_score_test.go | Polo network scoring |
| metrics_test.go | Structured logging metrics |
| commands_test.go | CLI pilotctl commands |
| ipc_test.go | Daemon↔client IPC |
| ipc_ops_test.go | IPC operations coverage |
| gateway_test.go | IP-to-Pilot bridge |
| nameserver_test.go | DNS-equivalent resolution |
| dashboard_test.go | Web dashboard |
| webhook_test.go | Webhook callbacks |
| webhook_reliability_test.go | Webhook retry and reliability |
| beacon_registry_test.go | Beacon and registry integration |

### Fuzz Tests
| File | Tests |
|------|-------|
| fuzz_beacon_test.go | Beacon message fuzzing |
| fuzz_config_test.go | Config parsing fuzzing |
| fuzz_crypto_test.go | Crypto operations fuzzing |
| fuzz_daemon_test.go | Daemon message fuzzing |
| fuzz_frames_test.go | Wire frame fuzzing |
| fuzz_fsutil_pool_test.go | File util and pool fuzzing |
| fuzz_gateway_test.go | Gateway fuzzing |
| fuzz_ipc_test.go | IPC protocol fuzzing |
| fuzz_nameserver_test.go | Nameserver fuzzing |
| fuzz_nameserver_records_test.go | Nameserver record fuzzing |
| fuzz_protocol_test.go | Protocol message fuzzing |
| fuzz_registry_test.go | Registry client fuzzing |
| fuzz_registry_server_test.go | Registry server fuzzing |
| fuzz_secure_test.go | Secure channel fuzzing |
| fuzz_tasksubmit_test.go | Task submit fuzzing |
| fuzz_webhook_test.go | Webhook fuzzing |

## Stats
- **86 test files**, 683+ tests (657 PASS, 26 SKIP)
- All tests use `t.Parallel()`, table-driven patterns, timeouts on blocking ops
- 16 fuzz test files for protocol robustness

## Examples

### Go Examples (`examples/go/`)
- **client**: `driver.DialAddr()` → Write/Read
- **secure**: X25519+AES-GCM server/client (port 443)
- **echo**: `driver.Listen(7)` → Accept → echo loop
- **webserver**: `http.Serve(pilotListener, mux)` on port 80
- **httpclient**: HTTP client over Pilot Protocol
- **dataexchange**: Typed frame exchange (port 1001)
- **eventstream**: Pub/sub event stream (port 1002)
- **config**: JSON config templates

### Python SDK Examples (`examples/python_sdk/`)
- **basic_usage.py**: Basic client usage
- **data_exchange_demo.py**: Data exchange protocol
- **event_stream_demo.py**: Event stream subscription
- **task_submit_demo.py**: Task submission workflow
- **pydantic_ai_agent.py**: PydanticAI agent integration
- **pydantic_ai_multiagent.py**: Multi-agent PydanticAI setup

### CLI Examples (`examples/cli/`)
- **BASIC_USAGE.md**: Step-by-step CLI usage guide
