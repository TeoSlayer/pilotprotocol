# Integration test suite — problem registry

Findings from `iter10` (hybrid DaemonSet+DooD run, 231 Jobs on Jetson
k3s cluster, fired 2026-04-22). Registry covers **test-script and test-data
bugs** surfaced by running the full suite; **not** Pilot protocol bugs
(those live at `.claude/PROBLEM-REGISTRY.md`).

Severity legend:
- **P0** — blocks a whole test category, architectural fix needed
- **P1** — single-test bug, fails deterministically
- **P2** — flake under load, passes in isolation
- **P3** — cosmetic / non-gating

---

## P0 — category-wide test-script failures

### P0-000 — node-2 DiskPressure → DaemonSet eviction (infra)
**Seen**: iter10 run aborted at ~9min. worker-node-2 hit
`DiskPressure` (root eMMC at 91% → kubelet tainted node → DaemonSet
pod `iter10-node-docker-lgt4z` evicted with reason
`Pod was rejected: The node had condition: [DiskPressure]`).

**Root cause**: Jetson nodes have eMMC (57G) at `/` and NVMe
(79G–1.8T) at `/mnt/nvme`. Chart defaults point `hostPath` at
`/var/lib/pilot-docker`, `/var/lib/pilot-workspace`, and
`/var/lib/pilot-preloaded` — all on eMMC. Under concurrent DooD load,
the shared dockerd's overlay2 graph + 50+ compose project workspaces
fill eMMC faster than the kubelet's image-GC can keep up. Cross-node
eMMC state post-abort: node-2 90% / node-3 94% / node-4 78% / node-10
65% — two nodes at/near the DiskPressure threshold, dockerd-data on
those nodes will no-op writes if not reclaimed.

**Fix scope**: move 3 `hostPath` roots to `/mnt/nvme/pilot-*`:
- `templates/node-docker-daemonset.yaml` `docker-graph` volume
  (hard-coded `/var/lib/pilot-docker` — either templatise via
  values.nodeDocker.dataRoot or just change the path)
- `workspaceHostPath.path` in values.yaml (already a variable)
- `preloadedHostPath.path` in values.yaml (already a variable)

Also need an explicit `rm -rf /var/lib/pilot-docker` cleanup on each
node before next run to reclaim the eMMC space already consumed.

**Side effect**: the aborted run's leftover eMMC data will cause any
node that still has it to fail k3s kubelet checks until cleaned.

**Status 2026-04-22**: chart changed — `nodeDocker.dataRoot` added
to `values.yaml` (default `/mnt/nvme/pilot-docker`),
`workspaceHostPath.path` switched to `/mnt/nvme/pilot-workspace`.
Preloaded tars left on eMMC (small, static, don't grow). Still
pending: destructive `rm -rf /var/lib/pilot-docker` on each node to
reclaim the 45+ GB already consumed per node. Next install will
auto-create fresh paths on NVMe.

---

### P0-001 — `net-*-shipped` tests: "stack boot" failure
**Seen**: 7/~8 net-*-shipped tests failed within 30s of start.
- net-cooling-off-shipped
- net-fifo-shipped
- net-gift-economy-shipped
- net-half-life-shipped
- net-sybil-gauntlet-shipped
- net-trust-decay-shipped
- net-whale-hunt-shipped (2 attempts, both failed)

**Symptom**: runner prints `[FAIL] stack boot` then exits rc=1 ≤10s
after start. No compose logs retained — cleanup ran on exit trap.

**Likely cause**: the three shipped-network configs (trust-decay,
high-trust-society, data-exchange-policy) use a two-step create
(unmanaged → policy set) via `network_helpers.sh`. Other shipped-
network scripts likely hardcode the one-shot `--rules-file` path,
which expects `NetworkRules`, not the `expr_policy` schema shipped
configs use. See memory: `project_shipped_networks_helper.md`.

**Fix scope**: each `test_net_*_shipped.sh` needs to switch to the
two-step helper. Likely a shared `_lib.sh` change or per-script sed.

---

### P0-002 — `gateway-*` tests: only runner registers, not a/b/gateway
**Seen**: gateway-ping, gateway-pubsub-sub, gateway-register,
gateway-task-result (×2).

**Symptom**: test waits for ≥3 nodes registered (agent-a, agent-b,
gateway), sees 0 or 1. Fails at `[FAIL] only <N> nodes registered`
or `[FAIL] gateway daemon info missing node_id: service "gateway"
is not running`.

**Likely cause**: test script assumes `docker compose up` brought up
the full gateway stack but the script itself doesn't invoke compose
up. Same root cause as P0-003 (pattern: compose-up is done by a
wrapper that existed in DinD-era local runs, but in k8s under DooD
each runner executes the script directly).

**Fix scope**: add `$DC up -d rendezvous agent-a agent-b gateway` at
top of each gateway test, or add a `PILOT_COMPOSE_FILE` +
`PILOT_COMPOSE_SERVICES` convention to `_lib.sh` and call it from a
pre-script hook in `job.yaml`.

---

### P0-003 — compose-native tests missing `docker compose up`
**Seen**: `test_p2p.sh` (confirmed during smoke — hung indefinitely
on "Waiting for agent-a and agent-b to register"). Unknown how many
other compose-native scripts have the same pattern.

**Symptom**: runner starts, script assumes stack is up, loops 60s
waiting for agents that never register, fails or times out.

**Distinction from P0-002**: P0-002 scripts do have compose-related
plumbing but the wrong service set / wrong file. P0-003 scripts have
no compose-up invocation at all.

**Fix scope**: audit all compose-native `test_*.sh` for a
`docker compose up` call. Either add one, or centralise in a hook.

---

## P1 — single-test bugs

### P1-001 — `test_beacon_ping.sh` endpoint race
**Seen**: smoke run (beacon-ping isolation test, 2026-04-22 ~18:58Z)
and confirmed reproducible under zero load.

**Symptom**: 3/4 subtests pass; subtest "agent-a has a non-empty
observed endpoint" fails — info JSON has no `.data.endpoint` field
because the agent was queried immediately after first registration,
before the beacon discover reply had populated its public endpoint.

**Fix**: add a poll loop (`for i in seq 1 30; ENDPOINT=...; [ -n
"$ENDPOINT" ] && break; sleep 1; done`) before the assertion.

---

### P1-002 — `policy-join-deny` stack boot
**Seen**: iter10 2026-04-22 19:29Z.

**Symptom**: `[FAIL] stack` at start.

**Likely cause**: related to P0-001 shipped-config pattern OR its own
compose file reference.

**Fix scope**: TBD — needs test-script read.

---

## P2 — under investigation

Will be added as the iter10 run completes and triage classifies
flake-vs-deterministic. Planned sweep: once the run finishes, group
all failed Jobs by exit reason and re-run each solo to split
P1 (deterministic) from P2 (load flake).

---

## P3 — cosmetic

_(none yet)_

---

## Closed / out of scope

### Closed — `iter8`: Class-A boltdb timeouts at parallelism=48
**Original cause**: 48 concurrent DinD pods racing containerd boltdb
open; boltdb has hard 10s lock timeout.

**Resolution**: iter10 hybrid architecture — 21 DinD (NAT tests that
need per-pod kernel netns for iptables isolation) + 210 DooD
(share host dockerd via DaemonSet socket). Worst-case concurrent
DinD at full run = 5/node, well under the contention floor.

Not filed as a P — this was an infrastructure fix, not a bug in the
current suite.

---

## How to update this file

1. When a test fails on a run, log the first 10 lines of its `[FAIL]
   ...` message + `rc=` line here.
2. Match against existing entries; merge if it's a duplicate.
3. If you find a new pattern, give it the next sequential P<n>-NNN
   ID and describe scope.
4. When a fix lands, move the entry under "Closed / out of scope"
   with the commit hash of the fix.
