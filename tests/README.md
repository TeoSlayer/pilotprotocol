# tests/

Daemon integration tests, organised by what they need to run.

## Layout

```
tests/
├── testenv.go                # Go test harness (boots a registry + daemons)
├── regtestutil/              # In-process registry fixture (used by Go tests)
│
├── zz_*_test.go              # 111 cross-component Go integration tests
├── compat/                   # 2 Go files — WSS↔UDP transport bridge
│
├── daemon/                   # Go: 5 daemon-internal regressions (candidates to fold into pkg/daemon)
├── internal/                 # Go: 4 tests of internal packages (candidates to fold or move)
├── pkg/                      # Go: 12 tests that should live next to pkg/X/_test.go
├── plugins/                  # Go: 1 test that should live in pilot-protocol/policy
│
├── end-to-end/               # Pilotctl smoke runner (run_tests.sh)
└── integration/              # Docker-based real-network suite
    ├── Dockerfile.multi      # Build daemon+rendezvous+pilotctl+gateway container
    ├── Dockerfile.nat-gw     # Build NAT gateway container
    ├── docker-compose.*.yml  # 10 top-level mesh scenarios
    ├── fixtures/policies/    # 14 JSON policy fixtures
    ├── test_*.sh             # 75 scripts (suite #1 — older)
    └── local/                # 199 scripts + 20 compose (suite #2 — newer)
```

## How each tier runs

| Tier | Command | Purpose | Status |
|---|---|---|---|
| **Go unit** | `go test ./...` (from repo root) | Pure-Go, no daemon process | ✅ green |
| **Go integration** | `go test -count=1 ./tests/` | Boots daemon + in-process registry via `testenv.go` | ✅ green |
| **Compat (WSS↔UDP)** | `go test ./tests/compat/...` | Cross-transport bridging using real beacon | ✅ green |
| **Benches** | `go test -bench=. ./tests/` | Throughput / latency / recovery time | works |
| **Docker integration** | `make integration` → `cd tests/integration && make test` | Real network: NAT, chaos, multi-node, gateway-in-docker | ❌ **BROKEN** — `Dockerfile.multi` builds `./cmd/rendezvous` and `./cmd/gateway` which no longer exist in web4 (extracted to sibling repos). Needs the fix below. |
| **Pilotctl smoke** | `bash tests/end-to-end/run_tests.sh` | CLI flow check | needs daemon + pilotctl on PATH |

## What's broken right now

1. **`Dockerfile.multi`** at `tests/integration/Dockerfile.multi:4-7`:
   ```dockerfile
   RUN go build -o /bin/pilot-rendezvous ./cmd/rendezvous && \
       go build -o /bin/pilot-daemon    ./cmd/daemon && \
       go build -o /bin/pilotctl        ./cmd/pilotctl && \
       go build -o /bin/pilot-gateway   ./cmd/gateway
   ```
   `./cmd/rendezvous` and `./cmd/gateway` are gone — extracted to `pilot-protocol/rendezvous` and `pilot-protocol/gateway`.

2. **No CI workflow runs the docker suite.** `.github/workflows/*.yml` does not call `make integration` or any path under `tests/integration/`. Only `Makefile` + `.github/workflows/README.md` mention it.

3. **Two parallel docker suites.** `tests/integration/` (75 .sh + 10 compose) and `tests/integration/local/` (199 .sh + 20 compose). **9 of the 10 docker-compose files exist in BOTH directories with diverged content.** Suite #2 (`local/`) is the newer, more active one.

## Recently removed

- `tests/integration/k8s/` — Helm chart + Dockerfile.runner + 13 tracked files + 439 MB of untracked docker-image tarballs. The k8s-based runner was unused by CI and the helm chart was orphaned. Deleted in commit `<latest>`.

- `tests/integration/logs-run.out` — orphan test-run log. Now in `.gitignore`.

## Refactoring plan

### Phase 1 — Unbreak the Docker suite (~30 min)

Fix `Dockerfile.multi` to fetch the extracted binaries instead of building them from local source. Two approaches:

- **(a) `go install` from tagged siblings** — simplest:
  ```dockerfile
  RUN go install github.com/pilot-protocol/rendezvous/cmd/rendezvous@v0.1.0 && \
      go install github.com/pilot-protocol/gateway/cmd/gateway@v0.1.0
  ```

- **(b) Download release tarballs** — needs `gh` or `curl` in the build context. More moving parts.

Same fix for any helper Dockerfile in `tests/integration/local/`.

### Phase 2 — Consolidate the two suites (~half a day)

Pick one. The decision: **suite #2 (`local/`) is the canonical one** going forward. It's larger, more recent, and has scenario-specific coverage (NAT variants, chaos, race conditions) the root suite lacks.

- For each compose file that exists in both: keep the `local/` version, delete the root duplicate.
- Move the 75 scripts at `tests/integration/` root that are NOT duplicated into `tests/integration/local/`.
- Result: a single suite under `tests/integration/local/`. Top-level `tests/integration/` keeps only the Dockerfiles + `fixtures/`.

### Phase 3 — Reorg for clarity (~1 hour)

```
tests/
├── README.md
├── testenv.go
├── regtestutil/
│
├── *_test.go                 # Go integration tests
├── compat/                   # WSS↔UDP bridge
├── benches/                  # MOVE all zz_bench_*.go here (8 files)
│
├── cli/                      # RENAMED from end-to-end/
│
└── docker/                   # RENAMED from integration/
    ├── README.md             # NEW — describes each scenario
    ├── Dockerfile.multi
    ├── Dockerfile.nat-gw
    ├── fixtures/policies/
    └── scenarios/            # RENAMED from local/
        ├── docker-compose.*.yml
        └── test_*.sh
```

### Phase 4 — Fold/move per-package tests (~1 hour)

Per the audit in this README's git history:
- `tests/daemon/*` → fold into `pkg/daemon/_test.go`
- `tests/internal/account` → fold into `internal/account/`
- `tests/internal/validate` → fold into `internal/validate/`
- `tests/internal/fsutil` → move to `pilot-protocol/common/fsutil/`
- `tests/internal/policy` → move to `pilot-protocol/policy/policylang/`
- `tests/pkg/coreapi` → fold into `pkg/coreapi/`
- `tests/pkg/logging` → fold into `pkg/logging/`
- `tests/pkg/config` → fold into `pkg/config/`
- `tests/pkg/registry/wire/*` → fold into `pkg/registry/wire/`
- `tests/pkg/secure/*` → fold into `pkg/secure/`
- `tests/pkg/urlvalidate` → fold into `pkg/urlvalidate/`
- `tests/pkg/registry/server/*` → move to `pilot-protocol/rendezvous/`
- `tests/plugins/policy/*` → move to `pilot-protocol/policy/`

After: every package's `_test.go` lives next to its implementation; `tests/` contains only cross-component integration tests.

### Phase 5 — Wire docker suite into CI (~1 hour, after Phase 1)

Add a new `.github/workflows/integration-docker.yml` that runs `make test-integration-quick` on push to main (Tier 2 of the Makefile — ~10min budget). Tier 3 (`test-integration-full`, ~30min) on a schedule (nightly).

## Things to think about (open questions)

- **The fuzz corpus.** ~15 `tests/zz_fuzz_*_test.go` files have `testdata/fuzz/<FunctionName>/` siblings that hold accumulated corpus. After moving fuzz tests into per-package locations, the corpus must move with them or be regenerated.
- **`tests/zz_registry_loadtest_test.go`** is gated behind `//go:build loadtest` and is not run by `go test ./tests/...` by default. Keep it that way; it's a deliberate manual-trigger load probe.
- **`tests/integration/local/` Python scripts.** Three `.py` files under `local/` — not Go, not shell. Worth understanding what they do before they get caught in a reorg.
- **Naming.** `local/` is a confusing name (everything runs locally). `scenarios/` reads better. Keep this in mind when doing Phase 3.

## Conventions

- Go integration tests live at `tests/*_test.go`, use `testenv.go` to spin up a registry + daemons, and run inside a single `go test ./tests/` invocation.
- Docker-based tests live under `tests/integration/` (or its eventual successor). They orchestrate containers via docker-compose and use shell `set -e` semantics with helpers in `*_helpers.sh`.
- Fuzz targets sit alongside regular tests in the same file (`FuzzX`/`TestX` pairs).
- Benchmarks use `BenchmarkX` and live in dedicated `zz_bench_*.go` files.
- New tests should go to the right tier: prefer Go for anything that doesn't strictly require multi-container orchestration.
