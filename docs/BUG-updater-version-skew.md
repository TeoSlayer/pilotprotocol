# BUG: pilot-updater stuck on v1.10.9 — three independent issues

**Reported:** 2026-06-14
**Re-audited:** 2026-06-14 against current code on `main`
**Severity:** medium (causes version skew); the `send-file` impact is a
separate, larger reliability bug — see `docs/PROPOSAL-reliable-file-transfer.md`.
**Components:** pilot-updater · release packaging · dataexchange / send-file

## Summary

The original bug report identified one phenomenon ("Node A pinned at v1.10.9
while a fresh `install.sh` pulls v1.11.0") and proposed a single mechanism
(stale RSS changelog feed). Live audit against the code confirms the
phenomenon but disproves the mechanism. There are in fact **three
independent issues** wearing the same symptom:

1. **The updater binary ships but is never started.** The install bundle
   contains `pilot-updater` next to `pilot-daemon` and `pilotctl`, but
   neither `install.sh` nor the daemon's normal startup launches it.
2. **`install.sh` references `pilot-gateway`, which is no longer in the
   v1.11.0 bundle.** Causes a harmless-looking `cp: cannot stat …
   pilot-gateway` line but signals stale install logic.
3. **`send-file` between any two nodes (skewed or not) has no reliability
   primitives** — no ACK timeout, no integrity hash, no resume, no
   progress. The 120s EOF in the original report is this bug, not version
   skew. The skew is incidental; the same failure reproduces between two
   v1.11.0 nodes.

This document covers (1) and (2). (3) is the larger fix and lives in
`docs/PROPOSAL-reliable-file-transfer.md`.

## Issue 1 — Updater shipped, never started

### What the original doc said

> *"a long-running install does not auto-update to the latest version …
> the changelog/update feed the updater reads looks stale"*

### What the code actually does

`updater/updater.go:244-249` builds the polling URL directly against the
GitHub API:

```go
if tag == "" {
    url = fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", u.config.Repo)
} else {
    url = fmt.Sprintf("https://api.github.com/repos/%s/releases/tags/%s", u.config.Repo, tag)
}
```

The RSS feed at `teoslayer.github.io/pilot-changelog` is **only** read by
the user-facing `pilotctl updates` command (`updates.go`) — it has no role
in the auto-update decision. The feed being stale is irrelevant to the
updater.

### The real cause

On the affected machine (Node A, macOS arm64):

- `pilot-updater` binary is installed at `~/.pilot/bin/pilot-updater`
  (mtime 2026-06-08, i.e. unchanged since first install — as expected if
  it was never invoked).
- `ps -axo command | grep pilot-updater` returns **nothing**.
- The running `pilot-daemon` command line is
  `pilot-daemon -identity … -socket … -listen … -hostname … -log-level info`
  — no flag enables an in-process updater either.

So the updater binary is sitting on disk being garbage-collected by Time
Machine, not polling GitHub at all. The install never set up a launchd
service / systemd unit / cron / supervisor for it, and the daemon does
not embed it.

### Fix

Three reasonable options, in increasing order of "proper":

1. **Document the deferral.** Add a clear note to `install.sh` output
   that the updater is provided but not auto-started; users opt in by
   running `pilotctl daemon start --enable-updater` (which already exists
   in `web4/cmd/pilotctl/main.go` per the `Daemon lifecycle` help).
2. **Auto-start the updater on install** by writing a launchd plist /
   systemd unit alongside the daemon plist. `install.sh` already writes
   the daemon plist; the same mechanism, scoped to the updater binary,
   takes ~30 lines.
3. **Embed the updater in the daemon** as an opt-in `--enable-updater`
   flag that spawns a goroutine running `updater.Service.Run`. This is
   the long-term right answer — one process, one PID, one log stream —
   but it changes the daemon contract.

(2) is shippable in one PR; (3) is the eventual direction.

## Issue 2 — `pilot-gateway` missing from v1.11.0 bundle

### Observed

```text
$ curl -sL .../v1.11.0/pilot-linux-amd64.tar.gz | tar tzf -
./
./updater
./daemon
./pilotctl
```

No `pilot-gateway`. `install.sh` line that calls
`cp /tmp/pilot/pilot-gateway …` fails with the documented "cannot stat"
error, then proceeds.

### Whose problem this is

Either:

- The release workflow (`release/`) dropped `pilot-gateway` from the
  artifact list and `install.sh` wasn't updated. Fix: re-add to the
  workflow or remove from `install.sh`, depending on intent.
- `pilot-gateway` was deliberately retired and `install.sh` is stale. Fix:
  remove the line from `install.sh` and update operator docs.

Inspecting `release/` and `install.sh` will resolve which.

## Issue 3 — Send-file is unreliable by design

See `docs/PROPOSAL-reliable-file-transfer.md`. Quick summary: the
"send-file hangs 120s then EOFs" failure in the original report is not
caused by version skew. It reproduces between two v1.11.0 nodes. The
underlying gaps are zero application-layer timeouts, no end-to-end
integrity hash, no resume protocol, atomic 256 MiB frames with no
streaming, and no progress reporting. The proposal lays out a
backward-compatible streaming protocol that addresses all of these.

## Open questions to drive a fix PR

- Is the intent for the updater to auto-run after install on all
  platforms, or only when the operator opts in? (Answers whether option
  2 or 3 above is right.)
- Is `pilot-gateway` retired? If not, why did the v1.11.0 release skip
  it?

## Environment (audit re-run)

| | Node A (laptop) | Node B (bench VM) |
|---|---|---|
| OS / arch | macOS arm64 | Ubuntu 24.04 amd64 |
| pilot daemon | v1.10.9 | (fresh VM, no install yet) |
| install date | 2026-06-08 | n/a |
| `pilot-updater` process | **not running** | n/a |
| `~/.pilot/bin/.pilot-version` | `v1.10.9` | n/a |
| `~/.pilot/bin/pilot-updater` mtime | 2026-06-08 (unchanged) | n/a |
| latest GitHub release tag | `v1.11.0` (published 2026-06-10) | same |
