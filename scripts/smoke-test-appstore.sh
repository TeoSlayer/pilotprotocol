#!/usr/bin/env bash
#
# smoke-test-appstore.sh — live end-to-end smoke test for the app
# store flow. This is the executable spec: every step a real new user
# runs, in the order they run it, with assertions that fail loudly.
#
# What it proves:
#
#  1. The pilot daemon ships with the app-store supervisor always on
#     (no flag).
#  2. `pilotctl appstore gen-key` produces a working ed25519 publisher
#     keypair.
#  3. `pilotctl appstore sign` produces a signature the supervisor
#     accepts.
#  4. A signed wallet bundle, packaged as a tarball + sha256 in a
#     staging catalogue, installs cleanly via
#     `pilotctl appstore install io.pilot.wallet`.
#  5. The daemon picks it up within seconds and exposes its IPC.
#  6. A second wallet process can act as a merchant; a 50 USDC payment
#     flows request → pay → verify → settle, then replay is rejected.
#  7. `pilotctl appstore uninstall` tears it all down; the daemon
#     cancels the supervise goroutine.
#  8. The host returns to fresh-user state — no artifacts left over.
#
# Usage:
#   scripts/smoke-test-appstore.sh           # against repo HEAD
#   PILOT_DEBUG=1 scripts/smoke-test-appstore.sh   # keep tmpdir on exit
#
# Requirements:
#   - go toolchain (any version the repos pin)
#   - The wallet repo at ../wallet relative to this web4 checkout.
#   - macOS or Linux. /tmp must be writable.
#
# Exit codes:
#   0   all steps green
#   1   a step failed (line number + step name printed)

set -euo pipefail

# ── plumbing ──────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WEB4_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WALLET_DIR="$(cd "$WEB4_DIR/.." && pwd)/wallet"
if [ ! -d "$WALLET_DIR" ]; then
    echo "FAIL: wallet repo not at $WALLET_DIR" >&2
    exit 1
fi

WORK="$(mktemp -d -t pilot-smoke-XXXXXX)"
PILOT_HOME_BAK=""
DAEMON_PID=""
MERCHANT_PID=""

step()  { printf "\n[step %s] %s\n" "$1" "$2"; }
ok()    { printf "  OK %s\n" "$1"; }
fail()  { printf "  FAIL %s\n" "$1" >&2; exit 1; }

cleanup() {
    set +e
    [ -n "$MERCHANT_PID" ] && kill "$MERCHANT_PID" 2>/dev/null
    [ -n "$DAEMON_PID" ]   && kill "$DAEMON_PID"   2>/dev/null
    if [ -n "$PILOT_HOME_BAK" ] && [ -d "$PILOT_HOME_BAK" ]; then
        rm -rf "$HOME/.pilot/apps"
        if [ -d "$PILOT_HOME_BAK/apps" ]; then
            mv "$PILOT_HOME_BAK/apps" "$HOME/.pilot/apps"
        fi
    fi
    if [ "${PILOT_DEBUG:-}" = "1" ]; then
        echo "[debug] keeping work dir: $WORK"
    else
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT INT TERM

# Preserve any pre-existing apps so an operator running the smoke
# test on their dev box doesn't lose their installed wallet.
if [ -d "$HOME/.pilot/apps" ]; then
    PILOT_HOME_BAK="$WORK/pilot-home-backup"
    mkdir -p "$PILOT_HOME_BAK"
    mv "$HOME/.pilot/apps" "$PILOT_HOME_BAK/apps"
fi

# ── step 1: build pilotctl + daemon + wallet from HEAD ────────────────

step 1 "build pilotctl, daemon, wallet"
( cd "$WEB4_DIR" && go build -o "$WORK/pilotctl" ./cmd/pilotctl ) || fail "build pilotctl"
( cd "$WEB4_DIR" && go build -o "$WORK/pilot-daemon" ./cmd/daemon ) || fail "build daemon"
( cd "$WALLET_DIR" && go build -o "$WORK/wallet" ./cmd/wallet ) || fail "build wallet"
ok "pilotctl + daemon + wallet built"

# ── step 2: generate publisher key + sign a wallet bundle ─────────────

step 2 "generate publisher key + sign wallet manifest"
"$WORK/pilotctl" appstore gen-key "$WORK/publisher.key" > "$WORK/gen-key.out" 2>&1 \
    || { cat "$WORK/gen-key.out"; fail "gen-key"; }
grep -q "ed25519:" "$WORK/gen-key.out" || fail "gen-key didn't print publisher line"
ok "publisher key written ($(stat -f %A "$WORK/publisher.key" 2>/dev/null || stat -c %a "$WORK/publisher.key") perms)"

BUNDLE="$WORK/bundle"
mkdir -p "$BUNDLE/bin"
cp "$WORK/wallet" "$BUNDLE/bin/wallet"
WALLET_SHA="$(shasum -a 256 "$BUNDLE/bin/wallet" | awk '{print $1}')"
python3 -c "
import json,sys
with open('$WALLET_DIR/manifest.json') as f: m = json.load(f)
m['binary']['sha256'] = '$WALLET_SHA'
with open('$BUNDLE/manifest.json','w') as f: json.dump(m, f, indent=2)
"
"$WORK/pilotctl" appstore sign --key "$WORK/publisher.key" "$BUNDLE/manifest.json" > "$WORK/sign.out" 2>&1 \
    || { cat "$WORK/sign.out"; fail "sign"; }
ok "manifest signed, binary sha pinned"

# ── step 3: stage a catalogue pointing at the local bundle ────────────

step 3 "stage a catalogue file pointing at the bundle tarball"
( cd "$BUNDLE" && tar czf "$WORK/io.pilot.wallet-test.tar.gz" manifest.json bin/wallet )
BUNDLE_SHA="$(shasum -a 256 "$WORK/io.pilot.wallet-test.tar.gz" | awk '{print $1}')"
cat > "$WORK/catalogue.json" <<EOF
{
  "version": 1,
  "updated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "apps": [
    {
      "id": "io.pilot.wallet",
      "version": "0.3.0",
      "description": "smoke-test build",
      "bundle_url": "file://$WORK/io.pilot.wallet-test.tar.gz",
      "bundle_sha256": "$BUNDLE_SHA"
    }
  ]
}
EOF
export PILOT_APPSTORE_CATALOG_URL="file://$WORK/catalogue.json"
ok "catalogue staged at \$PILOT_APPSTORE_CATALOG_URL"

# ── step 4: start the daemon (which always loads the app-store) ───────

step 4 "start the daemon (app-store supervisor unconditional)"
"$WORK/pilot-daemon" \
    -identity "$HOME/.pilot/identity.json" \
    -socket "$WORK/pilot.sock" \
    -listen :0 \
    -hostname smoke-test \
    -log-level info \
    > "$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!
sleep 2
ps -p "$DAEMON_PID" >/dev/null 2>&1 || { tail -20 "$WORK/daemon.log"; fail "daemon died"; }
grep -q "appstore" "$WORK/daemon.log" || fail "no appstore log line — supervisor didn't register"
ok "daemon up (PID $DAEMON_PID), app-store supervisor registered"

# ── step 5: catalogue + install by ID ─────────────────────────────────

step 5 "browse catalogue and install by ID"
"$WORK/pilotctl" appstore catalogue > "$WORK/cat.out" 2>&1 \
    || { cat "$WORK/cat.out"; fail "catalogue"; }
grep -q "io.pilot.wallet" "$WORK/cat.out" || fail "catalogue missing wallet entry"
ok "catalogue lists wallet"

"$WORK/pilotctl" appstore install io.pilot.wallet > "$WORK/install.out" 2>&1 \
    || { cat "$WORK/install.out"; fail "install"; }
grep -q "sha256 OK" "$WORK/install.out" || fail "install didn't verify sha256"
ok "wallet installed (sha256 verified)"

# ── step 6: wait for the daemon to spawn the wallet ───────────────────

step 6 "daemon discovers + spawns the app"
i=0
while [ ! -S "$HOME/.pilot/apps/io.pilot.wallet/app.sock" ] && [ $i -lt 15 ]; do
    sleep 1; i=$((i+1))
done
[ -S "$HOME/.pilot/apps/io.pilot.wallet/app.sock" ] || { tail -10 "$WORK/daemon.log"; fail "wallet socket missing after 15s"; }
ok "wallet socket ready after ${i}s"

ADDR_OUT="$("$WORK/pilotctl" appstore call io.pilot.wallet wallet.address)"
echo "$ADDR_OUT" | grep -q '"address"' || fail "wallet.address didn't return"
ok "wallet.address responded ($(echo $ADDR_OUT | tr -d '\n'))"

# ── step 7: live payment from wallet → merchant ───────────────────────

step 7 "live 50 USDC payment (wallet → merchant)"
MERCHANT_DIR="$WORK/merchant"
mkdir -p "$MERCHANT_DIR"
"$WORK/wallet" \
    -addr 0:0002.0000.0000 \
    -db "$MERCHANT_DIR/data.db" \
    -socket "$MERCHANT_DIR/wallet.sock" \
    -identity "$MERCHANT_DIR/identity.json" \
    > "$MERCHANT_DIR/wallet.log" 2>&1 &
MERCHANT_PID=$!
sleep 1
[ -S "$MERCHANT_DIR/wallet.sock" ] || fail "merchant socket missing"

( cd "$WEB4_DIR/scripts/smoke-pay-driver" && go build -o "$WORK/smoke-pay-driver" . ) \
    || fail "build smoke-pay-driver"
"$WORK/smoke-pay-driver" \
    -payer "$HOME/.pilot/apps/io.pilot.wallet/app.sock" \
    -merchant "$MERCHANT_DIR/wallet.sock" \
    -amount 50 > "$WORK/pay.out" 2>&1 \
    || { cat "$WORK/pay.out"; fail "live payment"; }
grep -q "PAY_OK" "$WORK/pay.out" || { cat "$WORK/pay.out"; fail "no PAY_OK marker"; }
ok "payment settled, replay rejected"

# ── step 8: uninstall + verify clean ──────────────────────────────────

step 8 "uninstall + verify clean"
"$WORK/pilotctl" appstore uninstall io.pilot.wallet --yes > "$WORK/uninstall.out" 2>&1 \
    || { cat "$WORK/uninstall.out"; fail "uninstall"; }
sleep 3
[ -d "$HOME/.pilot/apps/io.pilot.wallet" ] && fail "io.pilot.wallet dir still present after uninstall"
grep -q "removed from disk" "$WORK/daemon.log" || fail "daemon didn't log the uninstall"
ok "wallet removed, daemon noticed"

echo ""
printf "==== SMOKE TEST PASSED ====\n"
printf "daemon log: %s\n" "$WORK/daemon.log"
if [ "${PILOT_DEBUG:-}" = "1" ]; then
    echo "(PILOT_DEBUG=1 — work dir preserved at $WORK)"
fi
