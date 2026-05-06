#!/usr/bin/env python3
"""End-to-end smoke test for the Python SDK against a real daemon.

Test plan (run against the locally running pilot daemon):
1. Construct ``Driver`` — proves the seeder wired ``libpilot.dylib`` correctly.
2. Call ``info()`` — confirms the JSON-RPC path works.
3. Idempotently handshake the list-agents host (already trusted is OK).
4. ``send_message(target='list-agents', data='/data {...}', msg_type='text')``
   — exercises hostname resolve + dial + frame protocol.
5. Wait for the asynchronous reply to land in ``~/.pilot/inbox/`` and print
   a digest of the highest-tier specialist count.

The script exits 0 on success, non-zero on any failure. It writes the
reply file path to stdout so a caller can grep for it.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

# Allow running straight from a source checkout.
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from pilotprotocol import Driver, PilotError  # noqa: E402

LIST_AGENTS_HOST = "list-agents"
LIST_AGENTS_NODE_ID = 16398
INBOX_DIR = Path.home() / ".pilot" / "inbox"
WAIT_SECONDS = 8


def _newest_inbox_file(after_mtime: float) -> Path | None:
    if not INBOX_DIR.is_dir():
        return None
    candidates = []
    for f in INBOX_DIR.glob("*.json"):
        try:
            st = f.stat()
        except OSError:
            continue
        if st.st_mtime > after_mtime:
            candidates.append((st.st_mtime, f))
    if not candidates:
        return None
    candidates.sort(reverse=True)
    return candidates[0][1]


def main() -> int:
    print("[1/5] Constructing Driver…")
    try:
        d = Driver()
    except PilotError as e:
        print(f"  FAIL: cannot reach daemon: {e}")
        return 2
    print("  OK")

    print("[2/5] Calling info()…")
    info = d.info()
    print(f"  node_id={info.get('node_id')} addr={info.get('address')} peers={info.get('peers')}")

    print(f"[3/5] Handshake list-agents (node {LIST_AGENTS_NODE_ID})…")
    try:
        h = d.handshake(LIST_AGENTS_NODE_ID, "python sdk smoke test")
        print(f"  OK: {h}")
    except PilotError as e:
        # Already trusted is acceptable.
        msg = str(e).lower()
        if "already" in msg or "trust" in msg:
            print(f"  OK (already trusted): {e}")
        else:
            print(f"  FAIL: {e}")
            return 3

    print("[4/5] send_message → list-agents …")
    record_mtime = time.time() - 1
    try:
        result = d.send_message(
            LIST_AGENTS_HOST,
            b'/data {"search":"","limit":1}',
            msg_type="text",
        )
    except PilotError as e:
        print(f"  FAIL: send_message: {e}")
        return 4
    print(f"  sent: {result}")

    print(f"[5/5] Waiting up to {WAIT_SECONDS}s for inbox reply…")
    deadline = time.time() + WAIT_SECONDS
    reply_file: Path | None = None
    while time.time() < deadline:
        reply_file = _newest_inbox_file(record_mtime)
        if reply_file is not None:
            break
        time.sleep(0.5)
    if reply_file is None:
        print("  FAIL: no inbox reply within window")
        return 5

    print(f"  reply file: {reply_file}")
    try:
        envelope = json.loads(reply_file.read_text())
    except (OSError, ValueError) as e:
        print(f"  FAIL: cannot parse reply: {e}")
        return 6

    print(f"  agent={envelope.get('agent')} command={envelope.get('command')} ok={envelope.get('ok')}")

    # Try to extract the total count if the payload is a list-agents response.
    raw = envelope.get("data")
    if isinstance(raw, str):
        try:
            payload = json.loads(raw)
            total = payload.get("total") or payload.get("count")
            if total is None:
                items = payload.get("tiers", {}).get("free", {}).get("items", [])
                total = len(items)
            print(f"  list-agents total: {total}")
        except (ValueError, AttributeError):
            print("  (data not JSON; envelope OK)")

    d.close()
    print("\nSMOKE TEST PASSED (python)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
