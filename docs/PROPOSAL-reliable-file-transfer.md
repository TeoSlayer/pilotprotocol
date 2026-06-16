# Proposal: reliable file transfer for Pilot

**Status:** design + initial implementation in progress
**Owner:** `dataexchange` package · `web4/cmd/pilotctl/main.go::cmdSendFile`
· `web4/pkg/daemon/...` (receiver path)
**Context:** the original BUG-updater-version-skew report's "send-file
hangs ~120s then EOFs" is not version skew; it is the unmodified send-file
behavior. This proposal lays out what reliable means and how to get there
without breaking compatibility with v1.10.x receivers.

## Problem statement, in one paragraph

`pilotctl send-file` today sends a file as a **single 256 MiB-capped
atomic frame** (`dataexchange/dataexchange.go:61`), reads the entire file
into memory on both sides (`os.ReadFile` on sender, `make([]byte, length)
+ io.ReadFull` on receiver), encrypts the whole thing once at the tunnel
layer, waits for a literal string ACK (`"ACK FILE N bytes"`), with **no
application-layer timeouts anywhere** — neither the sender's `client.Recv()`
nor the receiver's `ReadFrame()` has a deadline. The receiver writes the
file synchronously and only ACKs after the disk flush completes. There is
no end-to-end content hash, no resume protocol, no progress reporting,
and no per-chunk backpressure. The result is exactly what the bug report
saw: large transfers over any non-trivial path stall, and the sender hangs
until SO_KEEPALIVE finally trips at ~120s.

## Goals (and non-goals)

**Goals**

1. Sender never hangs longer than a configurable timeout.
2. End-to-end integrity verified (not just per-tunnel AEAD).
3. Streaming on both sides — sender does not load the whole file into
   memory, receiver writes incrementally.
4. Progress visible to the sender during transfer (for human and agent
   UX).
5. Resume after a dropped transfer.
6. Backward compatible with v1.10.x receivers (which only understand
   `TypeFile`).
7. Concurrent transfers to the same peer work without interfering.

**Non-goals (this round)**

- Compression. Pilot already runs over GCM; compressing inside that
  is a separate optimization.
- Multipath / parallel-stream transfers. The overlay handles fan-out at
  a lower layer.
- Files > 100 GiB. Real but a separate scope.

## Design — three layers

### Layer 1 — `TypeFileStream` frame (new wire type)

Add a new dataexchange frame type alongside the existing `TypeFile`:

```go
const (
    TypeText   uint32 = 1
    TypeJSON   uint32 = 2
    TypeBinary uint32 = 3
    TypeFile   uint32 = 4
    TypeTrace  uint32 = 5
    // TypeAutoAnswer is reserved (see Alex's reply-on-conn PR chain).
    TypeFileStream uint32 = 7  // new — see below
)
```

`TypeFileStream` frames are **small**: a header, a control byte, and at
most 1 MiB of payload. The header carries:

- `transfer_id` (16 bytes random) — disambiguates concurrent transfers
- `kind` (1 byte) — one of:
  - `0x01 INIT`: filename, total size, SHA-256 of full content, sender's
    declared chunk size
  - `0x02 CHUNK`: offset (uint64), payload bytes, SHA-256 of this chunk
  - `0x03 ACK`: highest contiguous offset received (uint64)
  - `0x04 DONE`: end-of-stream marker; receiver verifies full SHA-256
  - `0x05 ABORT`: error code + human reason
  - `0x06 RESUME`: receiver tells sender "I have through offset N for
    transfer T" — only valid as a response to a re-INIT with same
    `transfer_id`

Wire format for each kind is straightforward fixed-prefix + payload.
Frames are still bounded by `MaxFrameSize` but in practice stay <1 MiB.

### Layer 2 — sender + receiver state machines

**Sender** (`pilotctl send-file` → `client.SendFileStream`):

```text
1. Open file, compute total size, stream-hash SHA-256 of full content.
2. INIT frame with filename, size, full-hash, chunk_size = 256 KiB.
3. Loop: read chunk_size bytes; send CHUNK(offset, payload, chunk_hash).
4. Sliding window: keep at most `window` chunks unacked (default 16 →
   4 MiB in flight). Block reading next chunk if window full.
5. On receiving ACK(offset N): advance window's left edge to N, free
   read-buffer space.
6. After last chunk: DONE.
7. Receive final ACK from receiver carrying full SHA-256 verification.
8. Timeouts at every Recv() — default 30s, exposed as `--timeout`.
```

**Receiver** (`dataexchange/service.go::handleConn` extended for
`TypeFileStream`):

```text
1. INIT: open `~/.pilot/received/.partial/{transfer_id}` (atomic rename
   on DONE). Start a per-transfer goroutine; register `transfer_id` in
   an in-memory map.
2. CHUNK: verify chunk SHA-256; write to file at offset (pwrite); update
   "highest contiguous offset" cursor. Send ACK with new cursor.
3. If a chunk arrives out of order: hold it in a small bounded buffer
   (default 16 chunks = 4 MiB) and write when its predecessor lands.
4. DONE: hash-verify full file; rename .partial → final name; ACK with
   success or ABORT with mismatch.
5. ABORT from sender: close transfer, keep .partial for inspection,
   schedule cleanup after 1h.
6. Timeouts at every ReadFrame() — default 60s per chunk, transfer-wide
   default 1h. Stalled transfers leave the .partial on disk for resume.
```

**Resume** — sender on retry sends INIT with the same `transfer_id`. If
receiver still has the `.partial`, it replies RESUME(offset N). Sender
seeks to N and continues from there. SHA-256 is recomputed on the
receiver side over the .partial file to detect corruption before resume.

### Layer 3 — backward compatibility

The sender starts every transfer by trying `TypeFileStream` first. If
the receiver is v1.10.x:

- It receives a `TypeFileStream` frame, hits `default` in the frame-type
  switch (`dataexchange/service.go:165` or thereabouts), and either drops
  the connection or saves to inbox as unknown.
- Sender's INIT does not get an INIT-ACK within the negotiation timeout
  (3 seconds, configurable via `--legacy-timeout`).
- Sender falls back to the old `TypeFile` atomic send, **but now with a
  timeout on the ACK Recv** (the smallest concession we make to the old
  path).

This means v1.11.x→v1.10.x transfers still work (legacy path); 11.x→11.x
gets the full reliability story; 10.x→11.x continues to work (receiver
just gets an unknown frame and the sender follows up with TypeFile per
the existing protocol).

## Implementation milestones

| | Scope | Surface |
|---|---|---|
| **M0** | Sender + receiver timeouts on the existing `TypeFile` path. No wire-format change. End-to-end SHA-256 sent as a sidecar in the ACK string ("ACK FILE N bytes sha256=…"). Sender verifies. | `dataexchange/service.go`, `dataexchange/client.go`, `web4/cmd/pilotctl/main.go` |
| **M1** | New `TypeFileStream` wire type + sender state machine + receiver state machine. No resume. No progress UX yet. | `dataexchange/*`, `web4/cmd/pilotctl/main.go` |
| **M2** | Progress reporting via stderr (TTY-only) using the existing `startWaitProgress` helper — currently just elapsed; extend with bytes-sent/bytes-total. | `web4/cmd/pilotctl/style.go`, `main.go` |
| **M3** | Resume protocol. RESUME frame + receiver-side `.partial` files + sender-side seek-and-continue. | `dataexchange/*`, `web4/cmd/pilotctl/main.go` |
| **M4** | Streaming I/O end-to-end (no whole-file allocations on either side). | `dataexchange/*` |
| **M5** | Backward-compat negotiation (auto-fall-back to `TypeFile` when peer doesn't ACK INIT). | `web4/cmd/pilotctl/main.go` |
| **M6** | Tests (unit, integration with a fake-network jitter, concurrent transfers, resume after crash, large file) — on a controllable VM. | `dataexchange/zz_*_test.go`, `tests/` |

## Open design questions

- **Window size default** — 16 chunks × 256 KiB = 4 MiB in flight feels
  right for relay paths; benchmarks on the VM will calibrate.
- **Chunk size negotiation** — sender's INIT proposes; should receiver
  be allowed to counter-propose smaller? (Mobile receivers, e.g.)
- **`.partial` retention policy** — 1 hour for now, or "until sender
  retries"? Latter is risk of orphan files; former is risk of "I came
  back tomorrow and resume doesn't work."
- **Integrity hash algorithm** — SHA-256 is the conservative pick.
  BLAKE3 is faster on the wire-format hashing path; not free, and
  Pilot has no other dependency on it. Picking SHA-256 unless a
  benchmark says otherwise.

## Verification

Bench rig already provisioned: `pilot-sendfile-bench-1781448324` in
`us-central1-a` (e2-standard-4 / 15 GB RAM / 50 GB pd-ssd). It can
serve as Node B for paired tests against this laptop. The bench
matrix:

| Test | Size | Path | Pass criteria |
|---|---|---|---|
| Baseline TypeFile | 1 / 10 / 100 / 256 MiB | both nodes v1.10.x | unchanged behavior, no regressions |
| Stream happy path | 1 / 10 / 100 / 1024 / 4096 MiB | both v1.11.x stream | within 90% of raw `scp` throughput on the same path |
| Stream resume | 1024 MiB | kill receiver at 50%, restart, resume | completes with single SHA-256 verify, no re-transfer of received bytes |
| Concurrent | 5 × 100 MiB simultaneous | both v1.11.x | all five complete; aggregate throughput within 80% of one-at-a-time × 5 |
| Sender timeout | 100 MiB, `kill -9` receiver mid-transfer | mixed | sender exits within `--timeout` (default 30 s) with a clear error and `pilot-mcp doctor`-style hint |
| Backward compat | 100 MiB v1.11.x sender → v1.10.x receiver | mixed | falls back to TypeFile, completes, no error logs on either side |

## Next steps

1. Land M0 (timeouts + sidecar SHA-256) as a small PR against
   `TeoSlayer/pilotprotocol`. This alone closes the "120s hang" report
   without any wire-format change.
2. Open a tracking issue with this proposal linked.
3. Stand up M1 behind a `--stream` flag on `pilotctl send-file` so the
   new path can be exercised against the bench VM without changing the
   default behavior.
4. Once M1 is stable in the wild, flip the default and start landing
   M2…M5.
