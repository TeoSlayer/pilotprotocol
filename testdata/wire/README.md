# Wire-format golden corpus

This directory holds byte-for-byte snapshots of every Pilot Protocol wire
frame across L1, L4, L5, L6 and L7. They are the **P6 invariance gate**
defined in `architecture-notes/05-VERIFICATION.md` §4.1.

`tests/wire_golden_test.go` (`TestWireFormatGolden`) reads each `.bin`,
parses it via the live decoders, re-marshals via the live encoders, and
asserts the round-trip is byte-identical. Any wire-format regression — a
field reorder, an extra byte of padding, a checksum-algorithm tweak — fails
the test and names the offending frame.

## Frames

| File | Layer | Layout |
| --- | --- | --- |
| `l1-packet-syn.bin` | L1 | 34-byte header, SYN, seq=100 |
| `l1-packet-data.bin` | L1 | ACK + 5-byte payload "hello", seq=101, ack=200 |
| `l1-packet-fin.bin` | L1 | FIN+ACK, seq=200, ack=101 |
| `l1-packet-rst.bin` | L1 | RST, seq=300 |
| `l1-packet-datagram.bin` | L1 | ProtoDatagram + 12-byte payload |
| `l4-msg-discover.bin` | L4 | `[0x01][nodeID(4)]` |
| `l4-msg-discover-reply-v4.bin` | L4 | `[0x02][iplen=4][IP(4)][port(2)]` |
| `l4-msg-discover-reply-v6.bin` | L4 | `[0x02][iplen=16][IP(16)][port(2)]` |
| `l4-msg-punch-request.bin` | L4 | `[0x03][requesterID(4)][targetID(4)]` |
| `l4-msg-punch-command.bin` | L4 | `[0x04][iplen=4][IP(4)][port(2)]` |
| `l4-msg-relay.bin` | L4 | `[0x05][senderID(4)][destID(4)][L1 SYN frame]` |
| `l4-msg-relay-deliver.bin` | L4 | `[0x06][senderID(4)][L1 SYN frame]` |
| `l4-msg-sync.bin` | L4 | `[0x07][beaconID(4)][nodeCount(2)][nodeID(4)] x 2` |
| `l4-punch-pilp.bin` | L4 | 4-byte `PILP` magic, no payload |
| `l5-key-exchange-auth.bin` | L5 | `[PILA(4)][nodeID(4)][x25519pub(32)][ed25519pub(32)][sig(64)]` (136 bytes) |
| `l5-key-exchange-unauth.bin` | L5 | `[PILK(4)][nodeID(4)][x25519pub(32)]` (40 bytes) |
| `l6-encrypted-frame.bin` | L6 | `[PILS(4)][senderNodeID(4)][nonce(12)][ciphertext+GCM tag]` — plaintext "hello", AES-256-GCM under fixed 0x42-repeating key, AAD = senderNodeID |
| `l7-sack-payload.bin` | L7 | `"SACK"(4) | count(1) | left(4) | right(4)` for one block (1500–1600) |

## Regenerating the corpus

Regenerating these files is a **wire-format change** and requires explicit
version-bump approval per VERIFICATION P6 — they exist precisely so that
silent format drift is impossible.

The generator lives at `cmd/wire-gen/main.go` behind the `wirecorpus` build
tag, so it cannot be built or run by the normal toolchain:

```
go run -tags=wirecorpus ./cmd/wire-gen
```

Optionally pass `-out` to redirect output:

```
go run -tags=wirecorpus ./cmd/wire-gen -out testdata/wire
```

After regenerating, run `go test ./tests -run TestWireFormatGolden` to confirm
round-trips remain byte-identical.

## Skipped frames

None — all 18 frames listed in `architecture-notes/05-VERIFICATION.md` §4.1
plus the IPv6 discover-reply variant are captured. The L5 auth frame uses a
deterministic Ed25519 seed so signatures are reproducible across runs; the L6
encrypted frame uses a fixed AES key, fixed nonce and fixed AAD so the
ciphertext bytes are reproducible.
