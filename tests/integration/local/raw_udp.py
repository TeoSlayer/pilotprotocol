#!/usr/bin/env python3
# raw_udp.py — minimal dependency-free UDP sender/flooder used by the
# Chunk D security tests. Keeps to Python stdlib (socket, argparse, sys,
# time) so it runs inside Dockerfile.multi with no extra install.
#
# Usage:
#   raw_udp.py send <host> <port> <hex_payload>
#   echo -n <hex_payload> | raw_udp.py send <host> <port> -
#   raw_udp.py flood <host> <port> <hex_payload> <count> [--rate pps]
#   raw_udp.py capture <host> <port> <timeout_s>   # bind+recv one frame, print hex
#
# The hex_payload form is plain hex, no 0x prefix, whitespace stripped.
# Binary stdin is accepted when payload == "-".

import argparse
import binascii
import socket
import sys
import time


def parse_payload(arg: str) -> bytes:
    if arg == "-":
        # read raw bytes from stdin — caller is responsible for binary piping
        data = sys.stdin.buffer.read()
        # if user piped hex via text, try decode
        try:
            return binascii.unhexlify(data.decode().strip().replace(" ", ""))
        except Exception:
            return data
    cleaned = "".join(arg.split())
    return binascii.unhexlify(cleaned)


def cmd_send(args: argparse.Namespace) -> int:
    payload = parse_payload(args.payload)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sk:
        sk.sendto(payload, (args.host, args.port))
    sys.stdout.write(f"sent {len(payload)} bytes to {args.host}:{args.port}\n")
    return 0


def cmd_flood(args: argparse.Namespace) -> int:
    payload = parse_payload(args.payload)
    rate = args.rate if args.rate and args.rate > 0 else 0
    # Simple token-like pacing: if rate is set, sleep to roughly hit pps.
    # Absolute precision is not required — tests check server-side counters.
    interval = 1.0 / rate if rate else 0.0
    start = time.time()
    sent = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sk:
        for _ in range(args.count):
            try:
                sk.sendto(payload, (args.host, args.port))
                sent += 1
            except OSError:
                # ENOBUFS under heavy flood is normal; keep going after a
                # tiny breath so we don't spin.
                time.sleep(0.001)
            if interval:
                time.sleep(interval)
    elapsed = time.time() - start
    pps = sent / elapsed if elapsed > 0 else 0.0
    sys.stdout.write(f"flooded {sent} datagrams in {elapsed:.3f}s ({pps:.0f} pps)\n")
    return 0


def cmd_capture(args: argparse.Namespace) -> int:
    # Bind locally to receive a frame — used by replay tests when tcpdump
    # is unavailable. Prints one hex line per datagram.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sk:
        sk.bind((args.host, args.port))
        sk.settimeout(args.timeout)
        try:
            data, addr = sk.recvfrom(65535)
            sys.stdout.write(binascii.hexlify(data).decode() + "\n")
            sys.stderr.write(f"from {addr[0]}:{addr[1]} len={len(data)}\n")
            return 0
        except socket.timeout:
            sys.stderr.write("capture timed out\n")
            return 2


def main() -> int:
    p = argparse.ArgumentParser(prog="raw_udp.py")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("send")
    s.add_argument("host")
    s.add_argument("port", type=int)
    s.add_argument("payload", help="hex string or '-' for stdin")
    s.set_defaults(func=cmd_send)

    f = sub.add_parser("flood")
    f.add_argument("host")
    f.add_argument("port", type=int)
    f.add_argument("payload", help="hex string or '-' for stdin")
    f.add_argument("count", type=int)
    f.add_argument("--rate", type=int, default=0, help="pps pacing (0 = unpaced)")
    f.set_defaults(func=cmd_flood)

    c = sub.add_parser("capture")
    c.add_argument("host")
    c.add_argument("port", type=int)
    c.add_argument("timeout", type=float)
    c.set_defaults(func=cmd_capture)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
