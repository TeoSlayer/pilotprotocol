#!/usr/bin/env python3
"""Tiny webhook sink: accepts POST on any path, appends {ts, path, body}
as JSON lines to /var/log/webhooks.jsonl, returns 200. stdlib only.

Usage: webhook_sink.py [--port 18080] [--log /var/log/webhooks.jsonl]
"""
import argparse
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    log_path = "/var/log/webhooks.jsonl"
    _lock = threading.Lock()

    def _write(self, record):
        line = json.dumps(record, separators=(",", ":")) + "\n"
        with self._lock:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            body = json.loads(raw.decode("utf-8")) if raw else None
        except Exception:
            body = raw.decode("utf-8", errors="replace")
        record = {"ts": time.time(), "path": self.path, "body": body}
        try:
            self._write(record)
        except Exception as e:
            sys.stderr.write(f"sink write error: {e}\n")
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, fmt, *args):
        return  # silence default stderr spam


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=18080)
    ap.add_argument("--log", default="/var/log/webhooks.jsonl")
    args = ap.parse_args()
    Handler.log_path = args.log
    os.makedirs(os.path.dirname(args.log), exist_ok=True)
    # Touch the log so tail/jq work immediately.
    open(args.log, "a").close()
    srv = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    sys.stderr.write(f"webhook_sink listening on :{args.port} -> {args.log}\n")
    srv.serve_forever()


if __name__ == "__main__":
    main()
