"""
Pilot Protocol TUI — unified interface for all service agents.

Default mode: chat with the Pilot AI assistant.
Slash commands route to other service agents:
  /scriptorium <command> <body>   — query Scriptorium (stockmarket, polymarket, …)
  /clawdit [query]                — run a security audit
  /ls                             — list available service agents
  /new                            — clear conversation (AI agent)
  /clear                          — clear screen
  /quit                           — exit

All commands are dispatched through pilotctl subprocesses.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import sys
import time

try:
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.padding import Padding
    from rich.panel import Panel
    from rich.table import Table
except ImportError:
    print("error: 'rich' library is required.  Install with:  pip install rich")
    sys.exit(1)


_console = Console(highlight=False, markup=True)

_PILOTCTL = shutil.which("pilotctl") or "pilotctl"

SERVICE_AGENTS = [
    {
        "name": "ai",
        "description": "Natural-language assistant powered by Gemini — ask anything about your network",
        "usage": 'pilotctl ai "<query>"',
        "config": "~/.pilot/scriptorium.yaml",
    },
    {
        "name": "scriptorium",
        "description": "Pre-built intelligence briefs (stockmarket, polymarket, …)",
        "usage": 'pilotctl scriptorium <command> "<body>"',
        "config": "~/.pilot/scriptorium.yaml",
        "subcommands": ["stockmarket", "polymarket"],
    },
    {
        "name": "clawdit",
        "description": "Security audit of an OpenClaw installation",
        "usage": 'pilotctl clawdit ["<query>"] [--file <path>]',
        "config": "~/.pilot/clawdit.yaml",
    },
]


def _log(message: str, level: str = "info") -> None:
    markers = {
        "success": "[green]✓[/green]",
        "error": "[red]✗[/red]",
        "warning": "[yellow]![/yellow]",
    }
    _console.print(f"  {markers.get(level, '[dim]⏺[/dim]')} {message}")


def _sys(text: str) -> None:
    for line in text.splitlines():
        _console.print(f"  [dim]{line}[/dim]")


def _print_agent(name: str, text: str) -> None:
    _console.print()
    _console.print(f"  [bold]{name}[/bold]")
    _console.print(Padding(Markdown(text), pad=(0, 4, 0, 2)))
    _console.print()


def _print_welcome() -> None:
    _console.print()
    _console.print("  [bold cyan]Pilot Protocol[/bold cyan]  [dim]service agent TUI[/dim]")
    _console.print()
    _sys("You are chatting with [bold]pilot-ai[/bold]. Type a message to begin.")
    _sys("")
    _sys("/scriptorium <cmd> <body>   query Scriptorium")
    _sys("/clawdit [query]            security audit")
    _sys("/ls                         list service agents")
    _sys("/new   new session   /clear   clear screen   /quit   exit")
    _console.print()


def _run_pilotctl(args: list[str], timeout: int = 180) -> tuple[str, str, int]:
    """Run a pilotctl command and return (stdout, stderr, returncode)."""
    cmd = [_PILOTCTL, "--json"] + args
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.stdout.strip(), proc.stderr.strip(), proc.returncode
    except subprocess.TimeoutExpired:
        return "", "command timed out", 1
    except FileNotFoundError:
        return "", f"pilotctl not found at {_PILOTCTL}", 1


def _parse_json_reply(stdout: str) -> str | None:
    """Extract the reply field from pilotctl --json output."""
    try:
        obj = json.loads(stdout)
        if "data" in obj and "reply" in obj["data"]:
            return obj["data"]["reply"]
        if "reply" in obj:
            return obj["reply"]
    except (json.JSONDecodeError, KeyError):
        pass
    return stdout if stdout else None


def _list_agents() -> None:
    _console.print()
    table = Table(title="Service Agents", show_header=True, header_style="bold cyan", padding=(0, 2))
    table.add_column("Name", style="bold")
    table.add_column("Description")
    table.add_column("Usage", style="dim")
    for agent in SERVICE_AGENTS:
        table.add_row(agent["name"], agent["description"], agent["usage"])
    _console.print(Padding(table, pad=(0, 2)))
    _console.print()


def _handle_ai(query: str) -> None:
    _console.print()
    _log("sending to pilot-ai…")
    stdout, stderr, rc = _run_pilotctl(["ai", query])
    if rc != 0:
        err_msg = stderr or stdout or "unknown error"
        # Try to extract message from JSON error
        try:
            obj = json.loads(err_msg) if err_msg.startswith("{") else json.loads(stdout)
            err_msg = obj.get("error", {}).get("message", err_msg) if isinstance(obj.get("error"), dict) else obj.get("message", err_msg)
        except (json.JSONDecodeError, KeyError):
            pass
        _log(err_msg, "error")
        _console.print()
        return
    reply = _parse_json_reply(stdout)
    if reply:
        _print_agent("pilot-ai", reply)
    else:
        _log("empty reply — check: pilotctl inbox", "warning")
        _console.print()


def _handle_scriptorium(rest: str) -> None:
    parts = rest.strip().split(None, 1)
    if not parts:
        _log("usage: /scriptorium <command> [body]", "warning")
        _sys("  commands: stockmarket, polymarket")
        _console.print()
        return
    cmd_name = parts[0]
    body = parts[1] if len(parts) > 1 else ""
    _console.print()
    _log(f"querying scriptorium/{cmd_name}…")
    args = ["scriptorium", cmd_name]
    if body:
        args.append(body)
    stdout, stderr, rc = _run_pilotctl(args)
    if rc != 0:
        err_msg = stderr or stdout or "unknown error"
        try:
            obj = json.loads(err_msg) if err_msg.startswith("{") else json.loads(stdout)
            err_msg = obj.get("error", {}).get("message", err_msg) if isinstance(obj.get("error"), dict) else obj.get("message", err_msg)
        except (json.JSONDecodeError, KeyError):
            pass
        _log(err_msg, "error")
        _console.print()
        return
    # Scriptorium dispatches via overlay and reply arrives in inbox.
    # The --json output contains the ACK, but the actual data comes via inbox.
    _log("command sent — waiting for reply in inbox…")
    _console.print()
    # Poll inbox for the reply
    _poll_and_print(cmd_name)


def _poll_and_print(label: str, timeout: int = 120) -> None:
    """Poll ~/.pilot/inbox/ for a new message and print it."""
    home = os.path.expanduser("~")
    inbox = os.path.join(home, ".pilot", "inbox")
    if not os.path.isdir(inbox):
        _log("inbox directory not found", "error")
        return

    existing = set(os.listdir(inbox)) if os.path.isdir(inbox) else set()
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(2)
        current = set(os.listdir(inbox))
        new_files = current - existing
        for fname in sorted(new_files):
            fpath = os.path.join(inbox, fname)
            try:
                with open(fpath) as f:
                    data = json.load(f)
                msg_data = data.get("data", "")
                # Unwrap double-JSON
                try:
                    msg_data = json.loads(msg_data)
                except (json.JSONDecodeError, TypeError):
                    pass
                if isinstance(msg_data, str) and msg_data:
                    _print_agent(f"scriptorium/{label}", msg_data)
                    return
            except (json.JSONDecodeError, OSError):
                pass
            existing.add(fname)
        existing = current

    _log(f"no reply within {timeout}s — check: pilotctl inbox", "warning")
    _console.print()


def _handle_clawdit(rest: str) -> None:
    _console.print()
    args = ["clawdit"]
    rest = rest.strip()

    # Parse --file flag from rest
    if "--file" in rest:
        parts = rest.split("--file")
        query_part = parts[0].strip()
        file_part = parts[1].strip().split()[0] if parts[1].strip() else ""
        if query_part:
            args.append(query_part)
        if file_part:
            args.extend(["--file", file_part])
    elif rest:
        args.append(rest)

    _log("requesting security audit…")
    stdout, stderr, rc = _run_pilotctl(args)
    if rc != 0:
        err_msg = stderr or stdout or "unknown error"
        try:
            obj = json.loads(err_msg) if err_msg.startswith("{") else json.loads(stdout)
            err_msg = obj.get("error", {}).get("message", err_msg) if isinstance(obj.get("error"), dict) else obj.get("message", err_msg)
        except (json.JSONDecodeError, KeyError):
            pass
        _log(err_msg, "error")
        _console.print()
        return
    reply = _parse_json_reply(stdout)
    if reply:
        _print_agent("clawdit", reply)
    else:
        _log("empty reply — check: pilotctl inbox", "warning")
        _console.print()


class PilotTUI:
    def run(self) -> None:
        _print_welcome()
        while True:
            _console.print("  [#cc785c]>[/#cc785c] ", end="")
            try:
                raw = sys.stdin.readline()
                if not raw:
                    break
                text = raw.rstrip("\n").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not text:
                continue

            lower = text.lower()
            if lower in ("/quit", "/exit", "quit", "exit"):
                break
            elif lower == "/ls":
                _list_agents()
            elif lower == "/new":
                _console.print()
                _log("ready — new conversation")
                _console.print()
            elif lower == "/clear":
                _console.clear()
                _print_welcome()
            elif lower.startswith("/scriptorium"):
                rest = text[len("/scriptorium"):]
                _handle_scriptorium(rest)
            elif lower.startswith("/clawdit"):
                rest = text[len("/clawdit"):]
                _handle_clawdit(rest)
            else:
                _handle_ai(text)

        _console.print()
        _sys("bye")


def main() -> None:
    try:
        PilotTUI().run()
    except KeyboardInterrupt:
        _console.print()
        _sys("bye")


if __name__ == "__main__":
    main()
