"""Runtime environment seeder for the Pilot Protocol Python SDK.

Both the CLI shims (``cli.py``) and the FFI loader (``client._load_lib``)
funnel through :func:`ensure_runtime_seeded`, which idempotently mirrors
the binaries shipped inside the wheel into ``~/.pilot/bin/``.

Design goals:
- The wheel is the *seed cache*; ``~/.pilot/bin/`` is the canonical runtime.
- No install-time code runs; seeding happens lazily on first SDK use.
- Concurrency-safe (flock) and crash-safe (atomic rename).
- Never downgrades; never replaces a running daemon binary.
- Coexists with ``install.sh`` (same layout, same ``.pilot-version`` marker).
"""

from __future__ import annotations

import errno
import json
import os
import platform
import shutil
import socket
import sys
import tempfile
import threading
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_BIN_NAMES = ("pilotctl", "pilot-daemon", "pilot-gateway", "pilot-updater")
_LIB_NAMES = {
    "Darwin": "libpilot.dylib",
    "Linux": "libpilot.so",
    "Windows": "libpilot.dll",
}

DEFAULT_REGISTRY = "34.71.57.205:9000"
DEFAULT_BEACON = "34.71.57.205:9001"
DEFAULT_SOCKET = "/tmp/pilot.sock"


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def _pkg_bin_dir() -> Path:
    """Where the wheel ships its bundled binaries (the seed cache)."""
    return Path(__file__).resolve().parent / "bin"


def _runtime_root() -> Path:
    """Canonical runtime dir. Honours ``PILOT_HOME`` for CI / multi-tenant."""
    override = os.environ.get("PILOT_HOME")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".pilot"


def _runtime_bin() -> Path:
    return _runtime_root() / "bin"


def _platform_lib_name() -> str:
    name = _LIB_NAMES.get(platform.system())
    if name is None:
        raise OSError(f"unsupported platform: {platform.system()}")
    return name


# ---------------------------------------------------------------------------
# Version helpers
# ---------------------------------------------------------------------------

def _semver_tuple(v: str) -> tuple[int, ...]:
    """Parse a SemVer-ish string into a comparable tuple. Unparseable → ()."""
    s = (v or "").strip().lstrip("v").split("-", 1)[0].split("+", 1)[0]
    if not s:
        return ()
    parts = []
    for p in s.split("."):
        try:
            parts.append(int(p))
        except ValueError:
            return ()
    return tuple(parts)


def _bundled_version() -> str:
    """Version of the binaries bundled in this wheel."""
    f = _pkg_bin_dir() / ".pilot-version"
    if f.is_file():
        try:
            return f.read_text().strip()
        except OSError:
            pass
    # Fall back to the package metadata if the marker file is missing.
    try:
        from importlib.metadata import version as _pkg_version
        return _pkg_version("pilotprotocol")
    except Exception:
        return ""


def _runtime_version(rt: Path) -> str:
    f = rt / ".pilot-version"
    if f.is_file():
        try:
            return f.read_text().strip()
        except OSError:
            return ""
    return ""


# ---------------------------------------------------------------------------
# Daemon liveness probe
# ---------------------------------------------------------------------------

def _daemon_running() -> bool:
    """True if a pilot daemon is reachable on its IPC socket."""
    sock_path = DEFAULT_SOCKET
    try:
        with open(_runtime_root() / "config.json") as f:
            cfg = json.load(f)
        sock_path = cfg.get("socket", sock_path) or sock_path
    except (OSError, ValueError):
        pass

    if not Path(sock_path).exists():
        return False
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(0.2)
    try:
        s.connect(sock_path)
        return True
    except OSError:
        return False
    finally:
        try:
            s.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Atomic file ops
# ---------------------------------------------------------------------------

def _atomic_install(src: Path, dst: Path) -> None:
    """Copy *src* → *dst* atomically, surviving in-flight execs.

    Writes to ``<dst>.tmp.<pid>`` then ``os.replace()`` over the target.
    On POSIX this unlinks the old inode while leaving any running process
    that mapped it untouched.
    """
    tmp = dst.with_name(f"{dst.name}.tmp.{os.getpid()}.{threading.get_ident()}")
    if tmp.exists():
        tmp.unlink()
    shutil.copy2(src, tmp)
    try:
        tmp.chmod(0o755)
        os.replace(tmp, dst)
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def _ensure_dir_writable(p: Path) -> None:
    """Create *p* if it does not exist; raise a clear error if we cannot
    write to it (e.g. owned by root after a botched install)."""
    p.mkdir(parents=True, exist_ok=True)
    if not os.access(p, os.W_OK):
        raise PermissionError(
            f"{p} is not writable by user {os.getuid()}. "
            f"Repair with: chown -R $USER {p}"
        )


# ---------------------------------------------------------------------------
# Config seeding
# ---------------------------------------------------------------------------

def _ensure_default_config() -> Path:
    """Make sure ``~/.pilot/config.json`` exists. Never overwrites an
    existing one — install.sh or the user may have set an email.
    """
    root = _runtime_root()
    _ensure_dir_writable(root)
    cfg_path = root / "config.json"
    if cfg_path.is_file():
        return cfg_path
    cfg = {
        "registry": DEFAULT_REGISTRY,
        "beacon": DEFAULT_BEACON,
        "socket": DEFAULT_SOCKET,
        "encrypt": True,
        "identity": str(root / "identity.json"),
    }
    tmp = cfg_path.with_name(
        f"config.json.tmp.{os.getpid()}.{threading.get_ident()}"
    )
    tmp.write_text(json.dumps(cfg, indent=2) + "\n")
    try:
        os.replace(tmp, cfg_path)
    except FileNotFoundError:
        # Another thread won the race; that's fine.
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass
    return cfg_path


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class SeedReport:
    """Summary of what a seeder pass did. Useful for tests + diagnostics."""

    def __init__(self) -> None:
        self.copied: list[str] = []
        self.skipped: list[str] = []
        self.action: str = "noop"   # one of: noop, seed, upgrade, daemon-skip
        self.bundled_version: str = ""
        self.installed_version: str = ""
        self.runtime_dir: Path = _runtime_bin()


_SEEDED_ONCE = False


def ensure_runtime_seeded(force: bool = False) -> Path:
    """Idempotently mirror bundled binaries into ``~/.pilot/bin/``.

    Returns the runtime bin dir. Safe to call on every CLI invocation and
    every Driver() construction; the steady state is a single stat() +
    string compare.

    Set ``force=True`` to re-run even if this process has already seeded.
    """
    global _SEEDED_ONCE
    if _SEEDED_ONCE and not force:
        return _runtime_bin()

    report = run_seeder()
    _SEEDED_ONCE = True
    return report.runtime_dir


def run_seeder() -> SeedReport:
    """Run one seeder pass and return a structured report."""
    report = SeedReport()
    rt_root = _runtime_root()
    rt = _runtime_bin()
    pkg = _pkg_bin_dir()

    # Make sure ~/.pilot/ exists and is writable.
    _ensure_dir_writable(rt_root)
    _ensure_dir_writable(rt)
    _ensure_default_config()

    # Cross-platform fcntl shim. flock is POSIX-only; on Windows we use
    # msvcrt.locking. Tests run on POSIX so the Windows path is best-effort.
    lock_path = rt / ".seed.lock"
    lock_path.touch(exist_ok=True)
    lock_fd = os.open(lock_path, os.O_RDWR)
    try:
        if os.name == "posix":
            import fcntl
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
        else:  # pragma: no cover - Windows
            import msvcrt
            msvcrt.locking(lock_fd, msvcrt.LK_LOCK, 1)

        bundled_str = _bundled_version()
        installed_str = _runtime_version(rt)
        report.bundled_version = bundled_str
        report.installed_version = installed_str

        bundled = _semver_tuple(bundled_str)
        installed = _semver_tuple(installed_str)

        # Decide overall action.
        force = os.environ.get("PILOT_FORCE_SEED") == "1"
        if not force and installed and bundled and bundled <= installed:
            # Same or newer already installed. Still verify each file exists.
            need_seed = False
            for name in _BIN_NAMES + (_platform_lib_name(),):
                if not (rt / name).is_file():
                    need_seed = True
                    break
            if not need_seed:
                report.action = "noop"
                return report

        report.action = "upgrade" if installed else "seed"
        daemon_busy = _daemon_running()

        for name in _BIN_NAMES + (_platform_lib_name(),):
            src = pkg / name
            if not src.is_file():
                # Wrong-platform wheel or partial bundle. Skip — caller will
                # surface a clear error when the missing binary is needed.
                continue
            dst = rt / name
            if name == "pilot-daemon" and daemon_busy and dst.is_file():
                report.skipped.append(name)
                report.action = "daemon-skip"
                continue
            try:
                _atomic_install(src, dst)
                report.copied.append(name)
            except OSError as e:
                # ETXTBSY can hit Linux despite atomic rename if a tool has
                # the file mmap'd. Skip with a notice; caller can retry.
                if e.errno in (errno.ETXTBSY, errno.EBUSY):
                    report.skipped.append(name)
                    continue
                raise

        # Update the marker last; a partial seed leaves the old marker.
        if bundled_str:
            ver_path = rt / ".pilot-version"
            tmp = ver_path.with_name(f".pilot-version.tmp.{os.getpid()}")
            tmp.write_text(bundled_str + "\n")
            os.replace(tmp, ver_path)

        return report
    finally:
        try:
            if os.name == "posix":
                import fcntl
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)


def runtime_binary(name: str) -> Path:
    """Resolve a binary by name, seeding if needed.

    Use this from CLI shims; it returns the path to exec.
    """
    rt = ensure_runtime_seeded()
    p = rt / name
    if not p.is_file():
        # Last-ditch fallback: run from the wheel itself.
        fallback = _pkg_bin_dir() / name
        if fallback.is_file():
            return fallback
        raise FileNotFoundError(
            f"Binary {name!r} not found in {rt} or {_pkg_bin_dir()}. "
            f"This wheel may be for a different platform."
        )
    return p


def runtime_library() -> Path:
    """Resolve libpilot.{so,dylib,dll}, seeding if needed."""
    rt = ensure_runtime_seeded()
    name = _platform_lib_name()
    p = rt / name
    if p.is_file():
        return p
    fallback = _pkg_bin_dir() / name
    if fallback.is_file():
        return fallback
    raise FileNotFoundError(
        f"libpilot ({name}) not found in {rt} or {_pkg_bin_dir()}."
    )


def reset_seeded_marker() -> None:
    """Test helper: forget that this process has already seeded."""
    global _SEEDED_ONCE
    _SEEDED_ONCE = False
