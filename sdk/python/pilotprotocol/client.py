"""Pilot Protocol Python SDK — ctypes wrapper around libpilot shared library.

This module provides a Pythonic interface to the Pilot Protocol daemon by
calling into the Go driver compiled as a C-shared library (.so/.dylib/.dll).
The Go library is the *single source of truth*; this wrapper is a thin FFI
boundary that marshals arguments and unmarshals JSON results.

Usage::

    from pilotprotocol import Driver

    d = Driver()                # connects to /tmp/pilot.sock
    info = d.info()             # returns dict
    d.close()

Or as a context manager::

    with Driver() as d:
        print(d.info())
"""

from __future__ import annotations

import ctypes
import ctypes.util
import json
import os
import platform
import sys
from pathlib import Path
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Library loading
# ---------------------------------------------------------------------------

_LIB_NAMES = {
    "Darwin": "libpilot.dylib",
    "Linux": "libpilot.so",
    "Windows": "libpilot.dll",
}


def _find_library() -> str:
    """Locate the libpilot shared library.

    Search order:
    1. PILOT_LIB_PATH environment variable (explicit override).
    2. ~/.pilot/bin/ (pip install location).
    3. Next to *this* Python file (pip-installed wheel layout - old).
    4. <project_root>/bin/ (development layout).
    5. System library search path via ctypes.util.find_library.
    """
    lib_name = _LIB_NAMES.get(platform.system())
    if lib_name is None:
        raise OSError(f"unsupported platform: {platform.system()}")

    # 1. Env override
    env = os.environ.get("PILOT_LIB_PATH")
    if env:
        p = Path(env)
        if p.is_file():
            return str(p)
        raise FileNotFoundError(f"PILOT_LIB_PATH={env} does not exist")

    # 2. ~/.pilot/bin/ (pip install location)
    pilot_bin = Path.home() / ".pilot" / "bin" / lib_name
    if pilot_bin.is_file():
        return str(pilot_bin)

    # 3. Same directory as this file (old wheel layout)
    here = Path(__file__).resolve().parent
    candidate = here / lib_name
    if candidate.is_file():
        return str(candidate)

    # 4. Development layout: <repo>/bin/
    repo_bin = here.parent.parent.parent / "bin" / lib_name
    if repo_bin.is_file():
        return str(repo_bin)

    # 5. System search
    found = ctypes.util.find_library("pilot")
    if found:
        return found

    raise FileNotFoundError(
        f"Cannot find {lib_name}.\n"
        "\n"
        "Expected locations:\n"
        f"  - ~/.pilot/bin/{lib_name} (pip install)\n"
        f"  - {here}/{lib_name} (bundled)\n"
        f"  - {repo_bin} (development)\n"
        "\n"
        "To install:\n"
        "  pip install pilotprotocol\n"
        "\n"
        "Or set PILOT_LIB_PATH:\n"
        f"  export PILOT_LIB_PATH=/path/to/{lib_name}"
    )


def _load_lib() -> ctypes.CDLL:  # pragma: no cover
    path = _find_library()
    return ctypes.CDLL(path)


_lib: Optional[ctypes.CDLL] = None


def _get_lib() -> ctypes.CDLL:  # pragma: no cover
    global _lib
    if _lib is None:
        _lib = _load_lib()
        _setup_signatures(_lib)
    return _lib


# ---------------------------------------------------------------------------
# C struct return types (match the generated header)
# ---------------------------------------------------------------------------

class _HandleErr(ctypes.Structure):
    """Return type for PilotConnect / PilotDial / PilotListen / PilotListenerAccept."""
    _fields_ = [("handle", ctypes.c_uint64), ("err", ctypes.c_char_p)]


class _ReadResult(ctypes.Structure):
    """Return type for PilotConnRead."""
    _fields_ = [
        ("n", ctypes.c_int),
        ("data", ctypes.c_char_p),
        ("err", ctypes.c_char_p),
    ]


class _WriteResult(ctypes.Structure):
    """Return type for PilotConnWrite."""
    _fields_ = [("n", ctypes.c_int), ("err", ctypes.c_char_p)]


# ---------------------------------------------------------------------------
# Signature setup
# ---------------------------------------------------------------------------

def _setup_signatures(lib: ctypes.CDLL) -> None:  # pragma: no cover
    """Declare argtypes / restype for every exported function."""

    # Memory
    lib.FreeString.argtypes = [ctypes.c_char_p]
    lib.FreeString.restype = None

    # Lifecycle
    lib.PilotConnect.argtypes = [ctypes.c_char_p]
    lib.PilotConnect.restype = _HandleErr

    lib.PilotClose.argtypes = [ctypes.c_uint64]
    lib.PilotClose.restype = ctypes.c_char_p

    # JSON-RPC (single *C.char return)
    for name in (
        "PilotInfo", "PilotPendingHandshakes", "PilotTrustedPeers",
        "PilotDeregister", "PilotRecvFrom",
    ):
        fn = getattr(lib, name)
        fn.argtypes = [ctypes.c_uint64]
        fn.restype = ctypes.c_char_p

    # (handle, uint32) -> *char
    for name in ("PilotApproveHandshake", "PilotRevokeTrust"):
        fn = getattr(lib, name)
        fn.argtypes = [ctypes.c_uint64, ctypes.c_uint32]
        fn.restype = ctypes.c_char_p

    # (handle, string) -> *char
    for name in ("PilotResolveHostname", "PilotSetHostname",
                 "PilotSetTags", "PilotSetWebhook"):
        fn = getattr(lib, name)
        fn.argtypes = [ctypes.c_uint64, ctypes.c_char_p]
        fn.restype = ctypes.c_char_p

    # (handle, int) -> *char
    for name in ("PilotSetVisibility", "PilotSetTaskExec"):
        fn = getattr(lib, name)
        fn.argtypes = [ctypes.c_uint64, ctypes.c_int]
        fn.restype = ctypes.c_char_p

    # (handle, uint32, string) -> *char
    lib.PilotHandshake.argtypes = [ctypes.c_uint64, ctypes.c_uint32, ctypes.c_char_p]
    lib.PilotHandshake.restype = ctypes.c_char_p

    lib.PilotRejectHandshake.argtypes = [ctypes.c_uint64, ctypes.c_uint32, ctypes.c_char_p]
    lib.PilotRejectHandshake.restype = ctypes.c_char_p

    # Disconnect (handle, uint32) -> *char
    lib.PilotDisconnect.argtypes = [ctypes.c_uint64, ctypes.c_uint32]
    lib.PilotDisconnect.restype = ctypes.c_char_p

    # Dial: (handle, string) -> struct{handle, err}
    lib.PilotDial.argtypes = [ctypes.c_uint64, ctypes.c_char_p]
    lib.PilotDial.restype = _HandleErr

    # Listen: (handle, uint16) -> struct{handle, err}
    lib.PilotListen.argtypes = [ctypes.c_uint64, ctypes.c_uint16]
    lib.PilotListen.restype = _HandleErr

    # Listener Accept / Close
    lib.PilotListenerAccept.argtypes = [ctypes.c_uint64]
    lib.PilotListenerAccept.restype = _HandleErr

    lib.PilotListenerClose.argtypes = [ctypes.c_uint64]
    lib.PilotListenerClose.restype = ctypes.c_char_p

    # Conn Read / Write / Close
    lib.PilotConnRead.argtypes = [ctypes.c_uint64, ctypes.c_int]
    lib.PilotConnRead.restype = _ReadResult

    lib.PilotConnWrite.argtypes = [ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
    lib.PilotConnWrite.restype = _WriteResult

    lib.PilotConnClose.argtypes = [ctypes.c_uint64]
    lib.PilotConnClose.restype = ctypes.c_char_p

    # SendTo: (handle, string, void*, int) -> *char
    lib.PilotSendTo.argtypes = [ctypes.c_uint64, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_int]
    lib.PilotSendTo.restype = ctypes.c_char_p


# ---------------------------------------------------------------------------
# Error helpers
# ---------------------------------------------------------------------------

class PilotError(Exception):
    """Raised when the Go library returns an error."""
    pass


def _check_err(raw: Optional[bytes]) -> None:
    """If raw is non-null, parse the JSON error and raise."""
    if raw is None:
        return
    obj = json.loads(raw)
    if "error" in obj:
        raise PilotError(obj["error"])


def _parse_json(raw: Optional[bytes]) -> dict[str, Any]:
    """Parse a JSON *C.char return, raising on error."""
    if raw is None:
        return {}
    obj = json.loads(raw)
    if "error" in obj:
        raise PilotError(obj["error"])
    return obj


def _free(ptr: Optional[bytes]) -> None:
    """Free a C string if non-null."""
    if ptr is not None:
        _get_lib().FreeString(ptr)


# ---------------------------------------------------------------------------
# Conn – stream connection wrapper
# ---------------------------------------------------------------------------

class Conn:
    """A stream connection over the Pilot Protocol.

    Wraps a Go *driver.Conn handle behind the C boundary.
    """

    def __init__(self, handle: int) -> None:
        self._h = handle
        self._closed = False

    def read(self, size: int = 4096) -> bytes:
        """Read up to *size* bytes. Blocks until data arrives."""
        if self._closed:
            raise PilotError("connection closed")
        lib = _get_lib()
        res = lib.PilotConnRead(self._h, size)
        if res.err:
            err = res.err
            _get_lib().FreeString(err)
            raise PilotError(json.loads(err)["error"])
        if res.n == 0:
            return b""
        data = ctypes.string_at(res.data, res.n)
        lib.FreeString(res.data)
        return data

    def write(self, data: bytes) -> int:
        """Write bytes to the connection. Returns bytes written."""
        if self._closed:
            raise PilotError("connection closed")
        lib = _get_lib()
        buf = ctypes.create_string_buffer(data)
        res = lib.PilotConnWrite(self._h, buf, len(data))
        if res.err:
            err = res.err
            lib.FreeString(err)
            raise PilotError(json.loads(err)["error"])
        return res.n

    def close(self) -> None:
        """Close the connection."""
        if self._closed:
            return
        self._closed = True
        lib = _get_lib()
        raw = lib.PilotConnClose(self._h)
        if raw:
            err = raw
            lib.FreeString(err)
            obj = json.loads(err)
            if "error" in obj:
                raise PilotError(obj["error"])

    def __enter__(self) -> "Conn":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def __del__(self) -> None:
        if not self._closed:
            try:
                self.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Listener – server socket wrapper
# ---------------------------------------------------------------------------

class Listener:
    """A port listener that accepts incoming stream connections."""

    def __init__(self, handle: int) -> None:
        self._h = handle
        self._closed = False

    def accept(self) -> Conn:
        """Block until a new connection arrives and return it."""
        if self._closed:
            raise PilotError("listener closed")
        lib = _get_lib()
        res = lib.PilotListenerAccept(self._h)
        if res.err:
            err = res.err
            lib.FreeString(err)
            raise PilotError(json.loads(err)["error"])
        return Conn(res.handle)

    def close(self) -> None:
        """Close the listener."""
        if self._closed:
            return
        self._closed = True
        lib = _get_lib()
        raw = lib.PilotListenerClose(self._h)
        if raw:
            err = raw
            lib.FreeString(err)
            obj = json.loads(err)
            if "error" in obj:
                raise PilotError(obj["error"])

    def __enter__(self) -> "Listener":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def __del__(self) -> None:
        if not self._closed:
            try:
                self.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Driver – main SDK entry point
# ---------------------------------------------------------------------------

DEFAULT_SOCKET_PATH = "/tmp/pilot.sock"


class Driver:
    """Pythonic wrapper around the Go driver via libpilot.

    This is a *thin* FFI layer — all protocol logic lives in Go.
    """

    def __init__(self, socket_path: str = DEFAULT_SOCKET_PATH) -> None:
        lib = _get_lib()
        res = lib.PilotConnect(socket_path.encode())
        if res.err:
            err = res.err
            lib.FreeString(err)
            raise PilotError(json.loads(err)["error"])
        self._h: int = res.handle
        self._closed = False

    # -- Context manager --

    def __enter__(self) -> "Driver":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # -- Lifecycle --

    def close(self) -> None:
        """Disconnect from the daemon."""
        if self._closed:
            return
        self._closed = True
        raw = _get_lib().PilotClose(self._h)
        _check_err(raw)
        _free(raw)

    # -- JSON-RPC helpers --

    def _call_json(self, fn_name: str, *args: Any) -> dict[str, Any]:
        """Call a C function that returns *C.char JSON, parse & free."""
        lib = _get_lib()
        fn = getattr(lib, fn_name)
        raw = fn(self._h, *args)
        try:
            return _parse_json(raw)
        finally:
            _free(raw)

    # -- Info --

    def info(self) -> dict[str, Any]:
        """Return the daemon's status information."""
        return self._call_json("PilotInfo")

    # -- Handshake / Trust --

    def handshake(self, node_id: int, justification: str = "") -> dict[str, Any]:
        """Send a trust handshake request to a remote node."""
        return self._call_json("PilotHandshake", ctypes.c_uint32(node_id), justification.encode())

    def approve_handshake(self, node_id: int) -> dict[str, Any]:
        """Approve a pending handshake request."""
        return self._call_json("PilotApproveHandshake", ctypes.c_uint32(node_id))

    def reject_handshake(self, node_id: int, reason: str = "") -> dict[str, Any]:
        """Reject a pending handshake request."""
        return self._call_json("PilotRejectHandshake", ctypes.c_uint32(node_id), reason.encode())

    def pending_handshakes(self) -> dict[str, Any]:
        """Return pending trust handshake requests."""
        return self._call_json("PilotPendingHandshakes")

    def trusted_peers(self) -> dict[str, Any]:
        """Return all trusted peers."""
        return self._call_json("PilotTrustedPeers")

    def revoke_trust(self, node_id: int) -> dict[str, Any]:
        """Remove a peer from the trusted set."""
        return self._call_json("PilotRevokeTrust", ctypes.c_uint32(node_id))

    # -- Hostname --

    def resolve_hostname(self, hostname: str) -> dict[str, Any]:
        """Resolve a hostname to node info."""
        return self._call_json("PilotResolveHostname", hostname.encode())

    def set_hostname(self, hostname: str) -> dict[str, Any]:
        """Set or clear the daemon's hostname."""
        return self._call_json("PilotSetHostname", hostname.encode())

    # -- Visibility / capabilities --

    def set_visibility(self, public: bool) -> dict[str, Any]:
        """Set the daemon's visibility on the registry."""
        return self._call_json("PilotSetVisibility", ctypes.c_int(1 if public else 0))

    def set_task_exec(self, enabled: bool) -> dict[str, Any]:
        """Enable or disable task execution capability."""
        return self._call_json("PilotSetTaskExec", ctypes.c_int(1 if enabled else 0))

    def deregister(self) -> dict[str, Any]:
        """Remove the daemon from the registry."""
        return self._call_json("PilotDeregister")

    def set_tags(self, tags: list[str]) -> dict[str, Any]:
        """Set capability tags for this node."""
        return self._call_json("PilotSetTags", json.dumps(tags).encode())

    def set_webhook(self, url: str) -> dict[str, Any]:
        """Set or clear the webhook URL."""
        return self._call_json("PilotSetWebhook", url.encode())

    # -- Connection management --

    def disconnect(self, conn_id: int) -> None:
        """Close a connection by ID (administrative)."""
        lib = _get_lib()
        raw = lib.PilotDisconnect(self._h, ctypes.c_uint32(conn_id))
        _check_err(raw)
        _free(raw)

    # -- Streams --

    def dial(self, addr: str) -> Conn:
        """Open a stream connection to addr (format: "N:XXXX.YYYY.YYYY:PORT")."""
        lib = _get_lib()
        res = lib.PilotDial(self._h, addr.encode())
        if res.err:
            err = res.err
            lib.FreeString(err)
            raise PilotError(json.loads(err)["error"])
        return Conn(res.handle)

    def listen(self, port: int) -> Listener:
        """Bind a port and return a Listener that accepts connections."""
        lib = _get_lib()
        res = lib.PilotListen(self._h, ctypes.c_uint16(port))
        if res.err:
            err = res.err
            lib.FreeString(err)
            raise PilotError(json.loads(err)["error"])
        return Listener(res.handle)

    # -- Datagrams --

    def send_to(self, addr: str, data: bytes) -> None:
        """Send an unreliable datagram. addr = "N:XXXX.YYYY.YYYY:PORT"."""
        lib = _get_lib()
        buf = ctypes.create_string_buffer(data)
        raw = lib.PilotSendTo(self._h, addr.encode(), buf, len(data))
        _check_err(raw)
        _free(raw)

    def recv_from(self) -> dict[str, Any]:
        """Receive the next incoming datagram (blocks).

        Returns dict with keys: src_addr, src_port, dst_port, data.
        """
        return self._call_json("PilotRecvFrom")
