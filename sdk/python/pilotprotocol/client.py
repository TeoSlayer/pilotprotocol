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
# IMPORTANT: All char* fields/returns MUST be c_void_p (not c_char_p).
# ctypes auto-converts c_char_p returns into Python bytes and drops the
# original pointer; passing those bytes back into FreeString then calls
# C.free() on a ctypes-internal buffer → munmap_chunk() / double-free.

class _HandleErr(ctypes.Structure):
    """Return type for PilotConnect / PilotDial / PilotListen / PilotListenerAccept."""
    _fields_ = [("handle", ctypes.c_uint64), ("err", ctypes.c_void_p)]


class _ReadResult(ctypes.Structure):
    """Return type for PilotConnRead."""
    _fields_ = [
        ("n", ctypes.c_int),
        ("data", ctypes.c_void_p),
        ("err", ctypes.c_void_p),
    ]


class _WriteResult(ctypes.Structure):
    """Return type for PilotConnWrite."""
    _fields_ = [("n", ctypes.c_int), ("err", ctypes.c_void_p)]


# ---------------------------------------------------------------------------
# Signature setup
# ---------------------------------------------------------------------------

def _setup_signatures(lib: ctypes.CDLL) -> None:  # pragma: no cover
    """Declare argtypes / restype for every exported function.

    IMPORTANT: All functions that return *C.char use c_void_p (NOT c_char_p)
    so we keep the raw pointer for FreeString.  c_char_p auto-converts to
    Python bytes and discards the original pointer, making FreeString crash.
    """

    # Memory — FreeString accepts the raw void* pointer
    lib.FreeString.argtypes = [ctypes.c_void_p]
    lib.FreeString.restype = None

    # Lifecycle
    lib.PilotConnect.argtypes = [ctypes.c_char_p]
    lib.PilotConnect.restype = _HandleErr

    lib.PilotClose.argtypes = [ctypes.c_uint64]
    lib.PilotClose.restype = ctypes.c_void_p

    # JSON-RPC (single *C.char return → c_void_p)
    for name in (
        "PilotInfo", "PilotPendingHandshakes", "PilotTrustedPeers",
        "PilotDeregister", "PilotRecvFrom",
    ):
        fn = getattr(lib, name)
        fn.argtypes = [ctypes.c_uint64]
        fn.restype = ctypes.c_void_p

    # (handle, uint32) -> *char
    for name in ("PilotApproveHandshake", "PilotRevokeTrust"):
        fn = getattr(lib, name)
        fn.argtypes = [ctypes.c_uint64, ctypes.c_uint32]
        fn.restype = ctypes.c_void_p

    # (handle, string) -> *char
    for name in ("PilotResolveHostname", "PilotSetHostname",
                 "PilotSetTags", "PilotSetWebhook"):
        fn = getattr(lib, name)
        fn.argtypes = [ctypes.c_uint64, ctypes.c_char_p]
        fn.restype = ctypes.c_void_p

    # (handle, int) -> *char
    for name in ("PilotSetVisibility", "PilotSetTaskExec"):
        fn = getattr(lib, name)
        fn.argtypes = [ctypes.c_uint64, ctypes.c_int]
        fn.restype = ctypes.c_void_p

    # (handle, uint32, string) -> *char
    lib.PilotHandshake.argtypes = [ctypes.c_uint64, ctypes.c_uint32, ctypes.c_char_p]
    lib.PilotHandshake.restype = ctypes.c_void_p

    lib.PilotRejectHandshake.argtypes = [ctypes.c_uint64, ctypes.c_uint32, ctypes.c_char_p]
    lib.PilotRejectHandshake.restype = ctypes.c_void_p

    # Disconnect (handle, uint32) -> *char
    lib.PilotDisconnect.argtypes = [ctypes.c_uint64, ctypes.c_uint32]
    lib.PilotDisconnect.restype = ctypes.c_void_p

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
    lib.PilotListenerClose.restype = ctypes.c_void_p

    # Conn Read / Write / Close
    lib.PilotConnRead.argtypes = [ctypes.c_uint64, ctypes.c_int]
    lib.PilotConnRead.restype = _ReadResult

    lib.PilotConnWrite.argtypes = [ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
    lib.PilotConnWrite.restype = _WriteResult

    lib.PilotConnClose.argtypes = [ctypes.c_uint64]
    lib.PilotConnClose.restype = ctypes.c_void_p

    # SendTo: (handle, string, void*, int) -> *char
    lib.PilotSendTo.argtypes = [ctypes.c_uint64, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_int]
    lib.PilotSendTo.restype = ctypes.c_void_p


# ---------------------------------------------------------------------------
# Error helpers
# ---------------------------------------------------------------------------

class PilotError(Exception):
    """Raised when the Go library returns an error."""
    pass


def _void_ptr_to_bytes(ptr: Optional[int]) -> Optional[bytes]:
    """Convert a c_void_p (int) to bytes by reading the C string.

    Returns None if ptr is None/0 (null pointer).
    """
    if not ptr:
        return None
    return ctypes.string_at(ptr)


def _check_err(ptr: Optional[int]) -> None:
    """If ptr is a non-null C string, parse the JSON error and raise.

    ptr is a raw c_void_p integer (NOT bytes).  We read the string first,
    then free the C pointer.
    """
    if not ptr:
        return
    raw = ctypes.string_at(ptr)
    _get_lib().FreeString(ptr)
    obj = json.loads(raw)
    if "error" in obj:
        raise PilotError(obj["error"])


def _parse_json(ptr: Optional[int]) -> dict[str, Any]:
    """Parse a JSON *C.char return, raising on error.

    ptr is a raw c_void_p integer.  We read + free it.
    """
    if not ptr:
        return {}
    raw = ctypes.string_at(ptr)
    _get_lib().FreeString(ptr)
    obj = json.loads(raw)
    if "error" in obj:
        raise PilotError(obj["error"])
    return obj


def _free(ptr: Optional[int]) -> None:
    """Free a C void pointer if non-null."""
    if ptr:
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
            raw = ctypes.string_at(res.err)
            lib.FreeString(res.err)
            raise PilotError(json.loads(raw)["error"])
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
            raw = ctypes.string_at(res.err)
            lib.FreeString(res.err)
            raise PilotError(json.loads(raw)["error"])
        return res.n

    def close(self) -> None:
        """Close the connection."""
        if self._closed:
            return
        self._closed = True
        lib = _get_lib()
        ptr = lib.PilotConnClose(self._h)
        if ptr:
            raw = ctypes.string_at(ptr)
            lib.FreeString(ptr)
            obj = json.loads(raw)
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
            raw = ctypes.string_at(res.err)
            lib.FreeString(res.err)
            raise PilotError(json.loads(raw)["error"])
        return Conn(res.handle)

    def close(self) -> None:
        """Close the listener."""
        if self._closed:
            return
        self._closed = True
        lib = _get_lib()
        ptr = lib.PilotListenerClose(self._h)
        if ptr:
            raw = ctypes.string_at(ptr)
            lib.FreeString(ptr)
            obj = json.loads(raw)
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
            raw = ctypes.string_at(res.err)
            lib.FreeString(res.err)
            raise PilotError(json.loads(raw)["error"])
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
        ptr = _get_lib().PilotClose(self._h)
        _check_err(ptr)

    # -- JSON-RPC helpers --

    def _call_json(self, fn_name: str, *args: Any) -> dict[str, Any]:
        """Call a C function that returns *C.char JSON, parse & free."""
        lib = _get_lib()
        fn = getattr(lib, fn_name)
        ptr = fn(self._h, *args)
        return _parse_json(ptr)

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
        ptr = lib.PilotDisconnect(self._h, ctypes.c_uint32(conn_id))
        _check_err(ptr)

    # -- Streams --

    def dial(self, addr: str) -> Conn:
        """Open a stream connection to addr (format: "N:XXXX.YYYY.YYYY:PORT")."""
        lib = _get_lib()
        res = lib.PilotDial(self._h, addr.encode())
        if res.err:
            raw = ctypes.string_at(res.err)
            lib.FreeString(res.err)
            raise PilotError(json.loads(raw)["error"])
        return Conn(res.handle)

    def listen(self, port: int) -> Listener:
        """Bind a port and return a Listener that accepts connections."""
        lib = _get_lib()
        res = lib.PilotListen(self._h, ctypes.c_uint16(port))
        if res.err:
            raw = ctypes.string_at(res.err)
            lib.FreeString(res.err)
            raise PilotError(json.loads(raw)["error"])
        return Listener(res.handle)

    # -- Datagrams --

    def send_to(self, addr: str, data: bytes) -> None:
        """Send an unreliable datagram. addr = "N:XXXX.YYYY.YYYY:PORT"."""
        lib = _get_lib()
        buf = ctypes.create_string_buffer(data)
        ptr = lib.PilotSendTo(self._h, addr.encode(), buf, len(data))
        _check_err(ptr)

    def recv_from(self) -> dict[str, Any]:
        """Receive the next incoming datagram (blocks).

        Returns dict with keys: src_addr, src_port, dst_port, data.
        """
        return self._call_json("PilotRecvFrom")

    # -- High-level service methods --

    def send_message(self, target: str, data: bytes, msg_type: str = "text") -> dict[str, Any]:
        """Send a message via the data exchange service (port 1001).

        Args:
            target: Hostname or protocol address (N:XXXX.YYYY.YYYY)
            data: Message data (text, JSON, or binary)
            msg_type: Message type: "text", "json", or "binary"

        Returns:
            Response from data exchange service with 'ack', 'bytes', 'type' keys
        """
        import struct
        
        # Resolve hostname if needed
        if not target.startswith("0:"):
            result = self.resolve_hostname(target)
            addr = result.get("address", "")
            if not addr:
                raise PilotError(f"Could not resolve hostname: {target}")
        else:
            addr = target

        # Map msg_type to frame type: 1=text, 2=binary, 3=json, 4=file
        type_map = {"text": 1, "binary": 2, "json": 3, "file": 4}
        frame_type = type_map.get(msg_type, 1)

        # Build frame: [4-byte type][4-byte length][payload]
        frame = struct.pack('>II', frame_type, len(data)) + data

        # Connect to data exchange service (port 1001)
        # Daemon sends ACK frame: [4-byte type=1][4-byte length]["ACK TYPE N bytes"]
        with self.dial(f"{addr}:1001") as conn:
            conn.write(frame)
            
            # Read ACK response frame
            try:
                ack_header = conn.read(8)
                if ack_header and len(ack_header) == 8:
                    ack_type, ack_len = struct.unpack('>II', ack_header)
                    ack_payload = conn.read(ack_len)
                    if ack_payload:
                        ack_msg = ack_payload.decode('utf-8', errors='replace')
                        return {"sent": len(data), "type": msg_type, "target": addr, "ack": ack_msg}
            except Exception:
                pass  # ACK read failed, but message was sent
            
            return {"sent": len(data), "type": msg_type, "target": addr}

    def send_file(self, target: str, file_path: str) -> dict[str, Any]:
        """Send a file via the data exchange service (port 1001).

        For TypeFile (4), payload format: [2-byte name length][name][file data]

        Args:
            target: Hostname or protocol address
            file_path: Path to file to send

        Returns:
            Response from data exchange service
        """
        import os
        import struct
        
        if not os.path.isfile(file_path):
            raise PilotError(f"File not found: {file_path}")

        with open(file_path, 'rb') as f:
            file_data = f.read()

        filename = os.path.basename(file_path)
        filename_bytes = filename.encode('utf-8')
        
        # For TypeFile: payload = [2-byte name len][name][file data]
        payload = struct.pack('>H', len(filename_bytes)) + filename_bytes + file_data
        
        # Build frame: [4-byte type=4][4-byte length][payload]
        frame = struct.pack('>II', 4, len(payload)) + payload

        # Resolve hostname if needed
        if not target.startswith("0:"):
            result = self.resolve_hostname(target)
            addr = result.get("address", "")
            if not addr:
                raise PilotError(f"Could not resolve hostname: {target}")
        else:
            addr = target

        # Send frame and read ACK
        with self.dial(f"{addr}:1001") as conn:
            conn.write(frame)
            
            # Read ACK response frame
            try:
                ack_header = conn.read(8)
                if ack_header and len(ack_header) == 8:
                    ack_type, ack_len = struct.unpack('>II', ack_header)
                    ack_payload = conn.read(ack_len)
                    if ack_payload:
                        ack_msg = ack_payload.decode('utf-8', errors='replace')
                        return {"sent": len(file_data), "filename": filename, "target": addr, "ack": ack_msg}
            except Exception:
                pass  # ACK read failed, but file was sent
            
            return {"sent": len(file_data), "filename": filename, "target": addr}

    def publish_event(self, target: str, topic: str, data: bytes) -> dict[str, Any]:
        """Publish an event via the event stream service (port 1002).

        Wire format: [2-byte topic len][topic][4-byte payload len][payload]
        Protocol: first event = subscribe, subsequent events = publish

        Args:
            target: Hostname or protocol address of event stream server
            topic: Event topic (e.g., "sensor/temperature")
            data: Event payload

        Returns:
            Response from event stream service
        """
        import struct
        
        # Resolve hostname if needed
        if not target.startswith("0:"):
            result = self.resolve_hostname(target)
            addr = result.get("address", "")
            if not addr:
                raise PilotError(f"Could not resolve hostname: {target}")
        else:
            addr = target

        # Helper to build event frame
        def build_event(topic_str: str, payload: bytes) -> bytes:
            topic_bytes = topic_str.encode('utf-8')
            return (struct.pack('>H', len(topic_bytes)) + topic_bytes +
                    struct.pack('>I', len(payload)) + payload)

        # Connect to event stream service (port 1002)
        # Protocol: first event = subscribe, subsequent = publish
        with self.dial(f"{addr}:1002") as conn:
            # Subscribe to topic first (empty payload)
            conn.write(build_event(topic, b''))
            
            # Now publish the actual event
            conn.write(build_event(topic, data))
            
            return {"status": "published", "topic": topic, "bytes": len(data)}

    def subscribe_event(self, target: str, topic: str, callback=None, timeout: int = 30):
        """Subscribe to events from the event stream service (port 1002).

        Wire format: [2-byte topic len][topic][4-byte payload len][payload]

        Args:
            target: Hostname or protocol address
            topic: Topic pattern to subscribe to (use "*" for all)
            callback: Optional callback function(topic, data) for each event
            timeout: Timeout in seconds (default: 30)

        Yields:
            (topic, data) tuples for each received event
        """
        import struct
        import time
        
        # Resolve hostname if needed
        if not target.startswith("0:"):
            result = self.resolve_hostname(target)
            addr = result.get("address", "")
            if not addr:
                raise PilotError(f"Could not resolve hostname: {target}")
        else:
            addr = target

        # Helper to build event frame
        def build_event(topic_str: str, payload: bytes) -> bytes:
            topic_bytes = topic_str.encode('utf-8')
            return (struct.pack('>H', len(topic_bytes)) + topic_bytes +
                    struct.pack('>I', len(payload)) + payload)

        # Helper to read event frame
        def read_event(conn):
            # Read 2-byte topic length
            topic_len_bytes = conn.read(2)
            if not topic_len_bytes or len(topic_len_bytes) < 2:
                return None
            topic_len = struct.unpack('>H', topic_len_bytes)[0]
            
            # Read topic
            topic_bytes = conn.read(topic_len)
            if not topic_bytes or len(topic_bytes) < topic_len:
                return None
            topic_str = topic_bytes.decode('utf-8')
            
            # Read 4-byte payload length
            payload_len_bytes = conn.read(4)
            if not payload_len_bytes or len(payload_len_bytes) < 4:
                return None
            payload_len = struct.unpack('>I', payload_len_bytes)[0]
            
            # Read payload
            payload = conn.read(payload_len)
            if not payload or len(payload) < payload_len:
                return None
                
            return (topic_str, payload)

        # Connect to event stream service (port 1002)
        conn = self.dial(f"{addr}:1002")
        try:
            # Send subscription (empty payload)
            conn.write(build_event(topic, b''))

            # Read events until timeout or connection closes
            start_time = time.time()
            while time.time() - start_time < timeout:
                try:
                    event = read_event(conn)
                    if not event:
                        break
                    event_topic, event_data = event
                    if callback:
                        callback(event_topic, event_data)
                    else:
                        yield (event_topic, event_data)
                except Exception as e:
                    if "connection closed" in str(e).lower() or "EOF" in str(e):
                        break
                    raise
        finally:
            conn.close()

    def submit_task(self, target: str, task_data: dict[str, Any]) -> dict[str, Any]:
        """Submit a task via the task submit service (port 1003).

        Args:
            target: Hostname or protocol address of task execution server
            task_data: Task specification as dict. Must include 'task_description'.
                      Optional: 'task_id' (auto-generated if not provided)

        Returns:
            Response from task submit service (StatusAccepted=200 or StatusRejected=400)
        """
        import struct
        import uuid
        
        # Resolve hostname if needed
        if not target.startswith("0:"):
            result = self.resolve_hostname(target)
            addr = result.get("address", "")
            if not addr:
                raise PilotError(f"Could not resolve hostname: {target}")
        else:
            addr = target

        # Get local address
        info = self.info()
        from_addr = info.get("address", "unknown")
        
        # Build proper SubmitRequest
        submit_req = {
            "task_id": task_data.get("task_id", str(uuid.uuid4())),
            "task_description": task_data.get("task_description", json.dumps(task_data)),
            "from_addr": from_addr,
            "to_addr": addr
        }
        
        # Encode task request as JSON
        task_json = json.dumps(submit_req).encode('utf-8')
        
        # Build submit frame: [4-byte type=1][4-byte length][JSON payload]
        frame = struct.pack('>II', 1, len(task_json)) + task_json

        # Connect to task submit service (port 1003)
        with self.dial(f"{addr}:1003") as conn:
            # Send submit frame
            conn.write(frame)
            
            # Read response frame: [4-byte type][4-byte length][JSON payload]
            header = conn.read(8)
            if not header or len(header) < 8:
                raise PilotError("No response from task submit service")
            
            resp_type, resp_len = struct.unpack('>II', header)
            response_data = conn.read(resp_len)
            
            if not response_data or len(response_data) < resp_len:
                raise PilotError("Incomplete response from task submit service")
            
            # Parse JSON response
            try:
                resp = json.loads(response_data.decode('utf-8'))
                return resp
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                raise PilotError(f"Invalid response format: {e}")
