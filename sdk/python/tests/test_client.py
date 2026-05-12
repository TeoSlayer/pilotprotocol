"""Unit tests for the ctypes-based Python SDK.

These tests mock the C boundary (the loaded CDLL) so they run without
a real daemon or shared library.  They verify:
  - Library discovery logic
  - JSON error parsing helpers
  - Driver / Conn / Listener Python wrappers behave correctly
  - Argument marshalling and memory management patterns
"""

from __future__ import annotations

import ctypes
import json
import os
import platform
import types
from pathlib import Path
from unittest import mock

import pytest

# We need to import the module but mock the library loading to avoid
# needing the actual .so/.dylib at test time.

import pilotprotocol.client as client_mod
from pilotprotocol.client import (
    PilotError,
    _HandleErr,
    _ReadResult,
    _WriteResult,
    _check_err,
    _parse_json,
    DEFAULT_SOCKET_PATH,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _json_err(msg: str) -> bytes:
    return json.dumps({"error": msg}).encode()


def _json_ok(data: dict) -> bytes:
    return json.dumps(data).encode()


def _mock_handle_err(handle: int = 0, err: bytes | None = None):
    """Create a mock HandleErr-like object compatible with c_void_p fields.

    ctypes c_void_p fields reject bytes values directly, so we use
    SimpleNamespace for mocks that need non-null err pointers.
    """
    return types.SimpleNamespace(handle=handle, err=err)


def _mock_read_result(n: int = 0, data: bytes | None = None, err: bytes | None = None):
    """Create a mock ReadResult-like object."""
    return types.SimpleNamespace(n=n, data=data, err=err)


def _mock_write_result(n: int = 0, err: bytes | None = None):
    """Create a mock WriteResult-like object."""
    return types.SimpleNamespace(n=n, err=err)


def _unwrap(x):
    """Coerce a ctypes-wrapped scalar into its plain Python value.

    The Driver wraps ints in ctypes types (c_uint16, c_int32, etc.) before
    calling into the C library. Real ctypes converts those to plain ints at
    the FFI boundary, but our FakeLib receives them as objects, so we strip
    the wrapper here for clean assertions.
    """
    return x.value if hasattr(x, "value") else x


class FakeLib:
    """Mimics the ctypes.CDLL object with controllable return values."""

    def __init__(self):
        self._freed: list[bytes] = []
        self._connect_result = _HandleErr(handle=1, err=None)
        self._json_returns: dict[str, bytes | None] = {}

    def FreeString(self, ptr):
        if ptr:
            self._freed.append(ptr)

    def PilotConnect(self, path):
        return self._connect_result

    def PilotClose(self, h):
        return None

    def PilotInfo(self, h):
        return self._json_returns.get("PilotInfo", _json_ok({"node_id": 42}))

    def PilotPendingHandshakes(self, h):
        return self._json_returns.get("PilotPendingHandshakes", _json_ok({"pending": []}))

    def PilotTrustedPeers(self, h):
        return self._json_returns.get("PilotTrustedPeers", _json_ok({"peers": []}))

    def PilotDeregister(self, h):
        return self._json_returns.get("PilotDeregister", _json_ok({"status": "ok"}))

    def PilotHandshake(self, h, node_id, justification):
        return self._json_returns.get("PilotHandshake", _json_ok({"status": "sent"}))

    def PilotApproveHandshake(self, h, node_id):
        return self._json_returns.get("PilotApproveHandshake", _json_ok({"status": "approved"}))

    def PilotRejectHandshake(self, h, node_id, reason):
        return self._json_returns.get("PilotRejectHandshake", _json_ok({"status": "rejected"}))

    def PilotRevokeTrust(self, h, node_id):
        return self._json_returns.get("PilotRevokeTrust", _json_ok({"status": "revoked"}))

    def PilotResolveHostname(self, h, hostname):
        return self._json_returns.get("PilotResolveHostname", _json_ok({"node_id": 7}))

    def PilotSetHostname(self, h, hostname):
        return self._json_returns.get("PilotSetHostname", _json_ok({"status": "ok"}))

    def PilotSetVisibility(self, h, public):
        return self._json_returns.get("PilotSetVisibility", _json_ok({"status": "ok"}))

    def PilotSetTags(self, h, tags_json):
        return self._json_returns.get("PilotSetTags", _json_ok({"status": "ok"}))

    def PilotSetWebhook(self, h, url):
        return self._json_returns.get("PilotSetWebhook", _json_ok({"status": "ok"}))

    def PilotDisconnect(self, h, conn_id):
        return None

    def PilotRecvFrom(self, h):
        return self._json_returns.get("PilotRecvFrom", _json_ok({
            "src_addr": "0:0001.0000.0001",
            "src_port": 8080,
            "dst_port": 9090,
            "data": "aGVsbG8=",
        }))

    def PilotDial(self, h, addr):
        return _HandleErr(handle=10, err=None)

    def PilotListen(self, h, port):
        return _HandleErr(handle=20, err=None)

    def PilotListenerAccept(self, lh):
        return _HandleErr(handle=30, err=None)

    def PilotListenerClose(self, lh):
        return None

    def PilotConnRead(self, ch, buf_size):
        return _mock_read_result(n=5, data=b"hello", err=None)

    def PilotConnWrite(self, ch, data, data_len):
        return _WriteResult(n=data_len, err=None)

    def PilotConnClose(self, ch):
        return None

    def PilotSendTo(self, h, addr, data, data_len):
        return None

    # --- 1.9.1 additions ---

    def PilotHealth(self, h):
        return self._json_returns.get("PilotHealth", _json_ok({"ok": True, "uptime_s": 42}))

    def PilotRotateKey(self, h):
        return self._json_returns.get("PilotRotateKey", _json_ok({"new_pubkey": "abc"}))

    def PilotDialTimeout(self, h, addr, timeout_ms):
        # capture for assertions
        self._last_dial_timeout = (addr, _unwrap(timeout_ms))
        return _HandleErr(handle=11, err=None)

    def PilotConnSetReadDeadline(self, h, deadline_unix_nanos):
        # capture deadline for assertions
        self._last_set_read_deadline = _unwrap(deadline_unix_nanos)
        return None

    def PilotBroadcast(self, h, network_id, port, data, data_len, admin_token):
        self._last_broadcast = {
            "network_id": _unwrap(network_id),
            "port": _unwrap(port),
            "data_len": _unwrap(data_len),
            "admin_token": admin_token,
        }
        return self._json_returns.get("PilotBroadcast", None)

    def PilotNetworkList(self, h):
        return self._json_returns.get("PilotNetworkList", _json_ok({"networks": [{"id": 0}]}))

    def PilotNetworkJoin(self, h, network_id, token):
        self._last_network_join = (_unwrap(network_id), token)
        return self._json_returns.get("PilotNetworkJoin", _json_ok({"status": "joined"}))

    def PilotNetworkLeave(self, h, network_id):
        return self._json_returns.get("PilotNetworkLeave", _json_ok({"status": "left"}))

    def PilotNetworkMembers(self, h, network_id):
        return self._json_returns.get("PilotNetworkMembers", _json_ok({"members": []}))

    def PilotNetworkInvite(self, h, network_id, target_node_id):
        self._last_network_invite = (_unwrap(network_id), _unwrap(target_node_id))
        return self._json_returns.get("PilotNetworkInvite", _json_ok({"status": "invited"}))

    def PilotNetworkPollInvites(self, h):
        return self._json_returns.get("PilotNetworkPollInvites", _json_ok({"invites": []}))

    def PilotNetworkRespondInvite(self, h, network_id, accept):
        self._last_network_respond = (_unwrap(network_id), _unwrap(accept))
        return self._json_returns.get(
            "PilotNetworkRespondInvite", _json_ok({"status": "responded"})
        )

    def PilotManagedScore(self, h, network_id, node_id, delta, topic):
        self._last_managed_score = (
            _unwrap(network_id), _unwrap(node_id), _unwrap(delta), topic,
        )
        return self._json_returns.get("PilotManagedScore", _json_ok({"status": "ok"}))

    def PilotManagedStatus(self, h, network_id):
        return self._json_returns.get(
            "PilotManagedStatus", _json_ok({"network_id": _unwrap(network_id)})
        )

    def PilotManagedRankings(self, h, network_id):
        return self._json_returns.get("PilotManagedRankings", _json_ok({"rankings": []}))

    def PilotManagedForceCycle(self, h, network_id):
        return self._json_returns.get("PilotManagedForceCycle", _json_ok({"status": "cycled"}))

    def PilotManagedReconcile(self, h, network_id):
        return self._json_returns.get(
            "PilotManagedReconcile",
            _json_ok({"network_id": _unwrap(network_id), "peers": []}),
        )

    def PilotPolicyGet(self, h, network_id):
        return self._json_returns.get(
            "PilotPolicyGet",
            _json_ok({"network_id": _unwrap(network_id), "policy": {}}),
        )

    def PilotPolicySet(self, h, network_id, policy_json):
        self._last_policy_set = (_unwrap(network_id), policy_json)
        return self._json_returns.get("PilotPolicySet", _json_ok({"status": "applied"}))

    def PilotMemberTagsGet(self, h, network_id, node_id):
        return self._json_returns.get("PilotMemberTagsGet", _json_ok({"tags": []}))

    def PilotMemberTagsSet(self, h, network_id, node_id, tags_json):
        self._last_member_tags_set = (
            _unwrap(network_id), _unwrap(node_id), tags_json,
        )
        return self._json_returns.get("PilotMemberTagsSet", _json_ok({"status": "ok"}))


@pytest.fixture(autouse=True)
def _mock_lib(monkeypatch):
    """Replace the global _lib with FakeLib for every test."""
    fake = FakeLib()
    monkeypatch.setattr(client_mod, "_lib", fake)
    # Also patch _get_lib to return our fake
    monkeypatch.setattr(client_mod, "_get_lib", lambda: fake)
    return fake


@pytest.fixture
def fake_lib(_mock_lib) -> FakeLib:
    return _mock_lib


# ---------------------------------------------------------------------------
# Error helper tests
# ---------------------------------------------------------------------------

class TestCheckErr:
    def test_none_is_ok(self):
        _check_err(None)  # should not raise

    def test_json_error_raises(self):
        with pytest.raises(PilotError, match="boom"):
            _check_err(_json_err("boom"))


class TestParseJSON:
    def test_none_returns_empty(self):
        assert _parse_json(None) == {}

    def test_valid_json(self):
        assert _parse_json(_json_ok({"a": 1})) == {"a": 1}

    def test_error_raises(self):
        with pytest.raises(PilotError, match="fail"):
            _parse_json(_json_err("fail"))


# ---------------------------------------------------------------------------
# Driver tests
# ---------------------------------------------------------------------------

class TestDriverLifecycle:
    def test_connect_default_path(self, fake_lib):
        d = client_mod.Driver()
        assert d._h == 1
        assert not d._closed

    def test_connect_custom_path(self, fake_lib):
        d = client_mod.Driver("/custom/pilot.sock")
        assert d._h == 1

    def test_connect_error(self, fake_lib):
        fake_lib._connect_result = _mock_handle_err(handle=0, err=_json_err("no daemon"))
        with pytest.raises(PilotError, match="no daemon"):
            client_mod.Driver()

    def test_close(self, fake_lib):
        d = client_mod.Driver()
        d.close()
        assert d._closed

    def test_close_idempotent(self, fake_lib):
        d = client_mod.Driver()
        d.close()
        d.close()  # should not raise

    def test_context_manager(self, fake_lib):
        with client_mod.Driver() as d:
            assert not d._closed
        assert d._closed


class TestDriverInfo:
    def test_info_success(self, fake_lib):
        d = client_mod.Driver()
        result = d.info()
        assert result == {"node_id": 42}

    def test_info_error(self, fake_lib):
        fake_lib._json_returns["PilotInfo"] = _json_err("daemon unreachable")
        d = client_mod.Driver()
        with pytest.raises(PilotError, match="daemon unreachable"):
            d.info()


class TestDriverHandshake:
    def test_handshake(self, fake_lib):
        d = client_mod.Driver()
        r = d.handshake(42, "test")
        assert r["status"] == "sent"

    def test_approve(self, fake_lib):
        d = client_mod.Driver()
        r = d.approve_handshake(42)
        assert r["status"] == "approved"

    def test_reject(self, fake_lib):
        d = client_mod.Driver()
        r = d.reject_handshake(42, "no thanks")
        assert r["status"] == "rejected"

    def test_pending(self, fake_lib):
        d = client_mod.Driver()
        r = d.pending_handshakes()
        assert "pending" in r

    def test_trusted(self, fake_lib):
        d = client_mod.Driver()
        r = d.trusted_peers()
        assert "peers" in r

    def test_revoke(self, fake_lib):
        d = client_mod.Driver()
        r = d.revoke_trust(42)
        assert r["status"] == "revoked"


class TestDriverHostname:
    def test_resolve(self, fake_lib):
        d = client_mod.Driver()
        r = d.resolve_hostname("myhost")
        assert r["node_id"] == 7

    def test_set_hostname(self, fake_lib):
        d = client_mod.Driver()
        r = d.set_hostname("newhost")
        assert r["status"] == "ok"


class TestDriverSettings:
    def test_set_visibility(self, fake_lib):
        d = client_mod.Driver()
        r = d.set_visibility(True)
        assert r["status"] == "ok"

    def test_deregister(self, fake_lib):
        d = client_mod.Driver()
        r = d.deregister()
        assert r["status"] == "ok"

    def test_set_tags(self, fake_lib):
        d = client_mod.Driver()
        r = d.set_tags(["gpu", "cuda"])
        assert r["status"] == "ok"

    def test_set_webhook(self, fake_lib):
        d = client_mod.Driver()
        r = d.set_webhook("https://example.com/hook")
        assert r["status"] == "ok"


class TestDriverDisconnect:
    def test_disconnect(self, fake_lib):
        d = client_mod.Driver()
        d.disconnect(123)  # should not raise


# ---------------------------------------------------------------------------
# Stream tests
# ---------------------------------------------------------------------------

class TestDriverDial:
    def test_dial_returns_conn(self, fake_lib):
        d = client_mod.Driver()
        conn = d.dial("0:0001.0000.0002:8080")
        assert isinstance(conn, client_mod.Conn)
        assert conn._h == 10

    def test_dial_error(self, fake_lib):
        fake_lib.PilotDial = lambda h, addr: _mock_handle_err(handle=0, err=_json_err("unreachable"))
        d = client_mod.Driver()
        with pytest.raises(PilotError, match="unreachable"):
            d.dial("bad:addr")


class TestDriverListen:
    def test_listen_returns_listener(self, fake_lib):
        d = client_mod.Driver()
        ln = d.listen(8080)
        assert isinstance(ln, client_mod.Listener)
        assert ln._h == 20

    def test_listen_error(self, fake_lib):
        fake_lib.PilotListen = lambda h, port: _mock_handle_err(handle=0, err=_json_err("port in use"))
        d = client_mod.Driver()
        with pytest.raises(PilotError, match="port in use"):
            d.listen(8080)


class TestConn:
    def test_read(self, fake_lib):
        conn = client_mod.Conn(10)
        data = conn.read(4096)
        assert data == b"hello"

    def test_read_closed_raises(self, fake_lib):
        conn = client_mod.Conn(10)
        conn.close()
        with pytest.raises(PilotError, match="closed"):
            conn.read()

    def test_write(self, fake_lib):
        conn = client_mod.Conn(10)
        n = conn.write(b"world")
        assert n == 5

    def test_write_closed_raises(self, fake_lib):
        conn = client_mod.Conn(10)
        conn.close()
        with pytest.raises(PilotError, match="closed"):
            conn.write(b"x")

    def test_close_idempotent(self, fake_lib):
        conn = client_mod.Conn(10)
        conn.close()
        conn.close()  # no error

    def test_context_manager(self, fake_lib):
        with client_mod.Conn(10) as c:
            assert not c._closed
        assert c._closed


class TestListener:
    def test_accept(self, fake_lib):
        ln = client_mod.Listener(20)
        conn = ln.accept()
        assert isinstance(conn, client_mod.Conn)
        assert conn._h == 30

    def test_accept_closed_raises(self, fake_lib):
        ln = client_mod.Listener(20)
        ln.close()
        with pytest.raises(PilotError, match="closed"):
            ln.accept()

    def test_close_idempotent(self, fake_lib):
        ln = client_mod.Listener(20)
        ln.close()
        ln.close()

    def test_context_manager(self, fake_lib):
        with client_mod.Listener(20) as ln:
            assert not ln._closed
        assert ln._closed


# ---------------------------------------------------------------------------
# Datagram tests
# ---------------------------------------------------------------------------

class TestDatagrams:
    def test_send_to(self, fake_lib):
        d = client_mod.Driver()
        d.send_to("0:0001.0000.0002:9090", b"payload")  # should not raise

    def test_recv_from(self, fake_lib):
        d = client_mod.Driver()
        dg = d.recv_from()
        assert dg["src_port"] == 8080
        assert dg["dst_port"] == 9090


# ---------------------------------------------------------------------------
# Library discovery tests
# ---------------------------------------------------------------------------

class TestFindLibrary:
    def test_env_override(self, tmp_path, monkeypatch):
        lib_file = tmp_path / "libpilot.dylib"
        lib_file.touch()
        monkeypatch.setenv("PILOT_LIB_PATH", str(lib_file))
        result = client_mod._find_library()
        assert result == str(lib_file)

    def test_env_missing_raises(self, monkeypatch):
        monkeypatch.setenv("PILOT_LIB_PATH", "/nonexistent/libpilot.dylib")
        with pytest.raises(FileNotFoundError, match="does not exist"):
            client_mod._find_library()

    def test_unsupported_platform(self, monkeypatch):
        monkeypatch.setattr("platform.system", lambda: "FreeBSD")
        monkeypatch.delenv("PILOT_LIB_PATH", raising=False)
        with pytest.raises(OSError, match="unsupported platform"):
            client_mod._find_library()


# ---------------------------------------------------------------------------
# DEFAULT_SOCKET_PATH constant
# ---------------------------------------------------------------------------

def test_default_socket_path():
    assert DEFAULT_SOCKET_PATH == "/tmp/pilot.sock"


# ---------------------------------------------------------------------------
# Additional coverage for 100%
# ---------------------------------------------------------------------------

class TestLibraryDiscoveryFallbacks:
    """Test all library discovery paths."""

    def test_same_directory_as_file(self, tmp_path, monkeypatch):
        # Create fake library next to client.py
        client_dir = Path(client_mod.__file__).parent
        lib_name = client_mod._LIB_NAMES[platform.system()]
        
        # We can't actually create a file there, so we mock Path.is_file
        def mock_is_file(self):
            if self.name == lib_name and self.parent == client_dir:
                return True
            return False
        
        monkeypatch.setattr(Path, "is_file", mock_is_file)
        monkeypatch.delenv("PILOT_LIB_PATH", raising=False)
        
        result = client_mod._find_library()
        assert lib_name in result

    def test_repo_bin_directory(self, tmp_path, monkeypatch):
        # Create temporary repo structure
        repo_root = tmp_path / "repo"
        bin_dir = repo_root / "bin"
        bin_dir.mkdir(parents=True)
        
        lib_name = client_mod._LIB_NAMES[platform.system()]
        lib_file = bin_dir / lib_name
        lib_file.touch()
        
        # Mock __file__ to point into this fake repo
        fake_client_path = repo_root / "sdk" / "python" / "pilotprotocol" / "client.py"
        fake_client_path.parent.mkdir(parents=True)
        
        monkeypatch.setattr(client_mod, "__file__", str(fake_client_path))
        monkeypatch.delenv("PILOT_LIB_PATH", raising=False)
        
        result = client_mod._find_library()
        assert str(lib_file) == result

    def test_system_search_path(self, monkeypatch):
        """Test ctypes.util.find_library fallback."""
        monkeypatch.delenv("PILOT_LIB_PATH", raising=False)
        
        # Mock Path.is_file to always return False (skip env and local paths)
        monkeypatch.setattr(Path, "is_file", lambda self: False)
        
        # Mock ctypes.util.find_library to return a path
        monkeypatch.setattr(
            "ctypes.util.find_library",
            lambda name: "/usr/local/lib/libpilot.so" if name == "pilot" else None
        )
        
        result = client_mod._find_library()
        assert result == "/usr/local/lib/libpilot.so"

    def test_not_found_raises(self, monkeypatch):
        """Test FileNotFoundError when library is nowhere."""
        monkeypatch.delenv("PILOT_LIB_PATH", raising=False)
        monkeypatch.setattr(Path, "is_file", lambda self: False)
        monkeypatch.setattr("ctypes.util.find_library", lambda name: None)
        
        with pytest.raises(FileNotFoundError, match="Cannot find"):
            client_mod._find_library()


class TestConnErrorPaths:
    """Test error handling in Conn methods."""

    def test_read_error_from_go(self, fake_lib):
        """Test Conn.read when Go returns an error."""
        fake_lib.PilotConnRead = lambda h, size: _mock_read_result(
            data=None, n=0, err=_json_err("connection reset")
        )
        
        conn = client_mod.Conn(10)
        with pytest.raises(PilotError, match="connection reset"):
            conn.read()

    def test_read_empty_response(self, fake_lib):
        """Test Conn.read when Go returns 0 bytes."""
        fake_lib.PilotConnRead = lambda h, size: _mock_read_result(
            data=None, n=0, err=None
        )
        
        conn = client_mod.Conn(10)
        result = conn.read()
        assert result == b""

    def test_write_error_from_go(self, fake_lib):
        """Test Conn.write when Go returns an error."""
        fake_lib.PilotConnWrite = lambda h, buf, size: _mock_write_result(
            n=0, err=_json_err("broken pipe")
        )
        
        conn = client_mod.Conn(10)
        with pytest.raises(PilotError, match="broken pipe"):
            conn.write(b"data")

    def test_close_with_error_response(self, fake_lib):
        """Test Conn.close when Go returns an error."""
        fake_lib.PilotConnClose = lambda h: _json_err("already closed")
        
        conn = client_mod.Conn(10)
        with pytest.raises(PilotError, match="already closed"):
            conn.close()

    def test_del_calls_close(self, fake_lib):
        """Test Conn.__del__ calls close()."""
        conn = client_mod.Conn(10)
        assert not conn._closed
        conn.__del__()
        assert conn._closed

    def test_del_catches_exceptions(self, fake_lib):
        """Test Conn.__del__ catches close() exceptions."""
        fake_lib.PilotConnClose = lambda h: _json_err("error")
        
        conn = client_mod.Conn(10)
        # Should not raise even though close() would raise
        conn.__del__()
        assert conn._closed


class TestListenerErrorPaths:
    """Test error handling in Listener methods."""

    def test_accept_error_from_go(self, fake_lib):
        """Test Listener.accept when Go returns an error."""
        fake_lib.PilotListenerAccept = lambda h: _mock_handle_err(
            handle=0, err=_json_err("listener closed")
        )
        
        ln = client_mod.Listener(20)
        with pytest.raises(PilotError, match="listener closed"):
            ln.accept()

    def test_close_with_error_response(self, fake_lib):
        """Test Listener.close when Go returns an error."""
        fake_lib.PilotListenerClose = lambda h: _json_err("already closed")
        
        ln = client_mod.Listener(20)
        with pytest.raises(PilotError, match="already closed"):
            ln.close()

    def test_del_calls_close(self, fake_lib):
        """Test Listener.__del__ calls close()."""
        ln = client_mod.Listener(20)
        assert not ln._closed
        ln.__del__()
        assert ln._closed

    def test_del_catches_exceptions(self, fake_lib):
        """Test Listener.__del__ catches close() exceptions."""
        fake_lib.PilotListenerClose = lambda h: _json_err("error")

        ln = client_mod.Listener(20)
        # Should not raise even though close() would raise
        ln.__del__()
        assert ln._closed


# ---------------------------------------------------------------------------
# 1.9.1 additions: health / rotate-key
# ---------------------------------------------------------------------------

class TestDriverHealth:
    def test_health_success(self, fake_lib):
        d = client_mod.Driver()
        r = d.health()
        assert r["ok"] is True
        assert r["uptime_s"] == 42

    def test_health_error(self, fake_lib):
        fake_lib._json_returns["PilotHealth"] = _json_err("daemon down")
        d = client_mod.Driver()
        with pytest.raises(PilotError, match="daemon down"):
            d.health()


class TestDriverRotateKey:
    def test_rotate_key(self, fake_lib):
        d = client_mod.Driver()
        r = d.rotate_key()
        assert r["new_pubkey"] == "abc"

    def test_rotate_identity_alias(self, fake_lib):
        d = client_mod.Driver()
        # rotate_identity should delegate to rotate_key
        r = d.rotate_identity()
        assert r["new_pubkey"] == "abc"

    def test_rotate_key_error(self, fake_lib):
        fake_lib._json_returns["PilotRotateKey"] = _json_err("registry rejected")
        d = client_mod.Driver()
        with pytest.raises(PilotError, match="registry rejected"):
            d.rotate_key()


# ---------------------------------------------------------------------------
# 1.9.1 additions: dial timeout
# ---------------------------------------------------------------------------

class TestDriverDialTimeout:
    def test_dial_without_timeout_uses_pilot_dial(self, fake_lib):
        # No timeout → original PilotDial path (handle=10)
        d = client_mod.Driver()
        conn = d.dial("0:0001.0000.0002:8080")
        assert conn._h == 10

    def test_dial_with_timeout_uses_pilot_dial_timeout(self, fake_lib):
        d = client_mod.Driver()
        conn = d.dial("0:0001.0000.0002:8080", timeout=2.5)
        # Timeout path returns handle=11
        assert conn._h == 11
        # 2.5 s = 2500 ms
        assert fake_lib._last_dial_timeout == (b"0:0001.0000.0002:8080", 2500)

    def test_dial_timeout_zero_floor(self, fake_lib):
        d = client_mod.Driver()
        d.dial("0:0001.0000.0002:8080", timeout=-1.0)
        # Negative → clamped to 0 ms
        _, ms = fake_lib._last_dial_timeout
        assert ms == 0

    def test_dial_timeout_error(self, fake_lib):
        fake_lib.PilotDialTimeout = lambda h, addr, ms: _mock_handle_err(
            handle=0, err=_json_err("dial timeout")
        )
        d = client_mod.Driver()
        with pytest.raises(PilotError, match="dial timeout"):
            d.dial("bad:addr", timeout=1.0)


# ---------------------------------------------------------------------------
# 1.9.1 additions: Conn.set_read_deadline
# ---------------------------------------------------------------------------

class TestConnReadDeadline:
    def test_clear_deadline_with_none(self, fake_lib):
        conn = client_mod.Conn(10)
        conn.set_read_deadline(None)
        assert fake_lib._last_set_read_deadline == 0

    def test_set_deadline_seconds_to_nanos(self, fake_lib):
        conn = client_mod.Conn(10)
        # 1700000000.5 s → 1_700_000_000_500_000_000 ns
        conn.set_read_deadline(1_700_000_000.5)
        assert fake_lib._last_set_read_deadline == 1_700_000_000_500_000_000

    def test_set_deadline_on_closed_conn_raises(self, fake_lib):
        conn = client_mod.Conn(10)
        conn.close()
        with pytest.raises(PilotError, match="closed"):
            conn.set_read_deadline(0.0)

    def test_set_deadline_propagates_error(self, fake_lib):
        fake_lib.PilotConnSetReadDeadline = lambda h, d: _json_err("bad handle")
        conn = client_mod.Conn(10)
        with pytest.raises(PilotError, match="bad handle"):
            conn.set_read_deadline(None)


# ---------------------------------------------------------------------------
# 1.9.1 additions: broadcast
# ---------------------------------------------------------------------------

class TestDriverBroadcast:
    def test_broadcast_passes_args(self, fake_lib):
        d = client_mod.Driver()
        d.broadcast(7, 1234, b"hello", "secret")
        captured = fake_lib._last_broadcast
        assert captured["network_id"] == 7
        assert captured["port"] == 1234
        assert captured["data_len"] == 5
        assert captured["admin_token"] == b"secret"

    def test_broadcast_propagates_error(self, fake_lib):
        fake_lib._json_returns["PilotBroadcast"] = _json_err("admin token required")
        d = client_mod.Driver()
        with pytest.raises(PilotError, match="admin token required"):
            d.broadcast(0, 9000, b"x", "")


# ---------------------------------------------------------------------------
# 1.9.1 additions: networks
# ---------------------------------------------------------------------------

class TestDriverNetworks:
    def test_network_list(self, fake_lib):
        d = client_mod.Driver()
        r = d.network_list()
        assert "networks" in r

    def test_network_join_passes_args(self, fake_lib):
        d = client_mod.Driver()
        r = d.network_join(7, "joinme")
        assert r["status"] == "joined"
        assert fake_lib._last_network_join == (7, b"joinme")

    def test_network_join_default_empty_token(self, fake_lib):
        d = client_mod.Driver()
        d.network_join(2)
        assert fake_lib._last_network_join == (2, b"")

    def test_network_leave(self, fake_lib):
        d = client_mod.Driver()
        r = d.network_leave(7)
        assert r["status"] == "left"

    def test_network_members(self, fake_lib):
        d = client_mod.Driver()
        r = d.network_members(7)
        assert "members" in r

    def test_network_invite(self, fake_lib):
        d = client_mod.Driver()
        r = d.network_invite(7, 4242)
        assert r["status"] == "invited"
        assert fake_lib._last_network_invite == (7, 4242)

    def test_network_poll_invites(self, fake_lib):
        d = client_mod.Driver()
        r = d.network_poll_invites()
        assert "invites" in r

    def test_network_respond_invite_accept(self, fake_lib):
        d = client_mod.Driver()
        d.network_respond_invite(7, True)
        assert fake_lib._last_network_respond == (7, 1)

    def test_network_respond_invite_reject(self, fake_lib):
        d = client_mod.Driver()
        d.network_respond_invite(7, False)
        assert fake_lib._last_network_respond == (7, 0)

    def test_network_join_error(self, fake_lib):
        fake_lib._json_returns["PilotNetworkJoin"] = _json_err("token rejected")
        d = client_mod.Driver()
        with pytest.raises(PilotError, match="token rejected"):
            d.network_join(7, "wrong")


# ---------------------------------------------------------------------------
# 1.9.1 additions: managed networks
# ---------------------------------------------------------------------------

class TestDriverManaged:
    def test_managed_score_passes_args(self, fake_lib):
        d = client_mod.Driver()
        r = d.managed_score(7, 4242, -3, "spam")
        assert r["status"] == "ok"
        assert fake_lib._last_managed_score == (7, 4242, -3, b"spam")

    def test_managed_score_default_topic(self, fake_lib):
        d = client_mod.Driver()
        d.managed_score(0, 1, 5)
        assert fake_lib._last_managed_score == (0, 1, 5, b"")

    def test_managed_score_negative_delta_preserved(self, fake_lib):
        # int32 delta — make sure negative numbers survive
        d = client_mod.Driver()
        d.managed_score(0, 1, -100000, "x")
        assert fake_lib._last_managed_score[2] == -100000

    def test_managed_status(self, fake_lib):
        d = client_mod.Driver()
        r = d.managed_status(42)
        assert r["network_id"] == 42

    def test_managed_rankings(self, fake_lib):
        d = client_mod.Driver()
        r = d.managed_rankings(42)
        assert "rankings" in r

    def test_managed_force_cycle(self, fake_lib):
        d = client_mod.Driver()
        r = d.managed_force_cycle(42)
        assert r["status"] == "cycled"

    def test_managed_reconcile(self, fake_lib):
        d = client_mod.Driver()
        r = d.managed_reconcile(42)
        assert r["network_id"] == 42
        assert r["peers"] == []


# ---------------------------------------------------------------------------
# 1.9.1 additions: policy
# ---------------------------------------------------------------------------

class TestDriverPolicy:
    def test_policy_get(self, fake_lib):
        d = client_mod.Driver()
        r = d.policy_get(7)
        assert r["network_id"] == 7

    def test_policy_set_dict_serializes_to_json(self, fake_lib):
        d = client_mod.Driver()
        d.policy_set(7, {"min_score": 3, "tags": ["good"]})
        net_id, payload = fake_lib._last_policy_set
        assert net_id == 7
        # The payload was JSON-serialized
        assert json.loads(payload) == {"min_score": 3, "tags": ["good"]}

    def test_policy_set_string_passthrough(self, fake_lib):
        d = client_mod.Driver()
        d.policy_set(0, '{"raw":true}')
        _, payload = fake_lib._last_policy_set
        assert payload == b'{"raw":true}'

    def test_policy_set_bytes_passthrough(self, fake_lib):
        d = client_mod.Driver()
        d.policy_set(0, b'{"raw":1}')
        _, payload = fake_lib._last_policy_set
        assert payload == b'{"raw":1}'

    def test_policy_set_error(self, fake_lib):
        fake_lib._json_returns["PilotPolicySet"] = _json_err("invalid policy")
        d = client_mod.Driver()
        with pytest.raises(PilotError, match="invalid policy"):
            d.policy_set(0, {})


# ---------------------------------------------------------------------------
# 1.9.1 additions: member tags
# ---------------------------------------------------------------------------

class TestDriverMemberTags:
    def test_member_tags_get(self, fake_lib):
        d = client_mod.Driver()
        r = d.member_tags_get(7, 4242)
        assert "tags" in r

    def test_member_tags_set_serializes_list(self, fake_lib):
        d = client_mod.Driver()
        d.member_tags_set(7, 4242, ["gpu", "fast"])
        net_id, node_id, tags_json = fake_lib._last_member_tags_set
        assert net_id == 7
        assert node_id == 4242
        assert json.loads(tags_json) == ["gpu", "fast"]

    def test_member_tags_set_empty_list(self, fake_lib):
        d = client_mod.Driver()
        d.member_tags_set(7, 4242, [])
        _, _, tags_json = fake_lib._last_member_tags_set
        assert json.loads(tags_json) == []

    def test_member_tags_set_error(self, fake_lib):
        fake_lib._json_returns["PilotMemberTagsSet"] = _json_err("not admin")
        d = client_mod.Driver()
        with pytest.raises(PilotError, match="not admin"):
            d.member_tags_set(7, 1, ["x"])
