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

    def PilotSetTaskExec(self, h, enabled):
        return self._json_returns.get("PilotSetTaskExec", _json_ok({"status": "ok"}))

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
        return _ReadResult(n=5, data=b"hello", err=None)

    def PilotConnWrite(self, ch, data, data_len):
        return _WriteResult(n=data_len, err=None)

    def PilotConnClose(self, ch):
        return None

    def PilotSendTo(self, h, addr, data, data_len):
        return None


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
        fake_lib._connect_result = _HandleErr(handle=0, err=_json_err("no daemon"))
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

    def test_set_task_exec(self, fake_lib):
        d = client_mod.Driver()
        r = d.set_task_exec(False)
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
        fake_lib.PilotDial = lambda self, h, addr: _HandleErr(handle=0, err=_json_err("unreachable"))
        # Rebind as method
        orig = fake_lib.PilotDial
        fake_lib.PilotDial = lambda h, addr: _HandleErr(handle=0, err=_json_err("unreachable"))
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
        fake_lib.PilotListen = lambda h, port: _HandleErr(handle=0, err=_json_err("port in use"))
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
        fake_lib.PilotConnRead = lambda h, size: _ReadResult(
            data=None, n=0, err=_json_err("connection reset")
        )
        
        conn = client_mod.Conn(10)
        with pytest.raises(PilotError, match="connection reset"):
            conn.read()

    def test_read_empty_response(self, fake_lib):
        """Test Conn.read when Go returns 0 bytes."""
        fake_lib.PilotConnRead = lambda h, size: _ReadResult(
            data=None, n=0, err=None
        )
        
        conn = client_mod.Conn(10)
        result = conn.read()
        assert result == b""

    def test_write_error_from_go(self, fake_lib):
        """Test Conn.write when Go returns an error."""
        fake_lib.PilotConnWrite = lambda h, buf, size: _WriteResult(
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
        fake_lib.PilotListenerAccept = lambda h: _HandleErr(
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
