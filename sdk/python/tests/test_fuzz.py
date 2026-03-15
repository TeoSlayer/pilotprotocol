"""
Fuzz / adversarial testing for the Python SDK.

Tries to break the SDK with:
  - Malformed inputs (None, negative numbers, huge strings)
  - Boundary conditions (0-byte reads, port limits)
  - Unicode / binary edge cases
  - Resource exhaustion (many connections)
  - Use-after-close / double-close patterns
  - Type coercion traps

Run:  python -m pytest tests/test_fuzz.py -v --no-header -p no:cacheprovider
"""

import os
import pytest
from pilotprotocol.client import Driver, Conn, Listener, PilotError

SOCKET = "/tmp/pilot.sock"

pytestmark = pytest.mark.skipif(
    not os.path.exists(SOCKET),
    reason=f"No daemon at {SOCKET}",
)


@pytest.fixture(scope="module")
def driver():
    d = Driver(SOCKET)
    yield d
    d.close()


@pytest.fixture(scope="module")
def addr(driver):
    info = driver.info()
    return info["address"]


# ================================================================
# Connection lifecycle
# ================================================================

class TestLifecycle:
    def test_connect(self):
        d = Driver(SOCKET)
        assert d is not None
        d.close()

    def test_close_idempotent(self):
        d = Driver(SOCKET)
        d.close()
        d.close()
        d.close()

    def test_context_manager(self):
        with Driver(SOCKET) as d:
            info = d.info()
            assert "node_id" in info

    def test_bad_socket_path(self):
        with pytest.raises(PilotError):
            Driver("/nonexistent/socket.sock")

    def test_two_drivers_coexist(self):
        d1 = Driver(SOCKET)
        d2 = Driver(SOCKET)
        assert d1.info()["node_id"] == d2.info()["node_id"]
        d1.close()
        d2.close()

    def test_rapid_open_close(self):
        for _ in range(20):
            d = Driver(SOCKET)
            d.close()


# ================================================================
# Malformed hostname inputs
# ================================================================

class TestHostnameFuzz:
    def test_empty(self, driver):
        driver.set_hostname("")

    def test_single_char(self, driver):
        driver.set_hostname("a")
        driver.set_hostname("")

    def test_long_255(self, driver):
        with pytest.raises(PilotError):
            driver.set_hostname("a" * 255)

    def test_long_1000(self, driver):
        with pytest.raises(PilotError):
            driver.set_hostname("x" * 1000)

    def test_unicode_emoji(self, driver):
        with pytest.raises(PilotError):
            driver.set_hostname("🚀🔥💯")

    def test_unicode_cjk(self, driver):
        with pytest.raises(PilotError):
            driver.set_hostname("测试节点")

    def test_special_chars(self, driver):
        with pytest.raises(PilotError):
            driver.set_hostname("node--test..name")

    def test_sql_injection(self, driver):
        with pytest.raises(PilotError):
            driver.set_hostname("'; DROP TABLE nodes; --")

    def test_newlines(self, driver):
        with pytest.raises(PilotError):
            driver.set_hostname("host\nname\twith\0null")

    def test_path_traversal(self, driver):
        with pytest.raises(PilotError):
            driver.set_hostname("../../etc/passwd")

    def test_resolve_empty(self, driver):
        with pytest.raises(PilotError):
            driver.resolve_hostname("")

    def test_resolve_nonexistent(self, driver):
        with pytest.raises(PilotError):
            driver.resolve_hostname("definitely-does-not-exist-xyz-12345")

    def test_resolve_very_long(self, driver):
        with pytest.raises(PilotError):
            driver.resolve_hostname("a" * 10000)


# ================================================================
# Malformed dial addresses
# ================================================================

class TestDialFuzz:
    def test_empty(self, driver):
        with pytest.raises(PilotError):
            driver.dial("")

    def test_just_colon(self, driver):
        with pytest.raises(PilotError):
            driver.dial(":")

    def test_no_port(self, driver, addr):
        with pytest.raises(PilotError):
            driver.dial(addr)

    def test_port_99999(self, driver, addr):
        with pytest.raises(PilotError):
            driver.dial(f"{addr}:99999")

    def test_negative_port(self, driver, addr):
        with pytest.raises(PilotError):
            driver.dial(f"{addr}:-1")

    def test_non_numeric_port(self, driver, addr):
        with pytest.raises(PilotError):
            driver.dial(f"{addr}:abc")

    def test_garbage(self, driver):
        with pytest.raises(PilotError):
            driver.dial("not_an_address_at_all")

    def test_unicode(self, driver):
        with pytest.raises(PilotError):
            driver.dial("🚀:1234")

    def test_very_long(self, driver):
        with pytest.raises(PilotError):
            driver.dial("a" * 10000 + ":7")


# ================================================================
# Conn read/write edge cases
# ================================================================

class TestConnFuzz:
    def test_write_empty(self, driver, addr):
        conn = driver.dial(f"{addr}:7")
        conn.write(b"")
        conn.close()

    def test_write_single_byte(self, driver, addr):
        conn = driver.dial(f"{addr}:7")
        conn.write(b"\x42")
        r = conn.read(1)
        assert len(r) == 1 and r[0] == 0x42
        conn.close()

    def test_write_null_bytes(self, driver, addr):
        conn = driver.dial(f"{addr}:7")
        conn.write(b"\x00\x00\x00")
        r = conn.read(3)
        assert len(r) == 3 and r[0] == 0x00
        conn.close()

    def test_all_byte_values(self, driver, addr):
        conn = driver.dial(f"{addr}:7")
        buf = bytes(range(256))
        conn.write(buf)
        received = b""
        while len(received) < 256:
            chunk = conn.read(256)
            if not chunk:
                break
            received += chunk
        assert len(received) == 256
        for i in range(256):
            assert received[i] == i, f"byte {i} mismatch"
        conn.close()

    def test_write_string_with_nulls(self, driver, addr):
        conn = driver.dial(f"{addr}:7")
        data = b"hello\x00world\x00"
        conn.write(data)
        r = conn.read(4096)
        assert len(r) == 12 and r[5] == 0x00
        conn.close()

    def test_read_size_zero(self, driver, addr):
        conn = driver.dial(f"{addr}:7")
        conn.write(b"data")
        r = conn.read(0)
        assert r == b""
        conn.close()

    def test_read_size_negative(self, driver, addr):
        conn = driver.dial(f"{addr}:7")
        conn.write(b"data")
        r = conn.read(-1)
        assert r == b""
        conn.close()

    def test_read_size_huge(self, driver, addr):
        conn = driver.dial(f"{addr}:7")
        conn.write(b"tiny")
        r = conn.read(10 * 1024 * 1024)
        assert len(r) == 4
        conn.close()

    def test_read_after_close(self, driver, addr):
        conn = driver.dial(f"{addr}:7")
        conn.close()
        with pytest.raises(PilotError, match="closed"):
            conn.read()

    def test_write_after_close(self, driver, addr):
        conn = driver.dial(f"{addr}:7")
        conn.close()
        with pytest.raises(PilotError, match="closed"):
            conn.write(b"x")

    def test_multiple_close(self, driver, addr):
        conn = driver.dial(f"{addr}:7")
        for _ in range(10):
            conn.close()

    def test_large_payload_64kb(self, driver, addr):
        conn = driver.dial(f"{addr}:7")
        payload = b"\x42" * 65536
        conn.write(payload)
        received = b""
        while len(received) < len(payload):
            chunk = conn.read(65536)
            if not chunk:
                break
            received += chunk
        assert len(received) == len(payload)
        assert received[0] == 0x42 and received[-1] == 0x42
        conn.close()

    def test_large_payload_128kb(self, driver, addr):
        conn = driver.dial(f"{addr}:7")
        size = 128 * 1024
        payload = bytes(i & 0xFF for i in range(size))
        conn.write(payload)
        received = b""
        while len(received) < size:
            chunk = conn.read(65536)
            if not chunk:
                break
            received += chunk
        assert len(received) == size
        assert received[0] == 0 and received[255] == 255 and received[256] == 0
        conn.close()

    def test_multiple_writes_same_conn(self, driver, addr):
        conn = driver.dial(f"{addr}:7")
        for i in range(5):
            msg = f"msg-{i}".encode()
            conn.write(msg)
            r = conn.read(4096)
            assert r == msg
        conn.close()

    def test_utf8_multibyte(self, driver, addr):
        conn = driver.dial(f"{addr}:7")
        text = "日本語テスト🚀🔥 مرحبا κόσμε".encode("utf-8")
        conn.write(text)
        r = conn.read(4096)
        assert r == text
        conn.close()

    def test_mtu_boundary_1400(self, driver, addr):
        conn = driver.dial(f"{addr}:7")
        buf = b"\x55" * 1400
        conn.write(buf)
        received = b""
        while len(received) < 1400:
            chunk = conn.read(4096)
            if not chunk:
                break
            received += chunk
        assert len(received) == 1400
        conn.close()

    def test_mtu_boundary_1401(self, driver, addr):
        conn = driver.dial(f"{addr}:7")
        buf = b"\x66" * 1401
        conn.write(buf)
        received = b""
        while len(received) < 1401:
            chunk = conn.read(4096)
            if not chunk:
                break
            received += chunk
        assert len(received) == 1401
        conn.close()


# ================================================================
# Listener edge cases
# ================================================================

class TestListenerFuzz:
    def test_port_zero(self, driver):
        ln = driver.listen(0)
        ln.close()

    def test_port_65535(self, driver):
        ln = driver.listen(65535)
        ln.close()

    def test_same_port_twice(self, driver):
        ln1 = driver.listen(6101)
        with pytest.raises(PilotError):
            driver.listen(6101)
        ln1.close()

    def test_close_then_reuse(self, driver):
        ln1 = driver.listen(6102)
        ln1.close()
        ln2 = driver.listen(6102)
        ln2.close()

    def test_close_idempotent(self, driver):
        ln = driver.listen(6103)
        for _ in range(10):
            ln.close()

    def test_accept_after_close(self, driver):
        ln = driver.listen(6104)
        ln.close()
        with pytest.raises(PilotError, match="closed"):
            ln.accept()

    def test_listen_dial_bidirectional(self, driver, addr):
        ln = driver.listen(6105)
        client = driver.dial(f"{addr}:6105")
        server = ln.accept()
        client.write(b"ping")
        assert server.read(4096) == b"ping"
        server.write(b"pong")
        assert client.read(4096) == b"pong"
        client.close()
        server.close()
        ln.close()

    def test_multiple_accepts(self, driver, addr):
        ln = driver.listen(6106)
        for i in range(3):
            c = driver.dial(f"{addr}:6106")
            s = ln.accept()
            msg = f"conn{i}".encode()
            c.write(msg)
            assert s.read(4096) == msg
            c.close()
            s.close()
        ln.close()

    def test_rapid_listen_close(self, driver):
        for _ in range(10):
            ln = driver.listen(6107)
            ln.close()


# ================================================================
# Datagram edge cases
# ================================================================

class TestDatagramFuzz:
    def test_empty_payload(self, driver, addr):
        driver.send_to(f"{addr}:8888", b"")

    def test_single_byte(self, driver, addr):
        import base64
        driver.send_to(f"{addr}:8887", b"\xff")
        dg = driver.recv_from()
        decoded = base64.b64decode(dg["data"])
        assert len(decoded) == 1 and decoded[0] == 0xFF

    def test_1kb_payload(self, driver, addr):
        import base64
        driver.send_to(f"{addr}:8886", b"\xaa" * 1024)
        dg = driver.recv_from()
        decoded = base64.b64decode(dg["data"])
        assert len(decoded) == 1024

    def test_malformed_address(self, driver):
        with pytest.raises(PilotError):
            driver.send_to("garbage:addr", b"test")

    def test_empty_address(self, driver):
        with pytest.raises(PilotError):
            driver.send_to("", b"test")


# ================================================================
# Tags edge cases
# ================================================================

class TestTagsFuzz:
    def test_empty(self, driver):
        driver.set_tags([])

    def test_single(self, driver):
        driver.set_tags(["one"])
        driver.set_tags([])

    def test_many_tags(self, driver):
        with pytest.raises(PilotError):
            driver.set_tags([f"tag-{i}" for i in range(100)])

    def test_very_long_tag(self, driver):
        with pytest.raises(PilotError):
            driver.set_tags(["a" * 10000])

    def test_unicode_tags(self, driver):
        # May or may not work depending on tag limit
        try:
            driver.set_tags(["🚀", "日本語"])
            driver.set_tags([])
        except PilotError:
            pass

    def test_empty_string_tag(self, driver):
        try:
            driver.set_tags(["", "", ""])
            driver.set_tags([])
        except PilotError:
            pass

    def test_duplicate_tags(self, driver):
        driver.set_tags(["dup", "dup", "dup"])
        driver.set_tags([])


# ================================================================
# Webhook edge cases
# ================================================================

class TestWebhookFuzz:
    def test_not_a_url(self, driver):
        driver.set_webhook("not a url")
        driver.set_webhook("")

    def test_very_long_url(self, driver):
        driver.set_webhook("https://example.com/" + "a" * 10000)
        driver.set_webhook("")

    def test_javascript_protocol(self, driver):
        driver.set_webhook("javascript:alert(1)")
        driver.set_webhook("")

    def test_file_protocol(self, driver):
        driver.set_webhook("file:///etc/passwd")
        driver.set_webhook("")


# ================================================================
# Visibility toggle
# ================================================================

class TestVisibilityFuzz:
    def test_rapid_toggle(self, driver):
        for i in range(10):
            driver.set_visibility(i % 2 == 0)
        driver.set_visibility(True)


# ================================================================
# Handshake edge cases
# ================================================================

class TestHandshakeFuzz:
    def test_node_zero(self, driver):
        with pytest.raises(PilotError):
            driver.handshake(0, "test")

    def test_node_max(self, driver):
        with pytest.raises(PilotError):
            driver.handshake(4294967295, "test")

    def test_long_justification(self, driver):
        with pytest.raises(PilotError):
            driver.handshake(99999, "a" * 10000)

    def test_empty_justification(self, driver):
        with pytest.raises(PilotError):
            driver.handshake(99999, "")

    def test_approve_nonexistent(self, driver):
        driver.approve_handshake(99999)

    def test_reject_nonexistent(self, driver):
        driver.reject_handshake(99999, "no")

    def test_revoke_nonexistent(self, driver):
        try:
            driver.revoke_trust(99999)
        except PilotError:
            pass


# ================================================================
# Use-after-close
# ================================================================

class TestUseAfterClose:
    def test_info_after_close(self):
        d = Driver(SOCKET)
        d.close()
        with pytest.raises(PilotError):
            d.info()

    def test_dial_after_close(self):
        d = Driver(SOCKET)
        d.close()
        with pytest.raises(PilotError):
            d.dial("0:0000.0000.0001:7")

    def test_listen_after_close(self):
        d = Driver(SOCKET)
        d.close()
        with pytest.raises(PilotError):
            d.listen(7777)

    def test_send_to_after_close(self):
        d = Driver(SOCKET)
        d.close()
        with pytest.raises(PilotError):
            d.send_to("0:0000.0000.0001:8000", b"test")

    def test_set_hostname_after_close(self):
        d = Driver(SOCKET)
        d.close()
        with pytest.raises(PilotError):
            d.set_hostname("test")


# ================================================================
# sendMessage edge cases
# ================================================================

class TestSendMessageFuzz:
    def test_empty_text(self, driver, addr):
        driver.send_message(addr, b"")

    def test_large_text_100kb(self, driver, addr):
        driver.send_message(addr, b"X" * (100 * 1024))

    def test_binary_null_bytes(self, driver, addr):
        driver.send_message(addr, b"\x00\x00\x00\x00\x00", msg_type="binary")

    def test_json_nested(self, driver, addr):
        import json
        deep = json.dumps({"a": {"b": {"c": {"d": {"e": "deep"}}}}}).encode()
        driver.send_message(addr, deep, msg_type="json")


# ================================================================
# Stress tests
# ================================================================

class TestStress:
    def test_rapid_echo_20(self, driver, addr):
        for i in range(20):
            conn = driver.dial(f"{addr}:7")
            msg = f"stress-{i}".encode()
            conn.write(msg)
            assert conn.read(4096) == msg
            conn.close()

    def test_rapid_conn_open_close_20(self, driver, addr):
        for _ in range(20):
            c = driver.dial(f"{addr}:7")
            c.close()

    def test_pipeline_10_writes(self, driver, addr):
        conn = driver.dial(f"{addr}:7")
        messages = [f"msg-{i:03d}".encode() for i in range(10)]
        for msg in messages:
            conn.write(msg)
        expected = b"".join(messages)
        received = b""
        while len(received) < len(expected):
            chunk = conn.read(4096)
            if not chunk:
                break
            received += chunk
        assert received == expected
        conn.close()
