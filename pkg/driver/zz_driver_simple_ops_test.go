// SPDX-License-Identifier: AGPL-3.0-or-later

package driver

import (
	"testing"
)

// TestDriverClose covers the trivial Close() forwarder.
func TestDriverClose(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()

	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := drv.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// TestDriverBroadcast covers the happy-path Broadcast (network + port +
// admin token + data → cmdBroadcastOK).
func TestDriverBroadcast(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()

	d.onCmd(cmdBroadcast, func(frame []byte) [][]byte {
		return [][]byte{{cmdBroadcastOK}}
	})

	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer drv.Close()

	if err := drv.Broadcast(1, 8080, []byte("hello"), "admin-token"); err != nil {
		t.Fatalf("Broadcast: %v", err)
	}
}

// TestConnClose covers Conn.Close (cmdClose fire-and-forget) and its
// idempotency — second Close is a no-op.
func TestConnClose(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()

	// Dial to get a Conn back.
	d.onCmd(cmdDial, func(frame []byte) [][]byte {
		resp := make([]byte, 5)
		resp[0] = cmdDialOK
		resp[1] = 0x00
		resp[2] = 0x00
		resp[3] = 0x00
		resp[4] = 0x42
		return [][]byte{resp}
	})

	drv, _ := Connect(d.path)
	defer drv.Close()

	conn, err := drv.Dial("0:0000.0000.0001:80")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	if err := conn.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	// Second Close is idempotent.
	if err := conn.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// TestDriverWaitForTrust covers the handshake-wait JSON-RPC.
func TestDriverWaitForTrust(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()

	d.onCmd(cmdHandshake, func(frame []byte) [][]byte {
		// Verify the sub-command byte (0x07 = subHandshakeWait).
		if len(frame) < 2 || frame[1] != subHandshakeWait {
			return [][]byte{{cmdError, 'b', 'a', 'd'}}
		}
		body := []byte(`{"trusted":true}`)
		return [][]byte{append([]byte{cmdHandshakeOK}, body...)}
	})

	drv, _ := Connect(d.path)
	defer drv.Close()

	result, err := drv.WaitForTrust(0xCAFE, 5000)
	if err != nil {
		t.Fatalf("WaitForTrust: %v", err)
	}
	if result == nil {
		t.Errorf("result is nil")
	}
}

// TestDriverRotateKey covers RotateKey's JSON-RPC roundtrip.
func TestDriverRotateKey(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()

	d.onCmd(cmdRotateKey, func(frame []byte) [][]byte {
		// jsonRPC expects [cmdRotateKeyOK][JSON body]
		body := []byte(`{"old_node_id":1,"new_node_id":2}`)
		resp := append([]byte{cmdRotateKeyOK}, body...)
		return [][]byte{resp}
	})

	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer drv.Close()

	result, err := drv.RotateKey()
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if result == nil {
		t.Errorf("RotateKey result is nil")
	}
}
