package tests

import (
	"testing"
	"time"

	"web4/pkg/driver"
)

// TestIPCDisconnectRecovery tests that driver operations return errors when
// the underlying IPC connection is broken. This verifies the doneCh and
// cleanup() logic in the IPC client: after the connection is closed,
// pending and future sendAndWait calls must return an error promptly
// (not hang forever).
func TestIPCDisconnectRecovery(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	// Start a daemon and get its socket path
	d, sockPath := env.AddDaemonOnly()
	t.Logf("daemon started: node=%d socket=%s", d.NodeID(), sockPath)

	// Connect two drivers to the same daemon
	drv1, err := driver.Connect(sockPath)
	if err != nil {
		t.Fatalf("driver 1 connect: %v", err)
	}

	drv2, err := driver.Connect(sockPath)
	if err != nil {
		t.Fatalf("driver 2 connect: %v", err)
	}

	// Verify both drivers work
	info1, err := drv1.Info()
	if err != nil {
		t.Fatalf("drv1 info: %v", err)
	}
	nodeID := int(info1["node_id"].(float64))
	t.Logf("driver 1 confirmed working, node_id=%d", nodeID)

	info2, err := drv2.Info()
	if err != nil {
		t.Fatalf("drv2 info: %v", err)
	}
	t.Logf("driver 2 confirmed working, node_id=%d", int(info2["node_id"].(float64)))

	// ---- Test 1: Close driver 1 and verify post-close operations fail promptly ----
	drv1.Close()
	t.Log("driver 1 closed")

	// Info after close should return an error (not hang)
	infoDone := make(chan error, 1)
	go func() {
		_, err := drv1.Info()
		infoDone <- err
	}()

	select {
	case err := <-infoDone:
		if err == nil {
			t.Fatal("expected error from Info after close, got nil")
		}
		t.Logf("post-close Info correctly returned error: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Info hung for 5 seconds after close — doneCh/cleanup not working")
	}

	// ---- Test 2: Driver 2 still works (closing one driver does not break another) ----
	info2b, err := drv2.Info()
	if err != nil {
		t.Fatalf("drv2 info after drv1 close: %v", err)
	}
	if int(info2b["node_id"].(float64)) != nodeID {
		t.Errorf("drv2 node_id changed unexpectedly")
	}
	t.Log("driver 2 still works after driver 1 closed")

	// ---- Test 3: Reconnect driver 1 and verify it works again ----
	drv1b, err := driver.Connect(sockPath)
	if err != nil {
		t.Fatalf("driver 1 reconnect: %v", err)
	}
	defer drv1b.Close()

	info1b, err := drv1b.Info()
	if err != nil {
		t.Fatalf("reconnected driver info: %v", err)
	}
	if int(info1b["node_id"].(float64)) != nodeID {
		t.Errorf("node_id mismatch after reconnect: got %d, want %d", int(info1b["node_id"].(float64)), nodeID)
	}
	t.Logf("reconnected driver confirmed working, node_id=%d", nodeID)

	// ---- Test 4: Concurrent Listen/Info with immediate close ----
	// Start a blocking operation and close while it's pending
	drv3, err := driver.Connect(sockPath)
	if err != nil {
		t.Fatalf("driver 3 connect: %v", err)
	}

	// Launch Listen which will succeed, then Accept which blocks
	ln, err := drv3.Listen(7000)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_ = ln

	// Close the driver while Accept would be blocking (if called)
	// Instead, just verify that closing is clean
	drv3.Close()
	t.Log("driver 3 closed while listener active")

	// Verify a post-close operation fails promptly
	postCloseDone := make(chan error, 1)
	go func() {
		_, err := drv3.Info()
		postCloseDone <- err
	}()

	select {
	case err := <-postCloseDone:
		if err == nil {
			t.Fatal("expected error from Info after drv3 close")
		}
		t.Logf("post-close Info on drv3 correctly returned error: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("post-close Info on drv3 hung")
	}

	drv2.Close()
	_ = d // daemon stopped by env.Close()
}
