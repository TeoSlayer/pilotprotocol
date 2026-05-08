// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"sync"
	"testing"
)

// Iter-102 originally covered task-file lifecycle helpers (cancel/expire,
// monitor loops) plus ipcConn.trackConn. The task tests moved to
// plugins/tasks/lifecycle_test.go as part of T3.2 (extraction of the
// task plugin). The ipcConn tests stay here — they exercise daemon
// internals.

// --- ipcConn.trackConn: mutex-protected append ---

func TestIpcConnTrackConnAppendsAllIDs(t *testing.T) {
	t.Parallel()
	c := &ipcConn{}
	for i := uint32(0); i < 5; i++ {
		c.trackConn(i * 100)
	}
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if len(c.conns) != 5 {
		t.Fatalf("conns len = %d, want 5", len(c.conns))
	}
	for i, want := range []uint32{0, 100, 200, 300, 400} {
		if c.conns[i] != want {
			t.Fatalf("conns[%d] = %d, want %d", i, c.conns[i], want)
		}
	}
}

func TestIpcConnTrackConnConcurrentSafe(t *testing.T) {
	t.Parallel()
	c := &ipcConn{}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id uint32) {
			defer wg.Done()
			c.trackConn(id)
		}(uint32(i))
	}
	wg.Wait()

	c.rmu.Lock()
	defer c.rmu.Unlock()
	if len(c.conns) != 50 {
		t.Fatalf("conns len after 50 concurrent appends = %d, want 50", len(c.conns))
	}
}
