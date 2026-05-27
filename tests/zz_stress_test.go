// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build nightly

package tests

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/driver"
)

func TestStressConcurrentConnections(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon()
	b := env.AddDaemon()

	// Each goroutine dials its own port so dials aren't deduplicated by
	// DialConnectionContext, which keys on (peerNode, dstPort).
	const numConns = 10
	const basePort = 3000 // avoid ports used by daemon services (1001-1003)

	startEchoListener := func(ln *driver.Listener) {
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer conn.Close()
					buf := make([]byte, 65535)
					for {
						n, err := conn.Read(buf)
						if err != nil {
							return
						}
						conn.Write(buf[:n])
					}
				}()
			}
		}()
	}

	for i := 0; i < numConns; i++ {
		ln, err := a.Driver.Listen(uint16(basePort + i))
		if err != nil {
			t.Fatalf("listen port %d: %v", basePort+i, err)
		}
		startEchoListener(ln)
	}

	var wg sync.WaitGroup
	var successes atomic.Int32
	var failures atomic.Int32

	for i := 0; i < numConns; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			d, err := driver.Connect(b.SocketPath)
			if err != nil {
				t.Logf("conn %d: driver connect failed: %v", idx, err)
				failures.Add(1)
				return
			}
			defer d.Close()

			conn, err := d.DialAddr(a.Daemon.Addr(), uint16(basePort+idx))
			if err != nil {
				t.Logf("conn %d: dial failed: %v", idx, err)
				failures.Add(1)
				return
			}
			defer conn.Close()

			msg := fmt.Sprintf("stress-test-%d", idx)
			if _, err := conn.Write([]byte(msg)); err != nil {
				t.Logf("conn %d: write failed: %v", idx, err)
				failures.Add(1)
				return
			}

			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			if err != nil {
				t.Logf("conn %d: read failed: %v", idx, err)
				failures.Add(1)
				return
			}

			reply := string(buf[:n])
			if reply != msg {
				t.Logf("conn %d: expected %q, got %q", idx, msg, reply)
				failures.Add(1)
				return
			}
			successes.Add(1)
		}(i)
	}

	wg.Wait()
	t.Logf("results: %d/%d succeeded, %d failed", successes.Load(), numConns, failures.Load())

	if successes.Load() < numConns {
		t.Errorf("expected all %d connections to succeed, got %d", numConns, successes.Load())
	}
}
