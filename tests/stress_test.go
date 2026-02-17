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

	// Echo server on A
	ln, err := a.Driver.Listen(1000)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
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

	const numConns = 20
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

			conn, err := d.DialAddr(a.Daemon.Addr(), 1000)
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
