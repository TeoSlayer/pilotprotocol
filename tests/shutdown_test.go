package tests

import (
	"fmt"
	"testing"
	"time"

	"web4/pkg/driver"
	"web4/pkg/registry"
)

func TestGracefulShutdown(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	// Start daemon A (server) — AddDaemonOnly since we stop it mid-test
	daemonA, sockPathA := env.AddDaemonOnly()

	// Start daemon B (client)
	infoB := env.AddDaemon()
	daemonB := infoB.Daemon

	t.Logf("daemon A: node=%d, daemon B: node=%d", daemonA.NodeID(), daemonB.NodeID())

	// Connect drivers and establish a connection
	drvA, err := driver.Connect(sockPathA)
	if err != nil {
		t.Fatalf("driver A connect: %v", err)
	}
	defer drvA.Close()

	ln, err := drvA.Listen(1000)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	// Accept connections in background
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				buf := make([]byte, 1024)
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

	drvB := infoB.Driver

	conn, err := drvB.DialAddr(daemonA.Addr(), 1000)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Verify connection works
	conn.Write([]byte("before-shutdown"))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read before shutdown: %v", err)
	}
	t.Logf("received before shutdown: %q", string(buf[:n]))

	// Verify node exists in registry before shutdown
	rc, _ := registry.Dial(env.RegistryAddr)
	defer rc.Close()
	_, err = rc.Lookup(daemonA.NodeID())
	if err != nil {
		t.Fatalf("lookup before shutdown should succeed: %v", err)
	}
	t.Log("node A found in registry before shutdown")

	// Graceful shutdown of daemon A
	t.Log("stopping daemon A...")
	daemonA.Stop()

	// Poll until node is deregistered from the registry
	deadline := time.After(5 * time.Second)
	for {
		_, lookupErr := rc.Lookup(daemonA.NodeID())
		if lookupErr != nil {
			t.Logf("node A correctly deregistered: %v", lookupErr)
			break
		}
		select {
		case <-deadline:
			t.Error("lookup after shutdown should fail — node should be deregistered")
			goto shutdownDone
		case <-time.After(10 * time.Millisecond):
		}
	}
shutdownDone:

	t.Log("graceful shutdown test passed")
}

func TestConnectionCleanupOnShutdown(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	infoA := env.AddDaemon()
	infoB := env.AddDaemon()

	daemonA := infoA.Daemon
	drvA := infoA.Driver
	drvB := infoB.Driver

	// Set up server on A
	ln, err := drvA.Listen(1000)
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
				buf := make([]byte, 1024)
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

	// Open multiple connections from B
	const numConns = 5
	conns := make([]*driver.Conn, numConns)
	for i := 0; i < numConns; i++ {
		c, err := drvB.DialAddr(daemonA.Addr(), 1000)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conns[i] = c

		// Verify each connection works
		msg := fmt.Sprintf("conn-%d", i)
		c.Write([]byte(msg))
		buf := make([]byte, 1024)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if string(buf[:n]) != msg {
			t.Errorf("conn %d: got %q, want %q", i, string(buf[:n]), msg)
		}
	}

	// Check connection count via Info
	info, err := drvB.Info()
	if err != nil {
		t.Fatalf("info: %v", err)
	}
	connCount := int(info["connections"].(float64))
	if connCount != numConns {
		t.Errorf("expected %d connections, got %d", numConns, connCount)
	}
	t.Logf("verified %d active connections before cleanup", connCount)

	// Close all connections
	for _, c := range conns {
		c.Close()
	}

	// Poll until all connections are cleaned up
	deadline := time.After(5 * time.Second)
	for {
		info, err = drvB.Info()
		if err != nil {
			t.Fatalf("info after close: %v", err)
		}
		connCount = int(info["connections"].(float64))
		if connCount == 0 {
			break
		}
		select {
		case <-deadline:
			t.Errorf("expected 0 connections after cleanup, got %d", connCount)
			return
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Logf("all connections cleaned up: %d remaining", connCount)
}
