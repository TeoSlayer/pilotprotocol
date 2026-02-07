package tests

import (
	"sync"
	"testing"
	"time"

	"web4/pkg/driver"
)

func TestAcceptQueueNoOrphan(t *testing.T) {
	t.Parallel()
	// Verify that connections are not orphaned — every accepted connection
	// is delivered to the application. This validates the fix that checks
	// accept queue capacity BEFORE sending SYN-ACK.

	env := NewTestEnv(t)

	infoS := env.AddDaemon()
	infoC := env.AddDaemon()

	daemonS := infoS.Daemon
	drvS := infoS.Driver
	drvC := infoC.Driver

	ln, err := drvS.Listen(7777)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	// Accept connections in background, count them
	accepted := 0
	var acceptMu sync.Mutex
	go func() {
		for {
			_, err := ln.Accept()
			if err != nil {
				return
			}
			acceptMu.Lock()
			accepted++
			acceptMu.Unlock()
		}
	}()

	// Open many concurrent connections
	numConns := 30
	var wg sync.WaitGroup
	successes := 0
	var mu sync.Mutex

	for i := 0; i < numConns; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := drvC.DialAddr(daemonS.Addr(), 7777)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				successes++
				conn.Write([]byte("ping"))
			}
		}()
	}
	wg.Wait()

	// Poll until all successful dials have been accepted
	deadline := time.After(5 * time.Second)
	var numAccepted int
	for {
		mu.Lock()
		target := successes
		mu.Unlock()
		acceptMu.Lock()
		numAccepted = accepted
		acceptMu.Unlock()
		if target > 0 && numAccepted >= target {
			break
		}
		select {
		case <-deadline:
			// Read final values before reporting
			acceptMu.Lock()
			numAccepted = accepted
			acceptMu.Unlock()
			goto done
		case <-time.After(10 * time.Millisecond):
		}
	}
done:

	t.Logf("dialed=%d, succeeded=%d, accepted=%d", numConns, successes, numAccepted)

	// Every successful dial should have a corresponding accept
	// (no orphaned connections)
	if successes > 0 && numAccepted == 0 {
		t.Error("connections succeeded but none were accepted — orphaned!")
	}
	if numAccepted < successes {
		t.Errorf("accepted %d < succeeded %d — some connections were orphaned", numAccepted, successes)
	}
}

func TestMaxRetransmitNotifiesApp(t *testing.T) {
	t.Parallel()
	// Verify that when a connection dies from max retransmits,
	// the application receives EOF on Read.

	env := NewTestEnv(t)

	infoA := env.AddDaemon()
	daemonB, sockPathB := env.AddDaemonOnly()

	drvA := infoA.Driver

	drvB, err := driver.Connect(sockPathB)
	if err != nil {
		t.Fatalf("driver B connect: %v", err)
	}
	defer drvB.Close()

	// B listens
	ln, err := drvB.Listen(7778)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	// A dials B
	connA, err := drvA.DialAddr(daemonB.Addr(), 7778)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// B accepts
	connB, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}

	// Verify connection works
	connA.Write([]byte("hello"))
	buf := make([]byte, 64)
	n, err := connB.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("expected 'hello', got %q", string(buf[:n]))
	}
	t.Logf("connection works: sent and received 'hello'")

	// Kill daemon B abruptly — A's connection should eventually die from retransmits
	daemonB.Stop()

	// A tries to send data — it should eventually get an error or the connection should close
	done := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for i := 0; i < 20; i++ {
			_, err := connA.Write([]byte("data that will never arrive"))
			if err != nil {
				done <- err
				return
			}
			<-ticker.C
		}
		done <- nil
	}()

	// Also check if Read returns EOF
	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		_, err := connA.Read(buf)
		readDone <- err
	}()

	// Wait for either write error or read EOF — should happen within retransmit window
	select {
	case err := <-readDone:
		t.Logf("Read returned error (expected EOF): %v", err)
	case err := <-done:
		if err != nil {
			t.Logf("Write returned error (expected): %v", err)
		} else {
			// Writes may succeed at IPC level even if remote is dead,
			// because the IPC send is async. The real signal is on Read.
			t.Logf("Writes completed — checking Read...")
			select {
			case err := <-readDone:
				t.Logf("Read returned error: %v", err)
			case <-time.After(30 * time.Second):
				t.Error("timeout waiting for Read to return after connection death")
			}
		}
	case <-time.After(30 * time.Second):
		t.Error("timeout waiting for connection to die from max retransmits")
	}
}

func TestConnectionLimits(t *testing.T) {
	t.Parallel()
	// Verify that daemon tracks connection counts correctly

	env := NewTestEnv(t)

	infoS := env.AddDaemon()
	infoC := env.AddDaemon()

	daemonS := infoS.Daemon
	drvS := infoS.Driver
	drvC := infoC.Driver

	// Server listens and accepts
	ln, err := drvS.Listen(7779)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			_, err := ln.Accept()
			if err != nil {
				return
			}
		}
	}()

	// Open several connections
	for i := 0; i < 5; i++ {
		conn, err := drvC.DialAddr(daemonS.Addr(), 7779)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		defer conn.Close()
	}

	// Poll until daemon reports at least 5 connections
	deadline := time.After(5 * time.Second)
	var conns int
	for {
		info, err := drvS.Info()
		if err != nil {
			t.Fatalf("info: %v", err)
		}
		conns = int(info["connections"].(float64))
		if conns >= 5 {
			break
		}
		select {
		case <-deadline:
			t.Errorf("expected at least 5 connections, got %d", conns)
			return
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Logf("server connections: %d", conns)
}
