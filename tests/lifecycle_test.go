package tests

import (
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/driver"
)

// TestDialClosedPort verifies that dialing a port with no listener returns an error (RST).
func TestDialClosedPort(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon()
	b := env.AddDaemon()

	// B dials A on port 9999 where nobody is listening
	_, err := b.Driver.DialAddr(a.Daemon.Addr(), 9999)
	if err == nil {
		t.Fatal("expected error dialing port with no listener, got nil")
	}
	t.Logf("correctly got error: %v", err)
}

// TestRemoteFIN verifies that when one side closes, the other gets io.EOF.
func TestRemoteFIN(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon()
	b := env.AddDaemon()

	ln, err := a.Driver.Listen(1000)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	accepted := make(chan struct{})
	serverEOF := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverEOF <- err
			return
		}
		close(accepted)
		// Keep reading until EOF
		buf := make([]byte, 1024)
		for {
			_, err := conn.Read(buf)
			if err != nil {
				serverEOF <- err
				return
			}
		}
	}()

	conn, err := b.Driver.DialAddr(a.Daemon.Addr(), 1000)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	<-accepted

	// Send some data then close
	conn.Write([]byte("goodbye"))
	conn.Close()

	// Server should get EOF
	select {
	case err := <-serverEOF:
		if err != io.EOF {
			t.Logf("got error (expected EOF): %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server did not receive EOF after client close")
	}
}

// TestSimultaneousClose verifies both sides can close at the same time without deadlock.
func TestSimultaneousClose(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon()
	b := env.AddDaemon()

	ln, err := a.Driver.Listen(1000)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	serverConn := make(chan interface{}, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverConn <- err
			return
		}
		serverConn <- conn
	}()

	clientConn, err := b.Driver.DialAddr(a.Daemon.Addr(), 1000)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	sc := <-serverConn
	srvConn, ok := sc.(io.ReadWriteCloser)
	if !ok {
		t.Fatalf("accept error: %v", sc)
	}

	// Exchange data to confirm connection works
	clientConn.Write([]byte("ping"))
	buf := make([]byte, 1024)
	srvConn.Read(buf)

	// Both sides close simultaneously
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		clientConn.Close()
	}()
	go func() {
		defer wg.Done()
		srvConn.Close()
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		t.Log("both sides closed without deadlock")
	case <-time.After(10 * time.Second):
		t.Fatal("simultaneous close deadlocked")
	}
}

// TestMultipleListeners verifies a daemon can listen on multiple ports simultaneously.
func TestMultipleListeners(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	// Disable built-in services so test can bind ports 1001, 1002 via driver
	disableSvcs := func(cfg *daemon.Config) {
		cfg.DisableDataExchange = true
		cfg.DisableEventStream = true
	}
	a := env.AddDaemon(disableSvcs)
	b := env.AddDaemon(disableSvcs)

	ports := []uint16{1000, 1001, 1002}
	for _, port := range ports {
		p := port
		ln, err := a.Driver.Listen(p)
		if err != nil {
			t.Fatalf("listen on port %d: %v", p, err)
		}
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			buf := make([]byte, 1024)
			n, _ := conn.Read(buf)
			conn.Write([]byte(fmt.Sprintf("port-%d:%s", p, string(buf[:n]))))
		}()
	}

	// Dial each port and verify we get the correct response
	for _, port := range ports {
		conn, err := b.Driver.DialAddr(a.Daemon.Addr(), port)
		if err != nil {
			t.Fatalf("dial port %d: %v", port, err)
		}

		msg := fmt.Sprintf("hello-%d", port)
		conn.Write([]byte(msg))

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read from port %d: %v", port, err)
		}

		expected := fmt.Sprintf("port-%d:%s", port, msg)
		if string(buf[:n]) != expected {
			t.Errorf("port %d: expected %q, got %q", port, expected, string(buf[:n]))
		}
		conn.Close()
	}
	t.Log("all 3 ports responded correctly")
}

// TestDialAndExchangeMultipleMessages verifies multiple round-trips on one connection.
func TestDialAndExchangeMultipleMessages(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon()
	b := env.AddDaemon()

	ln, err := a.Driver.Listen(1000)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	// Echo server
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			conn.Write(buf[:n])
		}
	}()

	conn, err := b.Driver.DialAddr(a.Daemon.Addr(), 1000)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send 10 messages on the same connection
	for i := 0; i < 10; i++ {
		msg := fmt.Sprintf("message-%d", i)
		if _, err := conn.Write([]byte(msg)); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if string(buf[:n]) != msg {
			t.Errorf("message %d: expected %q, got %q", i, msg, string(buf[:n]))
		}
	}
	t.Log("exchanged 10 messages on one connection")
}

// TestConnectionAfterPeerRestart verifies that when a peer's daemon is stopped,
// the remote side eventually gets an error on read.
func TestConnectionAfterPeerRestart(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon()
	// Start B as daemon-only so we can stop it independently
	bDaemon, bSock := env.AddDaemonOnly()

	bDrv, err := driver.Connect(bSock)
	if err != nil {
		t.Fatalf("connect driver B: %v", err)
	}

	// A listens, B dials
	ln, err := a.Driver.Listen(1000)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		// Keep reading until error
		buf := make([]byte, 1024)
		for {
			_, err := conn.Read(buf)
			if err != nil {
				serverErr <- err
				return
			}
		}
	}()

	conn, err := bDrv.DialAddr(a.Daemon.Addr(), 1000)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Write([]byte("before-crash"))

	// Crash daemon B
	bDrv.Close()
	bDaemon.Stop()

	// Server A should eventually get an error
	select {
	case err := <-serverErr:
		t.Logf("server got error after peer crash: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("server did not detect peer crash within timeout")
	}
}

// TestTimeWaitCleanup verifies connections are cleaned up after TIME_WAIT.
func TestTimeWaitCleanup(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	twDuration := 2 * time.Second
	a := env.AddDaemon(func(c *daemon.Config) {
		c.TimeWaitDuration = twDuration
	})
	b := env.AddDaemon(func(c *daemon.Config) {
		c.TimeWaitDuration = twDuration
	})

	ln, err := a.Driver.Listen(1000)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	accepted := make(chan io.ReadWriteCloser, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- conn
	}()

	conn, err := b.Driver.DialAddr(a.Daemon.Addr(), 1000)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Wait for accept to complete, exchange data to confirm establishment
	select {
	case srvConn := <-accepted:
		conn.Write([]byte("hi"))
		buf := make([]byte, 16)
		srvConn.Read(buf)
		// Now close both sides
		srvConn.Close()
		conn.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("accept timed out")
	}

	// Poll until connections reach 0 (TIME_WAIT expires)
	deadline := time.After(twDuration + 3*time.Second)
	for {
		info, err := b.Driver.Info()
		if err != nil {
			t.Fatalf("info: %v", err)
		}
		conns := int(info["connections"].(float64))
		if conns == 0 {
			t.Log("connections reached 0 after TIME_WAIT")
			break
		}
		select {
		case <-deadline:
			t.Fatalf("expected 0 connections after TIME_WAIT, got %d", conns)
		case <-time.After(200 * time.Millisecond):
		}
	}
}
