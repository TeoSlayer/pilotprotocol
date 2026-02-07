package tests

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"testing"
	"time"

	"web4/pkg/registry"
)

func TestEndToEnd(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	// Start daemon A
	a := env.AddDaemon()
	t.Logf("daemon A: node=%d addr=%s", a.Daemon.NodeID(), a.Daemon.Addr())

	// Start daemon B
	b := env.AddDaemon()
	t.Logf("daemon B: node=%d addr=%s", b.Daemon.NodeID(), b.Daemon.Addr())

	// Listen on port 1000 via driver A
	ln, err := a.Driver.Listen(1000)
	if err != nil {
		t.Fatalf("driver A listen: %v", err)
	}
	t.Log("driver A: listening on port 1000")

	// Server goroutine: accept and echo
	serverReady := make(chan struct{})
	serverDone := make(chan string, 1)
	go func() {
		close(serverReady)
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- fmt.Sprintf("accept error: %v", err)
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			serverDone <- fmt.Sprintf("read error: %v", err)
			return
		}

		received := string(buf[:n])
		log.Printf("server received: %q", received)

		conn.Write([]byte("echo:" + received))
		serverDone <- received
	}()
	<-serverReady

	// Driver B dials daemon A on port 1000
	targetAddr := fmt.Sprintf("%s:1000", a.Daemon.Addr().String())
	t.Logf("driver B: dialing %s", targetAddr)

	conn, err := b.Driver.Dial(targetAddr)
	if err != nil {
		t.Fatalf("driver B dial: %v", err)
	}
	defer conn.Close()

	t.Log("driver B: connected!")

	_, err = conn.Write([]byte("hello pilot"))
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	response := string(buf[:n])
	t.Logf("client received: %q", response)

	if response != "echo:hello pilot" {
		t.Errorf("expected %q, got %q", "echo:hello pilot", response)
	}

	select {
	case received := <-serverDone:
		if received != "hello pilot" {
			t.Errorf("server received %q, want %q", received, "hello pilot")
		}
	case <-time.After(5 * time.Second):
		t.Error("server timed out")
	}

	rc, _ := registry.Dial(env.RegistryAddr)
	defer rc.Close()

	nets, _ := rc.ListNetworks()
	t.Logf("networks: %v", nets)
}

func TestHTTPOverPilot(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon()
	b := env.AddDaemon()

	// Start HTTP server on daemon A port 80
	ln, err := a.Driver.Listen(80)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`)
	})
	go http.Serve(ln, mux)

	// Connect from daemon B and send HTTP request
	conn, err := b.Driver.DialAddr(a.Daemon.Addr(), 80)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	t.Log("connected to port 80")

	req := "GET /status HTTP/1.0\r\nHost: test\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Log("sent HTTP request")

	// Read response
	var resp []byte
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			resp = append(resp, buf[:n]...)
		}
		if err == io.EOF || err != nil {
			break
		}
	}

	t.Logf("HTTP response:\n%s", string(resp))

	if len(resp) == 0 {
		t.Fatal("got empty response")
	}
}
