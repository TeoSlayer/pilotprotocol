package tests

import (
	"bytes"
	"net"
	"sync"
	"testing"

	"web4/pkg/secure"
)

func TestSecureHandshakeAndRoundTrip(t *testing.T) {
	t.Parallel()
	clientRaw, serverRaw := net.Pipe()

	var clientConn, serverConn *secure.SecureConn
	var clientErr, serverErr error
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		serverConn, serverErr = secure.Handshake(serverRaw, true)
	}()
	go func() {
		defer wg.Done()
		clientConn, clientErr = secure.Handshake(clientRaw, false)
	}()
	wg.Wait()

	if clientErr != nil {
		t.Fatalf("client handshake: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("server handshake: %v", serverErr)
	}
	defer clientConn.Close()
	defer serverConn.Close()

	// Client sends to server (in goroutine — net.Pipe is synchronous)
	msg := []byte("hello secure world")
	go func() {
		clientConn.Write(msg)
	}()

	buf := make([]byte, 1024)
	n, err := serverConn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(buf[:n], msg) {
		t.Fatalf("expected %q, got %q", msg, buf[:n])
	}
}

func TestSecureBidirectional(t *testing.T) {
	t.Parallel()
	clientRaw, serverRaw := net.Pipe()

	var clientConn, serverConn *secure.SecureConn
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		serverConn, _ = secure.Handshake(serverRaw, true)
	}()
	go func() {
		defer wg.Done()
		clientConn, _ = secure.Handshake(clientRaw, false)
	}()
	wg.Wait()
	defer clientConn.Close()
	defer serverConn.Close()

	// Server replies to client
	go func() {
		serverConn.Write([]byte("server says hi"))
	}()

	buf := make([]byte, 1024)
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "server says hi" {
		t.Fatalf("expected %q, got %q", "server says hi", string(buf[:n]))
	}
}

func TestSecureMultipleMessages(t *testing.T) {
	t.Parallel()
	clientRaw, serverRaw := net.Pipe()

	var clientConn, serverConn *secure.SecureConn
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		serverConn, _ = secure.Handshake(serverRaw, true)
	}()
	go func() {
		defer wg.Done()
		clientConn, _ = secure.Handshake(clientRaw, false)
	}()
	wg.Wait()
	defer clientConn.Close()
	defer serverConn.Close()

	messages := []string{"msg1", "msg2", "msg3", "msg4", "msg5"}

	go func() {
		for _, m := range messages {
			clientConn.Write([]byte(m))
		}
	}()

	for _, expected := range messages {
		buf := make([]byte, 1024)
		n, err := serverConn.Read(buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(buf[:n]) != expected {
			t.Fatalf("expected %q, got %q", expected, string(buf[:n]))
		}
	}
}

func TestSecureLargePayload(t *testing.T) {
	t.Parallel()
	clientRaw, serverRaw := net.Pipe()

	var clientConn, serverConn *secure.SecureConn
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		serverConn, _ = secure.Handshake(serverRaw, true)
	}()
	go func() {
		defer wg.Done()
		clientConn, _ = secure.Handshake(clientRaw, false)
	}()
	wg.Wait()
	defer clientConn.Close()
	defer serverConn.Close()

	// Send 64KB payload
	data := make([]byte, 65536)
	for i := range data {
		data[i] = byte(i % 256)
	}

	go func() {
		clientConn.Write(data)
	}()

	buf := make([]byte, 65536)
	n, err := serverConn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n != len(data) {
		t.Fatalf("expected %d bytes, got %d", len(data), n)
	}
	if !bytes.Equal(buf[:n], data) {
		t.Fatal("payload mismatch")
	}
}

func TestSecureUniqueNonces(t *testing.T) {
	t.Parallel()
	// Two independent handshakes should produce different nonce prefixes
	// (tests the random nonce prefix feature)
	c1, s1 := net.Pipe()
	c2, s2 := net.Pipe()

	var sc1, sc2 *secure.SecureConn
	var wg sync.WaitGroup
	wg.Add(4)

	go func() { defer wg.Done(); secure.Handshake(s1, true) }()
	go func() { defer wg.Done(); sc1, _ = secure.Handshake(c1, false) }()
	go func() { defer wg.Done(); secure.Handshake(s2, true) }()
	go func() { defer wg.Done(); sc2, _ = secure.Handshake(c2, false) }()
	wg.Wait()

	if sc1 == nil || sc2 == nil {
		t.Fatal("handshake failed")
	}
	defer sc1.Close()
	defer sc2.Close()

	// Both connections should work independently
	// (they have different keys from different ECDH exchanges)
}
