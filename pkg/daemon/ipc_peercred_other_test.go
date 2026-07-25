//go:build !linux && !darwin

package daemon

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckPeerUIDNonUnixRejected(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	if _, err := checkPeerUID(c1); err == nil {
		t.Fatal("expected error for non-unix conn, got nil")
	}
}

func TestCheckPeerUIDUnixFailsClosed(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "s.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			accepted <- nil
			return
		}
		accepted <- c
	}()

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial unix: %v", err)
	}
	defer conn.Close()
	if srv := <-accepted; srv != nil {
		defer srv.Close()
	}

	uc, ok := conn.(*net.UnixConn)
	if !ok {
		t.Fatalf("expected *net.UnixConn, got %T", conn)
	}
	_, err = checkPeerUID(uc)
	if err == nil {
		t.Fatal("expected fail-closed error on unsupported platform, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported on this platform") {
		t.Fatalf("unexpected error: %v", err)
	}
}
