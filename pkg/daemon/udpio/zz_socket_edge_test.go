// SPDX-License-Identifier: AGPL-3.0-or-later

package udpio_test

import (
	"strings"
	"testing"

	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/udpio"
)

func TestListen_ResolveError(t *testing.T) {
	t.Parallel()
	// A host that can't resolve as a UDP address (no port).
	_, err := udpio.Listen("not-a-valid-address")
	if err == nil || !strings.Contains(err.Error(), "resolve") {
		t.Fatalf("want 'resolve' error, got %v", err)
	}
}

func TestListen_BindError(t *testing.T) {
	t.Parallel()
	// Negative-port format is rejected by resolve too on some platforms;
	// use a port that's reserved → bind fails.
	// Port 65536 overflows uint16 → resolve typically passes and listen fails.
	// Or: try to bind a privileged port we don't own.
	_, err := udpio.Listen("127.0.0.1:1")
	// This MAY succeed if running as root in some CI environments; if so,
	// skip the assertion gracefully.
	if err == nil {
		t.Skip("test environment allowed binding privileged port 1 (probably root); skipping")
	}
	if !strings.Contains(err.Error(), "listen udp") &&
		!strings.Contains(err.Error(), "permission") {
		t.Fatalf("want 'listen udp' or permission error, got %v", err)
	}
}

func TestLocalAddr_NilSocket(t *testing.T) {
	t.Parallel()
	var s *udpio.Socket
	if got := s.LocalAddr(); got != nil {
		t.Errorf("nil socket.LocalAddr() = %v, want nil", got)
	}
}

func TestConn_NilSocket(t *testing.T) {
	t.Parallel()
	var s *udpio.Socket
	if got := s.Conn(); got != nil {
		t.Errorf("nil socket.Conn() = %v, want nil", got)
	}
}

func TestListen_HappyPathLocalAddrPopulated(t *testing.T) {
	t.Parallel()
	s, err := udpio.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer s.Close()
	addr := s.LocalAddr()
	if addr == nil {
		t.Fatal("LocalAddr() returned nil after successful Listen")
	}
	if addr.Port == 0 {
		t.Errorf("LocalAddr() port is zero after Listen on ephemeral port")
	}
}
