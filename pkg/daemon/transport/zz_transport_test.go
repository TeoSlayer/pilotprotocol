// SPDX-License-Identifier: AGPL-3.0-or-later

package transport_test

import (
	"errors"
	"net"
	"testing"

	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/transport"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/udpio"
)

// TestUDPIOSocketSatisfiesTransport is a static-compile assertion that
// *udpio.Socket implements transport.Transport. If anyone removes a
// method from Socket (Send/Recv/LocalAddr/Close) in a future refactor,
// the build fails here — before tunnel.go does at runtime.
//
// The actual UDP behavior is covered by the existing udpio suite; this
// file only pins the interface contract.
func TestUDPIOSocketSatisfiesTransport(t *testing.T) {
	t.Parallel()
	var _ transport.Transport = (*udpio.Socket)(nil)
	// A live socket round-trip is the strongest end-to-end check, but
	// udpio.zz_udpio_test.go already covers that. Here we just confirm
	// the type implements the interface — compile-time check above.
	t.Log("compile-time: *udpio.Socket satisfies transport.Transport")
}

// TestErrClosedIsShared pins that udpio.ErrClosed and transport.ErrClosed
// are the same value. Callers use errors.Is on one or the other
// interchangeably; if they ever diverge silently, the readLoop teardown
// logic breaks for the non-matching transport.
func TestErrClosedIsShared(t *testing.T) {
	t.Parallel()
	if !errors.Is(udpio.ErrClosed, transport.ErrClosed) {
		t.Fatal("udpio.ErrClosed and transport.ErrClosed are not the same sentinel")
	}
	if !errors.Is(transport.ErrClosed, udpio.ErrClosed) {
		t.Fatal("symmetric check failed — sentinels diverged")
	}
}

// fakeTransport is a stub implementation used to confirm an arbitrary
// type with the right method set satisfies the interface. If anyone
// changes a method signature on Transport, this no longer compiles
// before runtime breaks.
type fakeTransport struct{}

func (fakeTransport) Send(_ []byte, _ *net.UDPAddr) (int, error) { return 0, nil }
func (fakeTransport) Recv() ([]byte, *net.UDPAddr, error)        { return nil, nil, transport.ErrClosed }
func (fakeTransport) LocalAddr() *net.UDPAddr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}
func (fakeTransport) Close() error { return nil }

// TestArbitraryTypeSatisfiesTransport pins the interface shape: any
// type with the four expected methods is a valid Transport. This is
// what makes the WSS transport pluggable.
func TestArbitraryTypeSatisfiesTransport(t *testing.T) {
	t.Parallel()
	var iface transport.Transport = fakeTransport{}
	if _, _, err := iface.Recv(); err == nil {
		t.Fatal("fake Recv should return ErrClosed sentinel")
	}
	if la := iface.LocalAddr(); la == nil {
		t.Fatal("fake LocalAddr should return non-nil")
	}
	_ = iface.Close()
}
