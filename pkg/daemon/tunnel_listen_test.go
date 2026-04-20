package daemon

import (
	"crypto/ecdh"
	"crypto/rand"
	"net"
	"strings"
	"testing"
)

func TestListenBindsUDPSocketAndSetsConn(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()
	if tm.conn == nil {
		t.Fatalf("tm.conn nil after Listen")
	}
	if tm.LocalAddr() == nil {
		t.Fatalf("LocalAddr nil after Listen")
	}
}

func TestListenResolveErrorReturnsResolveWrappedError(t *testing.T) {
	tm := NewTunnelManager()
	err := tm.Listen("not-a-valid-addr")
	if err == nil {
		t.Fatalf("expected error for invalid addr, got nil")
	}
	if !strings.Contains(err.Error(), "resolve") {
		t.Fatalf("error should mention resolve, got %v", err)
	}
	if tm.conn != nil {
		t.Fatalf("tm.conn should be nil on resolve error")
	}
}

func TestListenBindErrorReturnsListenWrappedError(t *testing.T) {
	// First listener occupies a port.
	first := NewTunnelManager()
	if err := first.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("first Listen: %v", err)
	}
	defer first.Close()
	addr := first.LocalAddr().(*net.UDPAddr).String()

	second := NewTunnelManager()
	err := second.Listen(addr)
	if err == nil {
		second.Close()
		t.Fatalf("expected bind error on duplicate port, got nil")
	}
	if !strings.Contains(err.Error(), "listen udp") {
		t.Fatalf("error should mention listen udp, got %v", err)
	}
	if second.conn != nil {
		t.Fatalf("second tm.conn should be nil on bind error")
	}
}

func TestLocalAddrNilWhenNotListening(t *testing.T) {
	tm := NewTunnelManager()
	if tm.LocalAddr() != nil {
		t.Fatalf("fresh TM LocalAddr should be nil")
	}
}

func TestCloseClosesRecvChAndIsIdempotent(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	if err := tm.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	// recvCh should now be closed — a range or receive should return immediately.
	select {
	case _, ok := <-tm.RecvCh():
		if ok {
			t.Fatalf("recvCh should be closed, but got a value")
		}
	default:
		t.Fatalf("recvCh not closed after Close — receive blocked")
	}

	// Second Close must be a noop (closeOnce guards it).
	if err := tm.Close(); err != nil {
		t.Fatalf("second Close returned error: %v", err)
	}
}

func TestCloseWithoutListenJustSignalsDoneAndClosesRecvCh(t *testing.T) {
	tm := NewTunnelManager()
	// No Listen → tm.conn is nil → Close skips conn.Close but still closes recvCh + done.
	if err := tm.Close(); err != nil {
		t.Fatalf("Close without Listen: %v", err)
	}
	select {
	case _, ok := <-tm.RecvCh():
		if ok {
			t.Fatalf("recvCh should be closed")
		}
	default:
		t.Fatalf("recvCh not closed")
	}
}

func TestRecvChReturnsSameChannelAcrossCalls(t *testing.T) {
	tm := NewTunnelManager()
	a := tm.RecvCh()
	b := tm.RecvCh()
	if a != b {
		t.Fatalf("RecvCh should return the same channel identity across calls")
	}
}

func TestDeriveSecretWithoutPrivKeyReturnsError(t *testing.T) {
	tm := NewTunnelManager()
	// No EnableEncryption → tm.privKey nil.
	_, err := tm.deriveSecret(make([]byte, 32))
	if err == nil || !strings.Contains(err.Error(), "no private key") {
		t.Fatalf("expected \"no private key\" error, got %v", err)
	}
}

func TestDeriveSecretInvalidPeerKeyLengthReturnsParseError(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	// Wrong-length bytes: X25519 needs exactly 32.
	_, err := tm.deriveSecret([]byte{1, 2, 3})
	if err == nil || !strings.Contains(err.Error(), "parse peer key") {
		t.Fatalf("expected parse-peer-key error, got %v", err)
	}
}

func TestDeriveSecretValidExchangeReturnsReadyPeerCrypto(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}

	// Generate a peer X25519 keypair
	curve := ecdh.X25519()
	peerPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("peer keygen: %v", err)
	}
	peerPub := peerPriv.PublicKey().Bytes()

	pc, err := tm.deriveSecret(peerPub)
	if err != nil {
		t.Fatalf("deriveSecret: %v", err)
	}
	if pc == nil {
		t.Fatalf("peerCrypto nil")
	}
	if !pc.ready {
		t.Fatalf("peerCrypto.ready should be true")
	}
	if pc.aead == nil {
		t.Fatalf("peerCrypto.aead should be populated")
	}
	// peerX25519Key stored for future rekey detection
	if !byteSliceEqual(pc.peerX25519Key[:], peerPub) {
		t.Fatalf("peerX25519Key mismatch")
	}
	// noncePrefix should be randomized (not all zeros) — probability of all-zero is 2^-32
	allZero := true
	for _, b := range pc.noncePrefix {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatalf("noncePrefix should be randomized, got all zeros")
	}
}

func byteSliceEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
