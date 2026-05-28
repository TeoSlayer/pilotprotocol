// SPDX-License-Identifier: AGPL-3.0-or-later

package secure_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/pilot-protocol/common/secure"
)

// runLookupHandshake connects two net.Pipe ends, runs HandshakeWithLookup on
// each side concurrently, and returns both resulting SecureConns (or errors).
// NOTE: callers must NOT mark tests t.Parallel() since HandshakeWithLookup
// mutates the global replay cache (see iter 12 lesson).
func runLookupHandshake(t *testing.T, serverCfg, clientCfg *secure.HandshakeConfig, serverLookup, clientLookup secure.PeerPubKeyLookup) (*secure.SecureConn, error, *secure.SecureConn, error) {
	t.Helper()
	s, c := net.Pipe()
	type result struct {
		sc  *secure.SecureConn
		err error
	}
	srvCh := make(chan result, 1)
	cliCh := make(chan result, 1)
	go func() {
		sc, err := secure.HandshakeWithLookup(s, true, serverCfg, serverLookup)
		srvCh <- result{sc, err}
	}()
	go func() {
		sc, err := secure.HandshakeWithLookup(c, false, clientCfg, clientLookup)
		cliCh <- result{sc, err}
	}()
	select {
	case <-time.After(5 * time.Second):
		s.Close()
		c.Close()
		t.Fatal("handshake timed out")
	default:
	}
	srv := <-srvCh
	cli := <-cliCh
	return srv.sc, srv.err, cli.sc, cli.err
}

func newEd25519KeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestHandshakeWithLookupHappyPath(t *testing.T) {
	secure.ResetReplayCache()
	serverPub, serverPriv := newEd25519KeyPair(t)
	clientPub, clientPriv := newEd25519KeyPair(t)
	const srvID, cliID = uint32(0x10001), uint32(0x20002)

	srvLookup := func(nodeID uint32) ed25519.PublicKey {
		if nodeID == cliID {
			return clientPub
		}
		return nil
	}
	cliLookup := func(nodeID uint32) ed25519.PublicKey {
		if nodeID == srvID {
			return serverPub
		}
		return nil
	}

	srvSC, srvErr, cliSC, cliErr := runLookupHandshake(t,
		&secure.HandshakeConfig{NodeID: srvID, Signer: serverPriv},
		&secure.HandshakeConfig{NodeID: cliID, Signer: clientPriv},
		srvLookup, cliLookup)

	if srvErr != nil {
		t.Fatalf("server handshake: %v", srvErr)
	}
	if cliErr != nil {
		t.Fatalf("client handshake: %v", cliErr)
	}
	if srvSC.PeerNodeID != cliID {
		t.Errorf("server saw peer=%d, want %d", srvSC.PeerNodeID, cliID)
	}
	if cliSC.PeerNodeID != srvID {
		t.Errorf("client saw peer=%d, want %d", cliSC.PeerNodeID, srvID)
	}

	// End-to-end data exchange proves the derived keys match on both sides.
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 5)
		if _, err := io.ReadFull(cliSC, buf); err != nil {
			done <- err
			return
		}
		if string(buf) != "ping!" {
			done <- errors.New("bad payload: " + string(buf))
			return
		}
		done <- nil
	}()
	if _, err := srvSC.Write([]byte("ping!")); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("read: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout reading from encrypted stream")
	}
	cliSC.Close()
	srvSC.Close()
}

func TestHandshakeWithLookupServerRejectsUnknownPeer(t *testing.T) {
	secure.ResetReplayCache()
	serverPub, serverPriv := newEd25519KeyPair(t)
	_, clientPriv := newEd25519KeyPair(t)
	const srvID, cliID = uint32(0x30003), uint32(0x40004)

	srvLookup := func(_ uint32) ed25519.PublicKey { return nil } // unknown
	cliLookup := func(nodeID uint32) ed25519.PublicKey {
		if nodeID == srvID {
			return serverPub
		}
		return nil
	}

	_, srvErr, _, _ := runLookupHandshake(t,
		&secure.HandshakeConfig{NodeID: srvID, Signer: serverPriv},
		&secure.HandshakeConfig{NodeID: cliID, Signer: clientPriv},
		srvLookup, cliLookup)

	// Server reads client's auth frame AFTER writing its own, then looks up
	// the client's pubkey and rejects on nil. Client has already completed
	// its side (read server frame, verified, wrote its own) so it returns
	// without error — only the server-side error surfaces.
	if srvErr == nil {
		t.Fatal("server should have rejected unknown peer")
	}
}

func TestHandshakeWithLookupClientRejectsUnknownServer(t *testing.T) {
	secure.ResetReplayCache()
	_, serverPriv := newEd25519KeyPair(t)
	clientPub, clientPriv := newEd25519KeyPair(t)
	const srvID, cliID = uint32(0x50005), uint32(0x60006)

	srvLookup := func(nodeID uint32) ed25519.PublicKey {
		if nodeID == cliID {
			return clientPub
		}
		return nil
	}
	cliLookup := func(_ uint32) ed25519.PublicKey { return nil }

	_, srvErr, _, cliErr := runLookupHandshake(t,
		&secure.HandshakeConfig{NodeID: srvID, Signer: serverPriv},
		&secure.HandshakeConfig{NodeID: cliID, Signer: clientPriv},
		srvLookup, cliLookup)

	if cliErr == nil {
		t.Fatal("client should have rejected unknown server")
	}
	if srvErr == nil {
		t.Fatal("server should have failed after client closed")
	}
}

func TestHandshakeWithLookupBadSignatureRejected(t *testing.T) {
	secure.ResetReplayCache()
	serverPub, serverPriv := newEd25519KeyPair(t)
	_, clientPriv := newEd25519KeyPair(t)
	// Third unrelated pubkey — server will look up client by nodeID but
	// get a key that doesn't match the client's actual signer.
	wrongPub, _ := newEd25519KeyPair(t)
	const srvID, cliID = uint32(0x70007), uint32(0x80008)

	srvLookup := func(nodeID uint32) ed25519.PublicKey {
		if nodeID == cliID {
			return wrongPub // signature will fail to verify
		}
		return nil
	}
	cliLookup := func(nodeID uint32) ed25519.PublicKey {
		if nodeID == srvID {
			return serverPub
		}
		return nil
	}

	_, srvErr, _, _ := runLookupHandshake(t,
		&secure.HandshakeConfig{NodeID: srvID, Signer: serverPriv},
		&secure.HandshakeConfig{NodeID: cliID, Signer: clientPriv},
		srvLookup, cliLookup)

	if srvErr == nil {
		t.Fatal("server should have rejected bad signature")
	}
}

func TestHandshakeWithLookupNoAuthSkipsLookup(t *testing.T) {
	secure.ResetReplayCache()
	s, c := net.Pipe()
	srvCh := make(chan error, 1)
	cliCh := make(chan error, 1)
	// No signer in cfg — auth is skipped, lookup is never called.
	go func() {
		_, err := secure.HandshakeWithLookup(s, true, nil, nil)
		srvCh <- err
	}()
	go func() {
		_, err := secure.HandshakeWithLookup(c, false, nil, nil)
		cliCh <- err
	}()
	select {
	case err := <-srvCh:
		if err != nil {
			t.Fatalf("server: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server handshake timed out")
	}
	select {
	case err := <-cliCh:
		if err != nil {
			t.Fatalf("client: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("client handshake timed out")
	}
	s.Close()
	c.Close()
}

// ---------- Server constructors ----------

func TestNewServerSetsFields(t *testing.T) {
	t.Parallel()
	called := false
	h := func(_ net.Conn) { called = true }
	s := secure.NewServer(nil, h)
	if s.Driver() != nil {
		t.Error("driver should be nil")
	}
	if s.Handler() == nil {
		t.Fatal("handler nil")
	}
	if s.AuthSigner() != nil || s.AuthNodeID() != 0 || s.PeerLookup() != nil {
		t.Error("unauth server should not populate auth fields")
	}
	// Sanity: handler invocable.
	s.Handler()(nil)
	if !called {
		t.Error("handler not invoked")
	}
}

func TestNewAuthServerSetsFields(t *testing.T) {
	t.Parallel()
	_, priv := newEd25519KeyPair(t)
	lookup := func(_ uint32) ed25519.PublicKey { return nil }
	h := func(_ net.Conn) {}
	s := secure.NewAuthServer(nil, h, 0xABCD1234, priv, lookup)
	if s.AuthNodeID() != 0xABCD1234 {
		t.Errorf("authNodeID = %#x", s.AuthNodeID())
	}
	if s.AuthSigner() == nil {
		t.Error("authSigner nil")
	}
	if s.PeerLookup() == nil {
		t.Error("peerLookup nil")
	}
}
