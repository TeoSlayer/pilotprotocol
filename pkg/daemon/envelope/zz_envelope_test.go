// SPDX-License-Identifier: AGPL-3.0-or-later

package envelope_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/envelope"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/keyexchange"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// peerSetup holds two L5 Managers + Stores with mutually derived Crypto
// installed for each side, so envelope encrypt/decrypt can round-trip.
type peerSetup struct {
	localID, peerID uint32
	localStore      *keyexchange.Store
	peerStore       *keyexchange.Store
}

// newPeerSetup wires up two Managers, generates X25519 keypairs, and
// installs Crypto on both sides keyed under each other's node ID. Returns
// the two stores (local has Crypto for peerID, peer has Crypto for localID).
func newPeerSetup(t *testing.T) *peerSetup {
	t.Helper()

	curve := ecdh.X25519()

	localPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("local X25519 keygen: %v", err)
	}
	peerPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("peer X25519 keygen: %v", err)
	}

	localStore := keyexchange.NewStore()
	peerStore := keyexchange.NewStore()

	const localID uint32 = 0x11111111
	const peerID uint32 = 0x22222222

	localStore.SetLocalNodeID(localID)
	peerStore.SetLocalNodeID(peerID)

	localMgr := keyexchange.New(localStore)
	peerMgr := keyexchange.New(peerStore)

	localMgr.SetX25519Keys(localPriv, localPriv.PublicKey().Bytes())
	peerMgr.SetX25519Keys(peerPriv, peerPriv.PublicKey().Bytes())

	// Each side derives a shared secret using their own private key + the
	// other's public key. ECDH guarantees both sides land on the same
	// shared secret, so HKDF derives the same AEAD key on both sides.
	localCrypto, err := localMgr.DeriveSecret(peerPriv.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("local DeriveSecret: %v", err)
	}
	peerCrypto, err := peerMgr.DeriveSecret(localPriv.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("peer DeriveSecret: %v", err)
	}

	// Both Cryptos must share the same nonce-prefix to decrypt each
	// other's frames — DeriveSecret randomizes per-call. We force them
	// equal so peer-side can open frames sealed with local-side's nonce
	// (since the nonce is on the wire, prefix only needs to match for
	// the AEAD nonce it was sealed under). Actually: the encrypt side
	// writes its OWN prefix into the wire nonce, so the decrypt side
	// reads that nonce verbatim — prefixes do NOT need to match. We
	// keep them as-is.

	localStore.Install(peerID, localCrypto)
	peerStore.Install(localID, peerCrypto)

	return &peerSetup{
		localID:    localID,
		peerID:     peerID,
		localStore: localStore,
		peerStore:  peerStore,
	}
}

// TestRoundTrip seals a plaintext on the local side and opens it on the
// peer side. Asserts plaintext recovery and counter increment.
func TestRoundTrip(t *testing.T) {
	t.Parallel()
	s := newPeerSetup(t)

	plaintext := []byte("hello pilot envelope")
	frame, err := envelope.EncryptFrame(s.localStore, s.peerID, plaintext)
	if err != nil {
		t.Fatalf("EncryptFrame: %v", err)
	}

	// Wire format: [PILS(4)][localNodeID(4)][nonce(12)][ct+tag]
	if !bytes.Equal(frame[0:4], protocol.TunnelMagicSecure[:]) {
		t.Fatalf("missing PILS magic: %x", frame[0:4])
	}
	if got := binary.BigEndian.Uint32(frame[4:8]); got != s.localID {
		t.Fatalf("frame senderID = %x, want %x", got, s.localID)
	}

	// Peer side decrypts (skip the PILS magic — DecryptFrame consumes
	// data starting at the senderID).
	res := envelope.DecryptFrame(s.peerStore, frame[4:])
	if res.Err != nil {
		t.Fatalf("DecryptFrame: %v", res.Err)
	}
	if !bytes.Equal(res.Plaintext, plaintext) {
		t.Fatalf("plaintext mismatch: got %q want %q", res.Plaintext, plaintext)
	}
	if res.PeerNodeID != s.localID {
		t.Fatalf("PeerNodeID = %x, want %x", res.PeerNodeID, s.localID)
	}
	if res.Counter != 1 {
		t.Fatalf("first decrypted Counter = %d, want 1", res.Counter)
	}
}

// TestWireFormatLayout asserts the on-wire byte layout matches the L6
// golden contract: [PILS(4)][senderID(4)][nonce(12)][ciphertext+GCM tag(>=16)].
// Cross-references tests/wire_golden_test.go::l6EncryptedFrameRoundtrip.
func TestWireFormatLayout(t *testing.T) {
	t.Parallel()
	s := newPeerSetup(t)

	plaintext := []byte("layout-check")
	frame, err := envelope.EncryptFrame(s.localStore, s.peerID, plaintext)
	if err != nil {
		t.Fatalf("EncryptFrame: %v", err)
	}

	const headerLen = 4 + 4 + 12
	const gcmTagLen = 16
	wantMin := headerLen + len(plaintext) + gcmTagLen
	if len(frame) != wantMin {
		t.Fatalf("frame len = %d, want %d", len(frame), wantMin)
	}
	if !bytes.Equal(frame[0:4], protocol.TunnelMagicSecure[:]) {
		t.Fatalf("magic mismatch: got %x, want %x", frame[0:4], protocol.TunnelMagicSecure[:])
	}
	if got := binary.BigEndian.Uint32(frame[4:8]); got != s.localID {
		t.Fatalf("senderID = %x, want %x", got, s.localID)
	}

	// The 12-byte nonce decomposes as [4-byte prefix][8-byte counter].
	nonceCounter := binary.BigEndian.Uint64(frame[8+4 : 8+12])
	if nonceCounter != 1 {
		t.Fatalf("first frame nonce counter = %d, want 1", nonceCounter)
	}
}

// TestDecryptErrTooShort exercises the structural-validity short-circuit.
func TestDecryptErrTooShort(t *testing.T) {
	t.Parallel()
	s := newPeerSetup(t)

	// minimum is 4 (nodeID) + 12 (nonce) + 16 (GCM tag) = 32 bytes.
	for _, n := range []int{0, 1, 16, 31} {
		res := envelope.DecryptFrame(s.peerStore, make([]byte, n))
		if !errors.Is(res.Err, envelope.ErrTooShort) {
			t.Fatalf("len=%d: err = %v, want ErrTooShort", n, res.Err)
		}
	}
}

// TestDecryptErrNoKey arrives when no Crypto is installed for the
// claimed peer ID.
func TestDecryptErrNoKey(t *testing.T) {
	t.Parallel()
	emptyStore := keyexchange.NewStore()

	// Build any structurally-valid frame (4 + 12 + 16) — content irrelevant.
	data := make([]byte, 4+12+16)
	binary.BigEndian.PutUint32(data[0:4], 0xDEADBEEF)

	res := envelope.DecryptFrame(emptyStore, data)
	if !errors.Is(res.Err, keyexchange.ErrNoKey) {
		t.Fatalf("err = %v, want ErrNoKey", res.Err)
	}
	if res.PeerNodeID != 0xDEADBEEF {
		t.Fatalf("PeerNodeID = %x, want 0xDEADBEEF", res.PeerNodeID)
	}
}

// TestDecryptErrAEAD flips a ciphertext byte and expects authentication
// failure (NOT replay — the speculative replay bit must be undone).
func TestDecryptErrAEAD(t *testing.T) {
	t.Parallel()
	s := newPeerSetup(t)

	plaintext := []byte("tamper-me")
	frame, err := envelope.EncryptFrame(s.localStore, s.peerID, plaintext)
	if err != nil {
		t.Fatalf("EncryptFrame: %v", err)
	}
	// Tamper a byte inside the ciphertext (after PILS+sender+nonce header).
	tampered := append([]byte(nil), frame...)
	tampered[len(tampered)-1] ^= 0xFF // flip last byte of GCM tag

	res := envelope.DecryptFrame(s.peerStore, tampered[4:])
	if !errors.Is(res.Err, envelope.ErrAEAD) {
		t.Fatalf("err = %v, want ErrAEAD", res.Err)
	}

	// After ErrAEAD, the genuine frame at the same counter should still
	// open (proves UndoReplayBit ran).
	res2 := envelope.DecryptFrame(s.peerStore, frame[4:])
	if res2.Err != nil {
		t.Fatalf("legit reopen after AEAD-fail: %v", res2.Err)
	}
	if !bytes.Equal(res2.Plaintext, plaintext) {
		t.Fatalf("plaintext mismatch on retry: %q vs %q", res2.Plaintext, plaintext)
	}
}

// TestDecryptErrReplay re-submits a previously-accepted frame.
func TestDecryptErrReplay(t *testing.T) {
	t.Parallel()
	s := newPeerSetup(t)

	frame, err := envelope.EncryptFrame(s.localStore, s.peerID, []byte("once"))
	if err != nil {
		t.Fatalf("EncryptFrame: %v", err)
	}

	if r := envelope.DecryptFrame(s.peerStore, frame[4:]); r.Err != nil {
		t.Fatalf("first decrypt: %v", r.Err)
	}
	r2 := envelope.DecryptFrame(s.peerStore, frame[4:])
	if !errors.Is(r2.Err, envelope.ErrReplay) {
		t.Fatalf("replay err = %v, want ErrReplay", r2.Err)
	}
}

// TestDecryptErrOutsideWindow: pump the high-water counter past the
// replay window, then submit a low-counter frame. Should be rejected
// with ErrOutsideWindow rather than ErrReplay.
func TestDecryptErrOutsideWindow(t *testing.T) {
	t.Parallel()
	s := newPeerSetup(t)

	// First, capture a frame at counter=1 (don't decrypt it yet).
	stale, err := envelope.EncryptFrame(s.localStore, s.peerID, []byte("stale"))
	if err != nil {
		t.Fatalf("encrypt stale: %v", err)
	}

	// Now advance the local counter way past the window by encrypting
	// many frames AND delivering them so the peer's MaxRecvNonce
	// advances past stale's counter + ReplayWindowSize.
	advance := keyexchange.ReplayWindowSize + 8
	for i := 0; i < advance; i++ {
		f, err := envelope.EncryptFrame(s.localStore, s.peerID, []byte("advance"))
		if err != nil {
			t.Fatalf("encrypt advance #%d: %v", i, err)
		}
		if r := envelope.DecryptFrame(s.peerStore, f[4:]); r.Err != nil {
			t.Fatalf("advance decrypt #%d: %v", i, r.Err)
		}
	}

	// Now submit the stale (counter=1) frame.
	res := envelope.DecryptFrame(s.peerStore, stale[4:])
	if !errors.Is(res.Err, envelope.ErrOutsideWindow) {
		t.Fatalf("err = %v, want ErrOutsideWindow", res.Err)
	}
}

// TestConcurrentEncryptDecrypt runs N goroutines in parallel; each
// encrypts a unique payload, ships it across, the peer side decrypts
// asynchronously. Validates no race (with -race), no spurious errors,
// and no plaintext corruption.
func TestConcurrentEncryptDecrypt(t *testing.T) {
	t.Parallel()
	s := newPeerSetup(t)

	const goroutines = 100
	frames := make(chan []byte, goroutines)

	var encWg sync.WaitGroup
	encWg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer encWg.Done()
			pt := []byte(fmt.Sprintf("payload-%04d-%s", i, "filler-bytes"))
			frame, err := envelope.EncryptFrame(s.localStore, s.peerID, pt)
			if err != nil {
				t.Errorf("encrypt #%d: %v", i, err)
				return
			}
			frames <- frame
		}()
	}
	encWg.Wait()
	close(frames)

	var (
		decWg sync.WaitGroup
		ok    atomic.Int64
		fail  atomic.Int64
	)
	for frame := range frames {
		decWg.Add(1)
		go func(f []byte) {
			defer decWg.Done()
			res := envelope.DecryptFrame(s.peerStore, f[4:])
			if res.Err != nil {
				fail.Add(1)
				t.Errorf("decrypt err: %v (counter %d)", res.Err, res.Counter)
				return
			}
			ok.Add(1)
		}(frame)
	}
	decWg.Wait()

	if fail.Load() != 0 {
		t.Fatalf("decrypt failures: %d/%d", fail.Load(), goroutines)
	}
	if ok.Load() != int64(goroutines) {
		t.Fatalf("decrypt ok = %d, want %d", ok.Load(), goroutines)
	}
}

// TestCounterMonotonic checks that 1000 sequential encrypts produce a
// strictly increasing per-frame counter (1..1000), with no gaps and no
// duplicates. The counter is in the last 8 bytes of the 12-byte nonce.
func TestCounterMonotonic(t *testing.T) {
	t.Parallel()
	s := newPeerSetup(t)

	const N = 1000
	const headerLen = 4 + 4 + 12

	prev := uint64(0)
	for i := 0; i < N; i++ {
		frame, err := envelope.EncryptFrame(s.localStore, s.peerID, []byte("seq"))
		if err != nil {
			t.Fatalf("encrypt #%d: %v", i, err)
		}
		if len(frame) < headerLen {
			t.Fatalf("frame too short at #%d", i)
		}
		// Counter occupies bytes 16..24 (PILS=4 + sender=4 + prefix=4 + counter=8).
		c := binary.BigEndian.Uint64(frame[8+4 : 8+12])
		if c != prev+1 {
			t.Fatalf("counter at #%d = %d, want %d (monotonic +1)", i, c, prev+1)
		}
		prev = c
	}
	if prev != N {
		t.Fatalf("final counter = %d, want %d", prev, N)
	}
}

// TestEncryptFrameNoKey covers the encrypt-side ErrNoKey path.
func TestEncryptFrameNoKey(t *testing.T) {
	t.Parallel()
	store := keyexchange.NewStore()
	store.SetLocalNodeID(0xAAAA)

	_, err := envelope.EncryptFrame(store, 0xBBBB, []byte("x"))
	if !errors.Is(err, keyexchange.ErrNoKey) {
		t.Fatalf("err = %v, want ErrNoKey", err)
	}
}

// TestEncryptFrameNotReady covers the encrypt-side ErrNotReady path —
// when a Crypto is installed but its handshake is incomplete.
func TestEncryptFrameNotReady(t *testing.T) {
	t.Parallel()
	s := newPeerSetup(t)

	c := s.localStore.Get(s.peerID)
	if c == nil {
		t.Fatalf("setup missing Crypto for peer")
	}
	c.Ready = false
	defer func() { c.Ready = true }()

	_, err := envelope.EncryptFrame(s.localStore, s.peerID, []byte("x"))
	if !errors.Is(err, keyexchange.ErrNotReady) {
		t.Fatalf("err = %v, want ErrNotReady", err)
	}
}
