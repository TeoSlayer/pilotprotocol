// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"crypto/ed25519"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestConcurrentRotateKeyAndSign is a regression test for the rotate-key /
// signer data race: RotateKey swaps d.identity and then zeros the OLD
// PrivateKey buffer in place, while the registry signer closure reads the
// private key to produce an Ed25519 signature. If the signer releases
// identityMu before calling Sign(), an in-flight signer that captured the
// old identity reads the very bytes RotateKey is concurrently zeroing
// (use-after-zero on signing material). Under -race this manifests as a
// WRITE/READ race on the PrivateKey slice.
//
// The fix holds identityMu.RLock() across the whole Sign() in every signer
// closure, and performs the old-key zeroing under identityMu.Lock(). RLock
// and Lock are mutually exclusive, so signing and zeroing can never overlap.
//
// This test spins N goroutines hammering the production-shaped signer closure
// while another goroutine repeatedly rotates the identity. It asserts every
// signature is valid for either the old or the new public key (never a
// corrupt/partially-zeroed key), and -race must report no data races.
func TestConcurrentRotateKeyAndSign(t *testing.T) {
	t.Parallel()

	reg, rc := startTestRegistry(t)
	t.Cleanup(func() { reg.Close() })
	t.Cleanup(func() { rc.Close() })

	d := New(Config{})
	d.regConn = rc
	registerSelfOnRegistry(t, d)

	// The exact signer closure the daemon installs in Start() / RotateKey:
	// hold identityMu.RLock() across Sign() so the read can never overlap
	// RotateKey's in-place zeroing of the old key (done under Lock()).
	sign := func(challenge string) (sig []byte, pub ed25519.PublicKey) {
		d.identityMu.RLock()
		defer d.identityMu.RUnlock()
		cur := d.identity
		if cur == nil {
			return nil, nil
		}
		// Snapshot the public key under the same lock so the verify target
		// matches the key that produced the signature.
		pub = append(ed25519.PublicKey(nil), cur.PublicKey...)
		return cur.Sign([]byte(challenge)), pub
	}

	const (
		signers     = 8
		rotations   = 12
		challengeFm = "rotate:race:challenge"
	)

	var (
		wg          sync.WaitGroup
		stop        atomic.Bool
		corruptSigs atomic.Int64
		signCount   atomic.Int64
	)

	// Signer goroutines: hammer the signer closure and verify each signature
	// against the public key snapshotted under the SAME RLock that produced
	// it. A correct signer returns a (sig, pub) pair where pub verifies sig.
	// A use-after-zero — the signer reading PrivateKey bytes that RotateKey
	// is concurrently zeroing — corrupts the signature so ed25519.Verify
	// fails (and trips the race detector). Snapshotting the pubkey under the
	// same lock means the verify target always matches the signing key, so a
	// verify failure can only come from torn signing material, not from a
	// benign mid-rotation key change.
	for i := 0; i < signers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				sig, pub := sign(challengeFm)
				if sig == nil {
					continue
				}
				signCount.Add(1)
				if !ed25519.Verify(pub, []byte(challengeFm), sig) {
					corruptSigs.Add(1)
				}
			}
		}()
	}

	// Rotation goroutine: the real production write+zero path. Each rotation
	// generates a fresh keypair, swaps it in under Lock, and zeros the old
	// PrivateKey buffer under Lock.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < rotations; i++ {
			if _, err := d.RotateKey(); err != nil {
				t.Errorf("RotateKey: %v", err)
				break
			}
		}
		stop.Store(true)
	}()

	// Safety valve so a wedged rotation can't hang the suite.
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		stop.Store(true)
		t.Fatal("concurrent rotate/sign did not finish within 30s")
	}

	if c := corruptSigs.Load(); c != 0 {
		t.Fatalf("got %d corrupt signatures (use-after-zero on signing key)", c)
	}
	if signCount.Load() == 0 {
		t.Fatal("no signatures were produced; test did not exercise the signer")
	}
}
