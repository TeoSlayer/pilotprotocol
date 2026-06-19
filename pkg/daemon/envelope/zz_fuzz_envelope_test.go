// SPDX-License-Identifier: AGPL-3.0-or-later

package envelope_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/envelope"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/keyexchange"
)

// fuzzPeerSetup mirrors newPeerSetup() in zz_envelope_test.go but is
// callable from the fuzz seed setup (no *testing.T). Used only to
// produce a few valid encrypted frames for the seed corpus.
func fuzzPeerSetup() (localStore *keyexchange.Store, peerID uint32, ok bool) {
	curve := ecdh.X25519()
	localPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, 0, false
	}
	peerPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, 0, false
	}

	localStore = keyexchange.NewStore()
	const localID uint32 = 0x11111111
	peerID = 0x22222222
	localStore.SetLocalNodeID(localID)

	localMgr := keyexchange.New(localStore)
	localMgr.SetX25519Keys(localPriv, localPriv.PublicKey().Bytes())

	localCrypto, err := localMgr.DeriveSecret(peerPriv.PublicKey().Bytes())
	if err != nil {
		return nil, 0, false
	}
	localStore.Install(peerID, localCrypto)
	return localStore, peerID, true
}

// FuzzDecryptFrame targets the envelope decoder with arbitrary bytes.
// Decode path:
//   - 4-byte sender ID + 12-byte nonce + ciphertext-with-tag
//   - lookup peer's Crypto, replay-window check, AEAD-Open with AAD.
//
// Adversarial inputs:
//   - frames shorter than 4+12+16
//   - sender ID matching an installed peer (forces full crypto path)
//   - random ciphertext (must surface as ErrAEAD, never a panic)
//   - replayed counters (ErrReplay)
//   - counters far below the window high-water-mark (ErrOutsideWindow)
//
// A panic out of this function would crash the daemon readLoop, so the
// recover-and-report pattern below is the correct find signal.
func FuzzDecryptFrame(f *testing.F) {
	// Seeds: a few sizes including the structurally-too-short input.
	f.Add([]byte{})
	f.Add(make([]byte, 4+12+15)) // one byte short of minimum
	f.Add(make([]byte, 4+12+16)) // exactly at minimum (all zeros)
	f.Add(make([]byte, 128))
	// Frame whose sender field matches the installed peer.
	{
		buf := make([]byte, 4+12+16)
		// peerID 0x22222222 matches fuzzPeerSetup() above.
		binary.BigEndian.PutUint32(buf[0:4], 0x22222222)
		f.Add(buf)
	}

	// Build one shared Store at seed time so the fuzzer reaches the
	// AEAD path for at least some inputs (sender ID 0x22222222).
	store, _, ok := fuzzPeerSetup()
	if !ok {
		f.Skip("could not initialise keyexchange Store")
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic on input %x: %v", data, r)
			}
		}()
		// Copy because some implementations may mutate the input.
		buf := make([]byte, len(data))
		copy(buf, data)
		_ = envelope.DecryptFrame(store, buf)
	})
}
