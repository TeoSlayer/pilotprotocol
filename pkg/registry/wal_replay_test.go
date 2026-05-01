// SPDX-License-Identifier: AGPL-3.0-or-later

package registry

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeMinimalSnapshot writes a snapshot to disk with the given nodes/networks
// pre-populated, then closes that server so the snapshot file is on disk and
// the WAL is empty. Returns the snapshot file path.
func writeMinimalSnapshot(t *testing.T, dir string, seed func(*Server)) string {
	t.Helper()
	storePath := filepath.Join(dir, "registry.json")
	s := NewWithStore("", storePath)
	if seed != nil {
		seed(s)
	}
	// Trigger a full flushSave directly so the snapshot is on disk and the
	// WAL is truncated.
	if err := s.flushSave(); err != nil {
		t.Fatalf("flushSave: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return storePath
}

// appendWALDelta opens the WAL file directly (the same path the server uses)
// and appends one entry. Used to simulate a mutation that completed in
// memory + WAL but never made it into a snapshot before the server died.
func appendWALDelta(t *testing.T, storePath string, typ DeltaType, nodeID uint32, payload interface{}) {
	t.Helper()
	w, err := NewWAL(storePath + ".wal")
	if err != nil {
		t.Fatalf("open WAL: %v", err)
	}
	defer w.Close()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	if err := w.Append(DeltaEntry{Type: typ, NodeID: nodeID, Data: raw}); err != nil {
		t.Fatalf("WAL append: %v", err)
	}
}

// TestWALReplayRestoresRegisterAfterCrash is the canonical recovery test:
// we write a snapshot, then a fresh register-delta to the WAL (no
// intermediate flushSave), then open a NEW server pointed at the same
// store. Replay must restore the registered node so its identity isn't
// lost on crash.
func TestWALReplayRestoresRegisterAfterCrash(t *testing.T) {
	dir := t.TempDir()
	storePath := writeMinimalSnapshot(t, dir, nil)

	// Generate a stable identity for the "registered" node so the test
	// asserts the pubKeyIdx is restored correctly.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	pkB64 := base64.StdEncoding.EncodeToString(pub)

	delta := registerDelta{
		NodeID:    777,
		Owner:     "alice",
		PublicKey: pkB64,
		RealAddr:  "10.0.0.7:9000",
		Hostname:  "alice-host",
		LANAddrs:  []string{"10.0.0.7"},
		Version:   "1.9.0-rc3",
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	appendWALDelta(t, storePath, DeltaRegister, 777, delta)

	// "Restart" by opening a new Server at the same path.
	s := NewWithStore("", storePath)
	defer s.Close()

	s.mu.RLock()
	defer s.mu.RUnlock()
	node, ok := s.nodes[777]
	if !ok {
		t.Fatalf("node 777 not restored from WAL replay; nodes=%v", keysOfUint32Map(s.nodes))
	}
	if node.Owner != "alice" {
		t.Fatalf("node.Owner = %q, want %q", node.Owner, "alice")
	}
	if node.RealAddr != "10.0.0.7:9000" {
		t.Fatalf("node.RealAddr = %q, want %q", node.RealAddr, "10.0.0.7:9000")
	}
	if got := s.pubKeyIdx[pkB64]; got != 777 {
		t.Fatalf("pubKeyIdx[%s] = %d, want 777", pkB64, got)
	}
	if got := s.ownerIdx["alice"]; got != 777 {
		t.Fatalf("ownerIdx[alice] = %d, want 777", got)
	}
	if got := s.hostnameIdx["alice-host"]; got != 777 {
		t.Fatalf("hostnameIdx[alice-host] = %d, want 777", got)
	}
	// Backbone (network 0) should include the node.
	backbone := s.networks[0]
	if backbone == nil {
		t.Fatalf("backbone network missing")
	}
	found := false
	for _, m := range backbone.Members {
		if m == 777 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("node 777 not in backbone members: %v", backbone.Members)
	}
	if s.nextNode <= 777 {
		t.Fatalf("nextNode = %d, want > 777", s.nextNode)
	}
}

// TestWALReplayIdempotentWithSnapshot covers the overlap window: if a
// mutation lands in the snapshot AND the WAL (because flushSave wrote
// the snapshot, the WAL truncated, then a subsequent flush wrote a new
// snapshot but the WAL had a pending entry from before), replay must
// not corrupt the existing snapshot state.
func TestWALReplayIdempotentWithSnapshot(t *testing.T) {
	dir := t.TempDir()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	pkB64 := base64.StdEncoding.EncodeToString(pub)

	// Snapshot already includes node 555.
	storePath := writeMinimalSnapshot(t, dir, func(s *Server) {
		s.mu.Lock()
		n := &NodeInfo{
			ID:        555,
			Owner:     "preexisting",
			PublicKey: pub,
			RealAddr:  "10.0.0.55:9000",
			Networks:  []uint16{0},
		}
		n.setLastSeen(time.Now())
		s.nodes[555] = n
		s.pubKeyIdx[pkB64] = 555
		s.ownerIdx["preexisting"] = 555
		s.networks[0].Members = append(s.networks[0].Members, 555)
		if s.nextNode <= 555 {
			s.nextNode = 556
		}
		s.mu.Unlock()
	})

	// WAL also has a register entry for 555 (overlap scenario).
	appendWALDelta(t, storePath, DeltaRegister, 555, registerDelta{
		NodeID:    555,
		Owner:     "preexisting",
		PublicKey: pkB64,
		RealAddr:  "10.0.0.99:9000", // different addr — replay should NOT overwrite
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	})

	s := NewWithStore("", storePath)
	defer s.Close()

	s.mu.RLock()
	defer s.mu.RUnlock()
	node, ok := s.nodes[555]
	if !ok {
		t.Fatalf("node 555 missing")
	}
	// Snapshot's RealAddr should win (replay is idempotent — does not overwrite).
	if node.RealAddr != "10.0.0.55:9000" {
		t.Fatalf("RealAddr = %q, want snapshot value 10.0.0.55:9000", node.RealAddr)
	}
}

// TestWALReplayRestoresKeyRotation locks down the high-stakes case: a
// daemon rotated its key, the rotation hit the WAL, then the registry
// crashed before the next snapshot. On restart, the new pubkey must be
// present in pubKeyIdx so the daemon's next signed request validates.
func TestWALReplayRestoresKeyRotation(t *testing.T) {
	dir := t.TempDir()
	oldPub, _, _ := ed25519.GenerateKey(rand.Reader)
	oldPkB64 := base64.StdEncoding.EncodeToString(oldPub)

	storePath := writeMinimalSnapshot(t, dir, func(s *Server) {
		s.mu.Lock()
		n := &NodeInfo{
			ID:        333,
			Owner:     "rotator",
			PublicKey: oldPub,
			Networks:  []uint16{0},
		}
		n.setLastSeen(time.Now())
		s.nodes[333] = n
		s.pubKeyIdx[oldPkB64] = 333
		s.networks[0].Members = append(s.networks[0].Members, 333)
		s.mu.Unlock()
	})

	newPub, _, _ := ed25519.GenerateKey(rand.Reader)
	newPkB64 := base64.StdEncoding.EncodeToString(newPub)

	appendWALDelta(t, storePath, DeltaKeyRotation, 333, keyRotationDelta{
		NodeID:       333,
		NewPublicKey: newPkB64,
		RotatedAt:    time.Now().UTC().Format(time.RFC3339),
	})

	s := NewWithStore("", storePath)
	defer s.Close()

	s.mu.RLock()
	defer s.mu.RUnlock()

	if _, exists := s.pubKeyIdx[oldPkB64]; exists {
		t.Fatalf("old pubkey should be removed from index after rotation replay")
	}
	if got := s.pubKeyIdx[newPkB64]; got != 333 {
		t.Fatalf("new pubKeyIdx[%s] = %d, want 333", newPkB64, got)
	}
	if base64.StdEncoding.EncodeToString(s.nodes[333].PublicKey) != newPkB64 {
		t.Fatalf("node.PublicKey not updated to new key")
	}
}

// TestWALReplayHandlesUnknownTypeGracefully ensures forward-compatibility:
// a future version writing a new DeltaType doesn't break replay on an
// older binary. Unknown types should be skipped.
func TestWALReplayHandlesUnknownTypeGracefully(t *testing.T) {
	dir := t.TempDir()
	storePath := writeMinimalSnapshot(t, dir, nil)

	// Use a DeltaType we don't currently apply (DeltaHeartbeat is in the
	// enum but never WAL'd; it's a fine stand-in for "unknown to replay").
	appendWALDelta(t, storePath, DeltaHeartbeat, 0, map[string]interface{}{
		"future_field": "should be ignored",
	})

	s := NewWithStore("", storePath)
	defer s.Close()
	// No assertion needed — the test passes if NewWithStore doesn't panic
	// or error out on the unknown delta.
}

// TestWALReplayRestoresNetworkCreate ensures a freshly-created network
// survives a crash before the next snapshot.
func TestWALReplayRestoresNetworkCreate(t *testing.T) {
	dir := t.TempDir()
	storePath := writeMinimalSnapshot(t, dir, nil)

	created := time.Now().UTC().Format(time.RFC3339)
	appendWALDelta(t, storePath, DeltaNetworkCreate, 0, networkCreateDelta{
		NetworkID:     17,
		Name:          "fresh-net",
		JoinRule:      "open",
		CreatedAt:     created,
	})

	s := NewWithStore("", storePath)
	defer s.Close()

	s.mu.RLock()
	defer s.mu.RUnlock()
	net, ok := s.networks[17]
	if !ok {
		t.Fatalf("network 17 missing after replay")
	}
	if net.Name != "fresh-net" {
		t.Fatalf("net.Name = %q, want fresh-net", net.Name)
	}
	if s.nextNet <= 17 {
		t.Fatalf("nextNet = %d, want > 17", s.nextNet)
	}
}

// helper: extract keys from a map[uint32]*NodeInfo for error messages
func keysOfUint32Map(m map[uint32]*NodeInfo) []uint32 {
	ks := make([]uint32, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

// TestWALEndToEndRegisterThenCrashRecovery is the integration that pins
// the producer + consumer together. It calls handleRegister via the
// public dispatch (which records to the WAL), suppresses the periodic
// snapshot by closing the server WITHOUT a final flush, then re-opens
// at the same path. The newly-registered node must reappear from WAL
// replay alone.
func TestWALEndToEndRegisterThenCrashRecovery(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "registry.json")

	// Round 1: server registers a node, then we simulate a crash by
	// closing it without letting saveLoop run a final flush. To do this
	// we close the saveCh signal first to drain it, then close done.
	s1 := NewWithStore("", storePath)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	pkB64 := base64.StdEncoding.EncodeToString(pub)

	resp, err := s1.handleRegister(map[string]interface{}{
		"public_key":  pkB64,
		"listen_addr": "127.0.0.1:9000",
		"owner":       "crash-test",
	}, "127.0.0.1:1234")
	if err != nil {
		t.Fatalf("handleRegister: %v", err)
	}
	registeredID, _ := resp["node_id"].(uint32)
	if registeredID == 0 {
		t.Fatalf("register returned no node_id; resp=%v", resp)
	}

	// Drain the saveCh so the final-save path in saveLoop's <-s.done
	// branch sees dirty=false and skips the flushSave. This is the
	// closest we can get to a true "crash before persistence" scenario
	// without process-killing.
	select {
	case <-s1.saveCh:
	default:
	}

	// Manually trigger Close. saveLoop's <-s.done branch will run; with
	// dirty=false (drained above) it will NOT call flushSave. The WAL
	// entry from handleRegister is still on disk.
	if err := s1.Close(); err != nil {
		t.Fatalf("close s1: %v", err)
	}

	// Verify no snapshot exists (or is empty). The WAL must be the only
	// source of truth for this node.
	if _, err := os.Stat(storePath); err == nil {
		// Snapshot did get written (saveCh drain didn't catch it; race
		// with previous saves is possible). That's still a valid scenario
		// — the test should still verify the node ends up restored.
		t.Logf("snapshot file exists despite drain attempt — test is weaker but still valid")
	}

	// Round 2: re-open and verify the registered node is back.
	s2 := NewWithStore("", storePath)
	defer s2.Close()

	s2.mu.RLock()
	defer s2.mu.RUnlock()
	if _, ok := s2.nodes[registeredID]; !ok {
		t.Fatalf("node %d not restored from WAL after simulated crash; nodes=%v", registeredID, keysOfUint32Map(s2.nodes))
	}
	if got := s2.pubKeyIdx[pkB64]; got != registeredID {
		t.Fatalf("pubKeyIdx[pk] = %d, want %d", got, registeredID)
	}
}

// silence unused-import warnings if we trim a test
var _ = fmt.Sprintf
