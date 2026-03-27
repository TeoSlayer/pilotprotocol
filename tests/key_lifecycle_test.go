package tests

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

// TestKeyInfoOnRegister verifies that registering a node populates
// created_at in the key metadata and that rotate_count starts at 0.
func TestKeyInfoOnRegister(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	before := time.Now().Add(-1 * time.Second)

	id, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	after := time.Now().Add(1 * time.Second)

	// Query key info
	info, err := rc.GetKeyInfo(nodeID)
	if err != nil {
		t.Fatalf("get_key_info: %v", err)
	}

	// Verify type
	if info["type"] != "get_key_info_ok" {
		t.Errorf("unexpected type: %v", info["type"])
	}

	// Verify created_at is set and recent
	createdAtStr, ok := info["created_at"].(string)
	if !ok || createdAtStr == "" {
		t.Fatal("created_at not set in key info")
	}
	createdAt, err := time.Parse(time.RFC3339, createdAtStr)
	if err != nil {
		t.Fatalf("parse created_at: %v", err)
	}
	if createdAt.Before(before) || createdAt.After(after) {
		t.Errorf("created_at %v not in expected range [%v, %v]", createdAt, before, after)
	}

	// Verify rotate_count is 0
	rotateCount := int(info["rotate_count"].(float64))
	if rotateCount != 0 {
		t.Errorf("rotate_count = %d, want 0", rotateCount)
	}

	// Verify rotated_at is not set
	if _, ok := info["rotated_at"]; ok {
		t.Error("rotated_at should not be set for a freshly registered node")
	}

	// Verify key_age_days is 0 (just registered)
	keyAgeDays := int(info["key_age_days"].(float64))
	if keyAgeDays != 0 {
		t.Errorf("key_age_days = %d, want 0", keyAgeDays)
	}

	t.Logf("key info after register: created_at=%s, rotate_count=%d, key_age_days=%d",
		createdAtStr, rotateCount, keyAgeDays)
}

// TestKeyInfoOnRotate verifies that rotating a key updates rotated_at
// and increments rotate_count.
func TestKeyInfoOnRotate(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	id, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Rotate key
	newID, _ := crypto.GenerateIdentity()
	challenge := fmt.Sprintf("rotate:%d", nodeID)
	sig := id.Sign([]byte(challenge))
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	newPubKeyB64 := crypto.EncodePublicKey(newID.PublicKey)

	beforeRotate := time.Now().Add(-1 * time.Second)

	_, err = rc.RotateKey(nodeID, sigB64, newPubKeyB64)
	if err != nil {
		t.Fatalf("rotate key: %v", err)
	}

	afterRotate := time.Now().Add(1 * time.Second)

	// Query key info
	info, err := rc.GetKeyInfo(nodeID)
	if err != nil {
		t.Fatalf("get_key_info: %v", err)
	}

	// Verify rotated_at is set and recent
	rotatedAtStr, ok := info["rotated_at"].(string)
	if !ok || rotatedAtStr == "" {
		t.Fatal("rotated_at not set after rotation")
	}
	rotatedAt, err := time.Parse(time.RFC3339, rotatedAtStr)
	if err != nil {
		t.Fatalf("parse rotated_at: %v", err)
	}
	if rotatedAt.Before(beforeRotate) || rotatedAt.After(afterRotate) {
		t.Errorf("rotated_at %v not in expected range [%v, %v]", rotatedAt, beforeRotate, afterRotate)
	}

	// Verify rotate_count is 1
	rotateCount := int(info["rotate_count"].(float64))
	if rotateCount != 1 {
		t.Errorf("rotate_count = %d, want 1", rotateCount)
	}

	t.Logf("key info after rotate: rotated_at=%s, rotate_count=%d", rotatedAtStr, rotateCount)

	// Rotate again with new identity
	newID2, _ := crypto.GenerateIdentity()
	challenge2 := fmt.Sprintf("rotate:%d", nodeID)
	sig2 := newID.Sign([]byte(challenge2))
	sigB642 := base64.StdEncoding.EncodeToString(sig2)
	newPubKeyB642 := crypto.EncodePublicKey(newID2.PublicKey)

	_, err = rc.RotateKey(nodeID, sigB642, newPubKeyB642)
	if err != nil {
		t.Fatalf("second rotate key: %v", err)
	}

	info2, err := rc.GetKeyInfo(nodeID)
	if err != nil {
		t.Fatalf("get_key_info after second rotate: %v", err)
	}

	rotateCount2 := int(info2["rotate_count"].(float64))
	if rotateCount2 != 2 {
		t.Errorf("rotate_count after second rotation = %d, want 2", rotateCount2)
	}
}

// TestKeyExpirySet verifies that set_key_expiry updates the key expiry.
func TestKeyExpirySet(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	id, _ := crypto.GenerateIdentity()
	setClientSigner(rc, id)

	resp, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Set expiry to 7 days from now
	expiresAt := time.Now().Add(7 * 24 * time.Hour).UTC().Truncate(time.Second)

	setResp, err := rc.SetKeyExpiry(nodeID, expiresAt)
	if err != nil {
		t.Fatalf("set_key_expiry: %v", err)
	}
	if setResp["type"] != "set_key_expiry_ok" {
		t.Errorf("unexpected type: %v", setResp["type"])
	}

	// Query key info to verify
	info, err := rc.GetKeyInfo(nodeID)
	if err != nil {
		t.Fatalf("get_key_info: %v", err)
	}

	expiresAtStr, ok := info["expires_at"].(string)
	if !ok || expiresAtStr == "" {
		t.Fatal("expires_at not set in key info")
	}
	parsed, err := time.Parse(time.RFC3339, expiresAtStr)
	if err != nil {
		t.Fatalf("parse expires_at: %v", err)
	}

	// Allow 1 second tolerance for RFC3339 rounding
	diff := parsed.Sub(expiresAt)
	if diff < -1*time.Second || diff > 1*time.Second {
		t.Errorf("expires_at mismatch: got %v, want %v (diff=%v)", parsed, expiresAt, diff)
	}

	t.Logf("key expiry set: %s", expiresAtStr)
}

// TestKeyExpiryRejectPast verifies that setting an expiry in the past is rejected.
func TestKeyExpiryRejectPast(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	id, _ := crypto.GenerateIdentity()
	setClientSigner(rc, id)

	resp, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Set expiry to 1 hour in the past
	pastTime := time.Now().Add(-1 * time.Hour)

	_, err = rc.SetKeyExpiry(nodeID, pastTime)
	if err == nil {
		t.Fatal("set_key_expiry with past time should fail")
	}
	t.Logf("correctly rejected past expiry: %v", err)
}

// TestKeyExpiryWarningInHeartbeat verifies that a heartbeat response includes
// a key_expiry_warning when the key is within 24 hours of expiry.
func TestKeyExpiryWarningInHeartbeat(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	id, _ := crypto.GenerateIdentity()
	setClientSigner(rc, id)

	resp, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Set expiry to 12 hours from now (within the 24-hour warning window)
	expiresAt := time.Now().Add(12 * time.Hour)

	_, err = rc.SetKeyExpiry(nodeID, expiresAt)
	if err != nil {
		t.Fatalf("set_key_expiry: %v", err)
	}

	// Send heartbeat
	hbResp, err := rc.Heartbeat(nodeID)
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}

	// Verify warning is present
	warning, ok := hbResp["key_expiry_warning"].(bool)
	if !ok || !warning {
		t.Errorf("expected key_expiry_warning=true in heartbeat response, got %v", hbResp["key_expiry_warning"])
	}
	t.Logf("heartbeat response with expiry warning: %v", hbResp)

	// Now set expiry far in the future and verify no warning
	farFuture := time.Now().Add(30 * 24 * time.Hour)
	_, err = rc.SetKeyExpiry(nodeID, farFuture)
	if err != nil {
		t.Fatalf("set_key_expiry (far future): %v", err)
	}

	hbResp2, err := rc.Heartbeat(nodeID)
	if err != nil {
		t.Fatalf("heartbeat 2: %v", err)
	}

	if _, hasWarning := hbResp2["key_expiry_warning"]; hasWarning {
		t.Error("key_expiry_warning should not be present when expiry is far in the future")
	}
}

// TestKeyAgeDaysInResolve verifies that resolve includes key_age_days.
func TestKeyAgeDaysInResolve(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	// Register two nodes (resolver and target)
	id1, _ := crypto.GenerateIdentity()
	setClientSigner(rc, id1)
	resp1, err := rc.RegisterWithKey("127.0.0.1:5001", crypto.EncodePublicKey(id1.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register node 1: %v", err)
	}
	nodeID1 := uint32(resp1["node_id"].(float64))

	id2, _ := crypto.GenerateIdentity()
	resp2, err := rc.RegisterWithKey("127.0.0.1:5002", crypto.EncodePublicKey(id2.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register node 2: %v", err)
	}
	nodeID2 := uint32(resp2["node_id"].(float64))

	// Make node 2 public so node 1 can resolve it
	setClientSigner(rc, id2)
	_, err = rc.SetVisibility(nodeID2, true)
	if err != nil {
		t.Fatalf("set visibility: %v", err)
	}

	// Resolve node 2 from node 1
	setClientSigner(rc, id1)
	resolveResp, err := rc.Resolve(nodeID2, nodeID1)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	// Just registered — key_age_days should be 0
	keyAgeDays, ok := resolveResp["key_age_days"].(float64)
	if !ok {
		t.Fatal("key_age_days not found in resolve response")
	}
	if int(keyAgeDays) != 0 {
		t.Errorf("key_age_days = %d, want 0 (just registered)", int(keyAgeDays))
	}
	t.Logf("resolve response key_age_days: %d", int(keyAgeDays))
}

// TestKeyInfoPersistence verifies that key metadata survives a registry restart.
func TestKeyInfoPersistence(t *testing.T) {
	t.Parallel()
	tmpDir, err := os.MkdirTemp("/tmp", "w4-keylife-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	storePath := filepath.Join(tmpDir, "registry.json")

	// Phase 1: start registry, register node, rotate key, set expiry
	reg1 := registry.NewWithStore("127.0.0.1:9001", storePath)
	go reg1.ListenAndServe(":0")
	select {
	case <-reg1.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry 1 failed to start")
	}

	regAddr := reg1.Addr().String()

	rc, err := registry.Dial(regAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}

	id, _ := crypto.GenerateIdentity()
	setClientSigner(rc, id)
	resp, err := rc.RegisterWithKey("", crypto.EncodePublicKey(id.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	// Rotate key
	newID, _ := crypto.GenerateIdentity()
	challenge := fmt.Sprintf("rotate:%d", nodeID)
	sig := id.Sign([]byte(challenge))
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	newPubKeyB64 := crypto.EncodePublicKey(newID.PublicKey)

	_, err = rc.RotateKey(nodeID, sigB64, newPubKeyB64)
	if err != nil {
		t.Fatalf("rotate key: %v", err)
	}

	// Set expiry
	setClientSigner(rc, newID)
	expiresAt := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	_, err = rc.SetKeyExpiry(nodeID, expiresAt)
	if err != nil {
		t.Fatalf("set_key_expiry: %v", err)
	}

	// Verify metadata before restart
	infoBefore, err := rc.GetKeyInfo(nodeID)
	if err != nil {
		t.Fatalf("get_key_info before restart: %v", err)
	}
	t.Logf("before restart: %v", infoBefore)

	// Force snapshot and close
	if err := reg1.TriggerSnapshot(); err != nil {
		t.Fatalf("trigger snapshot: %v", err)
	}
	rc.Close()
	reg1.Close()

	// Verify store file exists
	data, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	t.Logf("store file: %d bytes", len(data))

	// Phase 2: start new registry from the same store file
	reg2 := registry.NewWithStore("127.0.0.1:9001", storePath)
	go reg2.ListenAndServe(":0")
	select {
	case <-reg2.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry 2 failed to start")
	}
	defer reg2.Close()

	rc2, err := registry.Dial(reg2.Addr().String())
	if err != nil {
		t.Fatalf("dial registry 2: %v", err)
	}
	defer rc2.Close()

	// Get key info after restart
	infoAfter, err := rc2.GetKeyInfo(nodeID)
	if err != nil {
		t.Fatalf("get_key_info after restart: %v", err)
	}
	t.Logf("after restart: %v", infoAfter)

	// Verify created_at persisted
	if infoBefore["created_at"] != infoAfter["created_at"] {
		t.Errorf("created_at mismatch: before=%v, after=%v",
			infoBefore["created_at"], infoAfter["created_at"])
	}

	// Verify rotated_at persisted
	if infoBefore["rotated_at"] != infoAfter["rotated_at"] {
		t.Errorf("rotated_at mismatch: before=%v, after=%v",
			infoBefore["rotated_at"], infoAfter["rotated_at"])
	}

	// Verify rotate_count persisted
	if infoBefore["rotate_count"] != infoAfter["rotate_count"] {
		t.Errorf("rotate_count mismatch: before=%v, after=%v",
			infoBefore["rotate_count"], infoAfter["rotate_count"])
	}
	rotateCount := int(infoAfter["rotate_count"].(float64))
	if rotateCount != 1 {
		t.Errorf("rotate_count = %d, want 1", rotateCount)
	}

	// Verify expires_at persisted
	if infoBefore["expires_at"] != infoAfter["expires_at"] {
		t.Errorf("expires_at mismatch: before=%v, after=%v",
			infoBefore["expires_at"], infoAfter["expires_at"])
	}
}
