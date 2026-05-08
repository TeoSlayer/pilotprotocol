// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
)

// ---------------------------------------------------------------------------
// resolveLocalAddr — pure function, five branches.
// ---------------------------------------------------------------------------

func TestResolveLocalAddrBadInputReturnsAsIs(t *testing.T) {
	t.Parallel()
	// No colon → SplitHostPort errors → addr returned unchanged.
	if got := resolveLocalAddr("bad-no-port"); got != "bad-no-port" {
		t.Errorf("bad addr should pass through: got %q", got)
	}
}

func TestResolveLocalAddrEmptyHost(t *testing.T) {
	t.Parallel()
	if got := resolveLocalAddr(":4000"); got != "127.0.0.1:4000" {
		t.Errorf("empty host: got %q, want 127.0.0.1:4000", got)
	}
}

func TestResolveLocalAddrWildcardIPv4(t *testing.T) {
	t.Parallel()
	if got := resolveLocalAddr("0.0.0.0:9090"); got != "127.0.0.1:9090" {
		t.Errorf("0.0.0.0 host: got %q, want 127.0.0.1:9090", got)
	}
}

func TestResolveLocalAddrWildcardIPv6(t *testing.T) {
	t.Parallel()
	if got := resolveLocalAddr("[::]:1234"); got != "[::1]:1234" {
		t.Errorf(":: host: got %q, want [::1]:1234", got)
	}
}

func TestResolveLocalAddrLiteralIPReturnsUnchanged(t *testing.T) {
	t.Parallel()
	if got := resolveLocalAddr("10.0.0.5:80"); got != "10.0.0.5:80" {
		t.Errorf("literal IP should pass through: got %q", got)
	}
	if got := resolveLocalAddr("[2001:db8::1]:80"); got != "[2001:db8::1]:80" {
		t.Errorf("literal IPv6 should pass through: got %q", got)
	}
}

// ---------------------------------------------------------------------------
// nodeNetworks — returns uint16 slice from registry Lookup.
// ---------------------------------------------------------------------------

func TestNodeNetworksLookupErrorReturnsNil(t *testing.T) {
	t.Parallel()
	client, cleanup := startFakeRegistry(t, func(map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"error": "denied"}
	})
	defer cleanup()

	d := &Daemon{regConn: client, config: Config{AdminToken: "tok"}, nodeID: 99}
	if got := d.nodeNetworks(); got != nil {
		t.Errorf("error from registry must yield nil slice, got %v", got)
	}
}

func TestNodeNetworksParsesFloat64Entries(t *testing.T) {
	t.Parallel()
	client, cleanup := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		if req["type"] != "lookup" {
			return map[string]interface{}{"error": "unexpected method"}
		}
		return map[string]interface{}{
			"networks": []interface{}{float64(5), float64(7), "ignored-string", float64(65535)},
		}
	})
	defer cleanup()

	d := &Daemon{regConn: client, nodeID: 99}
	got := d.nodeNetworks()
	want := []uint16{5, 7, 65535}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (got %v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("nets[%d] = %d, want %d", i, got[i], want[i])
		}
	}
}

func TestNodeNetworksMissingFieldReturnsEmpty(t *testing.T) {
	t.Parallel()
	client, cleanup := startFakeRegistry(t, func(map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"node_id": float64(99)}
	})
	defer cleanup()

	d := &Daemon{regConn: client, nodeID: 99}
	got := d.nodeNetworks()
	if len(got) != 0 {
		t.Errorf("missing networks field must yield empty, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// lookupPeerPubKey — fetches Ed25519 pubkey from registry Lookup.
// ---------------------------------------------------------------------------

func TestLookupPeerPubKeyLookupError(t *testing.T) {
	t.Parallel()
	client, cleanup := startFakeRegistry(t, func(map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"error": "not found"}
	})
	defer cleanup()

	d := &Daemon{regConn: client}
	key, err := d.lookupPeerPubKey(42)
	if err == nil {
		t.Error("expected error on registry lookup failure")
	}
	if key != nil {
		t.Error("expected nil key on error")
	}
}

func TestLookupPeerPubKeyMissingField(t *testing.T) {
	t.Parallel()
	client, cleanup := startFakeRegistry(t, func(map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{}
	})
	defer cleanup()

	d := &Daemon{regConn: client}
	_, err := d.lookupPeerPubKey(42)
	if err == nil {
		t.Error("expected error when public_key field missing")
	} else if !strings.Contains(err.Error(), "no public key") {
		t.Errorf("error should mention missing key, got: %v", err)
	}
}

func TestLookupPeerPubKeyEmptyString(t *testing.T) {
	t.Parallel()
	client, cleanup := startFakeRegistry(t, func(map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"public_key": ""}
	})
	defer cleanup()

	d := &Daemon{regConn: client}
	_, err := d.lookupPeerPubKey(42)
	if err == nil {
		t.Error("expected error on empty public_key")
	}
}

func TestLookupPeerPubKeyHappyPath(t *testing.T) {
	t.Parallel()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	encoded := crypto.EncodePublicKey(id.PublicKey)
	if _, err := base64.StdEncoding.DecodeString(encoded); err != nil {
		t.Fatalf("encoded pubkey not valid base64: %v", err)
	}

	client, cleanup := startFakeRegistry(t, func(map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"public_key": encoded}
	})
	defer cleanup()

	d := &Daemon{regConn: client}
	got, err := d.lookupPeerPubKey(42)
	if err != nil {
		t.Fatalf("lookupPeerPubKey: %v", err)
	}
	if len(got) != len(id.PublicKey) {
		t.Errorf("returned key length = %d, want %d", len(got), len(id.PublicKey))
	}
	for i := range id.PublicKey {
		if got[i] != id.PublicKey[i] {
			t.Errorf("byte %d mismatch: got %x want %x", i, got[i], id.PublicKey[i])
			break
		}
	}
}

// ---------------------------------------------------------------------------
// saveNetworkSnapshot / loadNetworkSnapshot — file I/O round-trip.
// ---------------------------------------------------------------------------

func TestSaveNetworkSnapshotEmptyIdentityPathNoop(t *testing.T) {
	t.Parallel()
	d := New(Config{}) // IdentityPath empty
	d.saveNetworkSnapshot([]uint16{1, 2, 3})
}

func TestLoadNetworkSnapshotEmptyIdentityPathNoop(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	d.loadNetworkSnapshot()
}

func TestLoadNetworkSnapshotMissingFileNoop(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	d := New(Config{IdentityPath: filepath.Join(dir, "id.json")})
	d.loadNetworkSnapshot()
	if len(d.netPolicies) != 0 {
		t.Error("no-file load should not populate policies")
	}
}

func TestLoadNetworkSnapshotMalformedJSONLogged(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "networks.json"), []byte("not-json"), 0600); err != nil {
		t.Fatalf("seed bad file: %v", err)
	}
	d := New(Config{IdentityPath: filepath.Join(dir, "id.json")})
	d.loadNetworkSnapshot()
	if len(d.netPolicies) != 0 {
		t.Error("malformed JSON must not populate policies")
	}
}

func TestSaveAndLoadNetworkSnapshotRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	idPath := filepath.Join(dir, "id.json")

	d := New(Config{IdentityPath: idPath})
	d.netPolicies[1] = []uint16{80, 443}
	d.netPolicies[2] = []uint16{22}
	d.memberTags[1] = []string{"admin", "test"}
	d.memberTags[2] = []string{"bot"}
	d.saveNetworkSnapshot([]uint16{1, 2})

	snapPath := filepath.Join(dir, "networks.json")
	if _, err := os.Stat(snapPath); err != nil {
		t.Fatalf("snapshot file missing: %v", err)
	}

	d2 := New(Config{IdentityPath: idPath})
	d2.loadNetworkSnapshot()
	if got, want := d2.netPolicies[1], []uint16{80, 443}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("policies[1] = %v, want %v", got, want)
	}
	if got, want := d2.netPolicies[2], []uint16{22}; len(got) != len(want) || got[0] != want[0] {
		t.Errorf("policies[2] = %v, want %v", got, want)
	}
	if got, want := d2.memberTags[1], []string{"admin", "test"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("tags[1] = %v, want %v", got, want)
	}
}

func TestLoadNetworkSnapshotDoesNotOverwriteExistingPolicies(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	idPath := filepath.Join(dir, "id.json")

	// Seed snapshot on disk.
	d := New(Config{IdentityPath: idPath})
	d.netPolicies[1] = []uint16{22}
	d.memberTags[1] = []string{"from-disk"}
	d.saveNetworkSnapshot([]uint16{1})

	// New daemon with pre-populated live state — load must NOT overwrite.
	d2 := New(Config{IdentityPath: idPath})
	d2.netPolicies[1] = []uint16{999}
	d2.memberTags[1] = []string{"live"}
	d2.loadNetworkSnapshot()

	if got := d2.netPolicies[1]; len(got) != 1 || got[0] != 999 {
		t.Errorf("existing policy must not be overwritten: got %v, want [999]", got)
	}
	if got := d2.memberTags[1]; len(got) != 1 || got[0] != "live" {
		t.Errorf("existing tags must not be overwritten: got %v, want [live]", got)
	}
}

// ---------------------------------------------------------------------------
// Info — pure snapshot aggregator over a minimal Daemon.
// ---------------------------------------------------------------------------

func TestInfoReturnsSnapshotForFreshDaemon(t *testing.T) {
	t.Parallel()
	client, cleanup := startFakeRegistry(t, func(map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"error": "denied"}
	})
	defer cleanup()

	d := New(Config{
		Hostname: "testbox",
		Email:    "ci@example.com",
		Version:  "v0.0.0-test",
		Encrypt:  false,
	})
	d.regConn = client
	d.nodeID = 7
	d.addr.Network = 0
	d.addr.Node = 7

	info := d.Info()
	if info == nil {
		t.Fatal("Info returned nil")
	}
	if info.NodeID != 7 {
		t.Errorf("NodeID = %d, want 7", info.NodeID)
	}
	if info.Hostname != "testbox" {
		t.Errorf("Hostname = %q, want testbox", info.Hostname)
	}
	if info.Email != "ci@example.com" {
		t.Errorf("Email = %q, want ci@example.com", info.Email)
	}
	if info.Version != "v0.0.0-test" {
		t.Errorf("Version = %q, want v0.0.0-test", info.Version)
	}
	if info.Identity {
		t.Error("Identity should be false when IdentityPath is empty")
	}
	if info.PublicKey != "" {
		t.Errorf("PublicKey should be empty for no-identity daemon; got %q", info.PublicKey)
	}
	if info.Connections != 0 {
		t.Errorf("Connections = %d, want 0 on fresh daemon", info.Connections)
	}
	if info.Ports != 0 {
		t.Errorf("Ports = %d, want 0 on fresh daemon", info.Ports)
	}
	if info.Peers != 0 {
		t.Errorf("Peers = %d, want 0 on fresh daemon", info.Peers)
	}
	if info.Encrypt {
		t.Error("Encrypt should reflect config=false")
	}
	if len(info.Networks) != 0 {
		t.Errorf("Networks = %v, want [] for denied lookup", info.Networks)
	}
	if info.Uptime < 0 {
		t.Errorf("Uptime must be non-negative, got %v", info.Uptime)
	}
}

func TestInfoHasIdentityTrueWhenIdentityPathSet(t *testing.T) {
	t.Parallel()
	client, cleanup := startFakeRegistry(t, func(map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"error": "denied"}
	})
	defer cleanup()
	d := New(Config{IdentityPath: "/does/not/exist/id.json"})
	d.regConn = client
	info := d.Info()
	if !info.Identity {
		t.Error("Identity should be true when IdentityPath is set")
	}
}

func TestInfoIncludesNetworkMembershipsSkippingBackbone(t *testing.T) {
	t.Parallel()
	client, cleanup := startFakeRegistry(t, func(map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{
			"networks": []interface{}{float64(0), float64(3), float64(5)},
		}
	})
	defer cleanup()

	d := New(Config{})
	d.regConn = client
	d.nodeID = 12
	info := d.Info()
	// Network 0 is backbone → filtered. Expect 2 memberships.
	if len(info.Networks) != 2 {
		t.Fatalf("Networks len = %d, want 2 (got %v)", len(info.Networks), info.Networks)
	}
	if info.Networks[0].NetworkID != 3 {
		t.Errorf("Networks[0].NetworkID = %d, want 3", info.Networks[0].NetworkID)
	}
	if info.Networks[1].NetworkID != 5 {
		t.Errorf("Networks[1].NetworkID = %d, want 5", info.Networks[1].NetworkID)
	}
}
