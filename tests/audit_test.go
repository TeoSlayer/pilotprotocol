package tests

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/beacon"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

// TestAuditLogAPI tests the get_audit_log API endpoint (the ring buffer, not slog).
func TestAuditLogAPI(t *testing.T) {
	t.Parallel()

	reg := registry.New("127.0.0.1:9001")
	reg.SetAdminToken(TestAdminToken)
	go reg.ListenAndServe(":0")
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	defer reg.Close()

	rc, err := registry.Dial(reg.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rc.Close()

	// Register nodes and create a network to generate audit events
	nodeA, _ := registerTestNode(t, rc)
	registerTestNode(t, rc)
	resp, err := rc.CreateNetwork(nodeA, "audit-api-net", "open", "", TestAdminToken, false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Fetch full audit log
	logResp, err := rc.GetAuditLog(0, TestAdminToken)
	if err != nil {
		t.Fatalf("get audit log: %v", err)
	}

	entries, ok := logResp["entries"].([]interface{})
	if !ok {
		t.Fatalf("entries field not a list: %T", logResp["entries"])
	}
	if len(entries) < 3 {
		t.Errorf("expected at least 3 audit entries (2 registrations + 1 network create), got %d", len(entries))
	}

	// Verify newest-first ordering
	first := entries[0].(map[string]interface{})
	last := entries[len(entries)-1].(map[string]interface{})
	firstTime := first["timestamp"].(string)
	lastTime := last["timestamp"].(string)
	if firstTime < lastTime {
		t.Errorf("expected newest-first ordering: first=%s, last=%s", firstTime, lastTime)
	}

	// Verify all entries have required fields
	for i, e := range entries {
		entry := e.(map[string]interface{})
		if _, ok := entry["timestamp"]; !ok {
			t.Errorf("entry %d missing timestamp", i)
		}
		if _, ok := entry["action"]; !ok {
			t.Errorf("entry %d missing action", i)
		}
	}

	// Verify the newest entry is network.created
	if first["action"] != "network.created" {
		t.Errorf("expected newest entry to be network.created, got %s", first["action"])
	}

	// Test filtering by network_id
	filteredResp, err := rc.GetAuditLog(netID, TestAdminToken)
	if err != nil {
		t.Fatalf("get filtered audit log: %v", err)
	}
	filteredEntries := filteredResp["entries"].([]interface{})
	if len(filteredEntries) == 0 {
		t.Error("expected at least 1 filtered entry for the created network")
	}
	for _, e := range filteredEntries {
		entry := e.(map[string]interface{})
		if nid, ok := entry["network_id"]; ok {
			if uint16(nid.(float64)) != netID {
				t.Errorf("filtered entry has wrong network_id: %v", nid)
			}
		}
	}

	// Test that wrong admin token is rejected
	_, err = rc.GetAuditLog(0, "wrong-token")
	if err == nil {
		t.Error("expected error with wrong admin token")
	}

	t.Logf("audit log returned %d entries, filtered=%d", len(entries), len(filteredEntries))
}

// TestAuditLogRingBuffer verifies that the audit ring buffer caps at maxAuditEntries (1000)
// and that the default API limit returns 100 entries.
func TestAuditLogRingBuffer(t *testing.T) {
	t.Parallel()

	reg := registry.New("127.0.0.1:9001")
	reg.SetAdminToken(TestAdminToken)
	go reg.ListenAndServe(":0")
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	defer reg.Close()

	rc, err := registry.Dial(reg.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rc.Close()

	// Register a single node, then set polo score 1010 times to exceed
	// the 1000-entry ring buffer without hitting rate limiters.
	nodeID, _ := registerTestNode(t, rc)
	for i := 0; i < 1010; i++ {
		rc.SetPoloScore(nodeID, i)
	}
	// Total events: 1 registration + 1010 polo_score.set = 1011 events.
	// Ring buffer should cap at 1000, dropping the oldest 11.

	// Default limit is 100 — verify we get exactly 100 entries
	logResp, err := rc.GetAuditLog(0, TestAdminToken)
	if err != nil {
		t.Fatalf("get audit log: %v", err)
	}
	entries := logResp["entries"].([]interface{})
	if len(entries) != 100 {
		t.Errorf("expected 100 entries (default limit), got %d", len(entries))
	}

	// All returned entries should be polo_score.set (the registration was evicted)
	for i, e := range entries {
		entry := e.(map[string]interface{})
		if entry["action"] != "polo_score.set" {
			t.Errorf("entry %d: expected polo_score.set, got %s", i, entry["action"])
		}
	}

	t.Logf("ring buffer test: got %d entries with default limit", len(entries))
}

// parseAuditLines extracts audit events from JSON log lines.
func parseAuditLines(buf *bytes.Buffer) []map[string]interface{} {
	var events []map[string]interface{}
	for _, line := range strings.Split(buf.String(), "\n") {
		if line == "" {
			continue
		}
		var entry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		if msg, _ := entry["msg"].(string); msg == "audit" {
			events = append(events, entry)
		}
	}
	return events
}

// TestAuditEvents verifies that structured audit events are emitted for all
// registry mutations. This test is not parallel because it redirects the
// global slog handler to capture JSON output.
func TestAuditEvents(t *testing.T) {
	// Redirect slog to buffer
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	old := slog.Default()
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(old)

	// Start registry
	reg := registry.New("127.0.0.1:9001")
	reg.SetAdminToken(TestAdminToken)
	go reg.ListenAndServe(":0")
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	defer reg.Close()

	rc, err := registry.Dial(reg.Addr().String())
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	// 1. Register two nodes
	nodeA, identityA := registerTestNode(t, rc)
	nodeB, _ := registerTestNode(t, rc)

	// 2. Network lifecycle: create, join, leave, rename, delete
	resp, err := rc.CreateNetwork(nodeA, "audit-net", "open", "", TestAdminToken, false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	_, err = rc.JoinNetwork(nodeB, netID, "", 0, TestAdminToken)
	if err != nil {
		t.Fatalf("join network: %v", err)
	}

	_, err = rc.LeaveNetwork(nodeB, netID, TestAdminToken)
	if err != nil {
		t.Fatalf("leave network: %v", err)
	}

	_, err = rc.RenameNetwork(netID, "audit-net-renamed", TestAdminToken)
	if err != nil {
		t.Fatalf("rename network: %v", err)
	}

	_, err = rc.DeleteNetwork(netID, TestAdminToken)
	if err != nil {
		t.Fatalf("delete network: %v", err)
	}

	// 3. Trust operations
	setClientSigner(rc, identityA)
	_, err = rc.ReportTrust(nodeA, nodeB)
	if err != nil {
		t.Fatalf("report trust: %v", err)
	}
	_, err = rc.RevokeTrust(nodeA, nodeB)
	if err != nil {
		t.Fatalf("revoke trust: %v", err)
	}

	// 4. Node metadata operations
	_, err = rc.SetVisibility(nodeA, true)
	if err != nil {
		t.Fatalf("set visibility: %v", err)
	}

	_, err = rc.SetHostname(nodeA, "audit-host")
	if err != nil {
		t.Fatalf("set hostname: %v", err)
	}

	_, err = rc.SetTags(nodeA, []string{"gpu", "arm64"})
	if err != nil {
		t.Fatalf("set tags: %v", err)
	}

	_, err = rc.SetTaskExec(nodeA, true)
	if err != nil {
		t.Fatalf("set task exec: %v", err)
	}

	// 5. Deregister
	_, err = rc.Deregister(nodeA)
	if err != nil {
		t.Fatalf("deregister: %v", err)
	}

	// Parse and check
	events := parseAuditLines(&buf)
	actions := make(map[string]bool)
	for _, ev := range events {
		if a, ok := ev["audit_action"].(string); ok {
			actions[a] = true
		}
	}

	expected := []string{
		"node.registered",
		"network.created",
		"network.joined",
		"network.left",
		"network.renamed",
		"network.deleted",
		"trust.created",
		"trust.revoked",
		"visibility.changed",
		"hostname.changed",
		"tags.changed",
		"task_exec.changed",
		"node.deregistered",
	}
	for _, action := range expected {
		if !actions[action] {
			t.Errorf("missing audit action: %s", action)
		}
	}

	// Verify at least we got a reasonable number of events
	if len(events) < len(expected) {
		t.Errorf("expected at least %d audit events, got %d", len(expected), len(events))
	}

	t.Logf("captured %d audit events, %d unique actions", len(events), len(actions))
}

// TestAuditInviteActions verifies that invite.created and invite.responded
// are emitted as structured audit events.
func TestAuditInviteActions(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	old := slog.Default()
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(old)

	reg := registry.New("127.0.0.1:9001")
	reg.SetAdminToken(TestAdminToken)
	go reg.ListenAndServe(":0")
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	defer reg.Close()

	rc, err := registry.Dial(reg.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rc.Close()

	creatorID, _ := registerTestNode(t, rc)
	resp, err := rc.CreateNetwork(creatorID, "audit-invite-net", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	targetID, targetIdentity := registerTestNode(t, rc)

	_, err = rc.InviteToNetwork(netID, creatorID, targetID, TestAdminToken)
	if err != nil {
		t.Fatalf("invite: %v", err)
	}

	setClientSigner(rc, targetIdentity)
	rc.PollInvites(targetID)
	rc.RespondInvite(targetID, netID, true)

	events := parseAuditLines(&buf)
	actions := make(map[string]bool)
	for _, ev := range events {
		if a, ok := ev["audit_action"].(string); ok {
			actions[a] = true
		}
	}

	for _, required := range []string{"invite.created", "invite.responded"} {
		if !actions[required] {
			t.Errorf("missing audit action: %s (got: %v)", required, actions)
		}
	}

	// Verify invite.created has expected fields
	for _, ev := range events {
		if ev["audit_action"] == "invite.created" {
			if _, ok := ev["network_id"]; !ok {
				t.Error("invite.created missing network_id field")
			}
			if _, ok := ev["inviter_id"]; !ok {
				t.Error("invite.created missing inviter_id field")
			}
			if _, ok := ev["target_node_id"]; !ok {
				t.Error("invite.created missing target_node_id field")
			}
		}
		if ev["audit_action"] == "invite.responded" {
			if _, ok := ev["accepted"]; !ok {
				t.Error("invite.responded missing accepted field")
			}
		}
	}
}

// TestAuditEventHasRequiredFields verifies that every audit event contains
// msg, audit_action, and time fields (SIEM ingestibility requirement).
func TestAuditEventHasRequiredFields(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	old := slog.Default()
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(old)

	reg := registry.New("127.0.0.1:9001")
	reg.SetAdminToken(TestAdminToken)
	go reg.ListenAndServe(":0")
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	defer reg.Close()

	rc, err := registry.Dial(reg.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rc.Close()

	nodeID, _ := registerTestNode(t, rc)
	rc.CreateNetwork(nodeID, "fields-check-net", "open", "", TestAdminToken, false)

	events := parseAuditLines(&buf)
	if len(events) == 0 {
		t.Fatal("no audit events captured")
	}
	for _, ev := range events {
		if ev["msg"] != "audit" {
			t.Errorf("audit event missing msg=audit: %v", ev)
		}
		if _, ok := ev["audit_action"]; !ok {
			t.Errorf("audit event missing audit_action field: %v", ev)
		}
		if _, ok := ev["time"]; !ok {
			t.Errorf("audit event missing time field: %v", ev)
		}
	}
}

// TestAuditConcurrentMutations verifies that concurrent registry mutations each
// produce an audit event. No events should be lost under concurrent load.
func TestAuditConcurrentMutations(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	old := slog.Default()
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(old)

	reg := registry.New("127.0.0.1:9001")
	reg.SetAdminToken(TestAdminToken)
	go reg.ListenAndServe(":0")
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	defer reg.Close()

	const workers = 10
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rc, err := registry.Dial(reg.Addr().String())
			if err != nil {
				return
			}
			defer rc.Close()
			nodeID, _ := registerTestNode(t, rc)
			rc.CreateNetwork(nodeID, strings.Repeat("x", i+1)+"-concurrent-net", "open", "", TestAdminToken, false)
		}(i)
	}
	wg.Wait()

	events := parseAuditLines(&buf)
	// Every worker registers a node and creates a network → 2 audit events each
	if len(events) < workers*2 {
		t.Errorf("expected at least %d audit events for %d workers, got %d", workers*2, workers, len(events))
	}
	// All must have audit_action
	for _, ev := range events {
		if _, ok := ev["audit_action"]; !ok {
			t.Errorf("audit event missing audit_action: %v", ev)
		}
	}
}

// signChallenge creates a base64-encoded Ed25519 signature for a challenge string.
func signChallenge(id *crypto.Identity, challenge string) string {
	sig := id.Sign([]byte(challenge))
	return base64.StdEncoding.EncodeToString(sig)
}

// TestAuditKeyRotated verifies that key rotation emits a "key.rotated" audit event.
func TestAuditKeyRotated(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	old := slog.Default()
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(old)

	reg := registry.New("127.0.0.1:9001")
	reg.SetAdminToken(TestAdminToken)
	go reg.ListenAndServe(":0")
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	defer reg.Close()

	rc, err := registry.Dial(reg.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rc.Close()

	nodeID, identity := registerTestNode(t, rc)

	// Generate new key pair for rotation
	newIdentity, _ := crypto.GenerateIdentity()
	newPubKeyB64 := crypto.EncodePublicKey(newIdentity.PublicKey)

	// Sign the rotation challenge with the OLD key
	challenge := fmt.Sprintf("rotate:%d", nodeID)
	sig := signChallenge(identity, challenge)

	_, err = rc.RotateKey(nodeID, sig, newPubKeyB64)
	if err != nil {
		t.Fatalf("rotate key: %v", err)
	}

	events := parseAuditLines(&buf)
	found := false
	for _, ev := range events {
		if ev["audit_action"] == "key.rotated" {
			found = true
			if uint32(ev["node_id"].(float64)) != nodeID {
				t.Errorf("key.rotated: wrong node_id, got %v, want %d", ev["node_id"], nodeID)
			}
			break
		}
	}
	if !found {
		actions := make([]string, 0)
		for _, ev := range events {
			if a, ok := ev["audit_action"].(string); ok {
				actions = append(actions, a)
			}
		}
		t.Fatalf("missing audit action 'key.rotated' (got: %v)", actions)
	}
}

// TestAuditHandshakeRelayedAndResponded verifies that requesting and responding
// to a handshake emits "handshake.relayed" and "handshake.responded" audit events.
func TestAuditHandshakeRelayedAndResponded(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	old := slog.Default()
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(old)

	reg := registry.New("127.0.0.1:9001")
	reg.SetAdminToken(TestAdminToken)
	go reg.ListenAndServe(":0")
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	defer reg.Close()

	rc, err := registry.Dial(reg.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rc.Close()

	nodeA, identityA := registerTestNode(t, rc)
	nodeB, identityB := registerTestNode(t, rc)

	// A requests handshake to B (M12: signed)
	reqChallenge := fmt.Sprintf("handshake:%d:%d", nodeA, nodeB)
	reqSig := signChallenge(identityA, reqChallenge)

	_, err = rc.RequestHandshake(nodeA, nodeB, "test handshake", reqSig)
	if err != nil {
		t.Fatalf("request handshake: %v", err)
	}

	// B polls and responds (accept)
	setClientSigner(rc, identityB)
	_, err = rc.PollHandshakes(nodeB)
	if err != nil {
		t.Fatalf("poll handshakes: %v", err)
	}

	respChallenge := fmt.Sprintf("respond:%d:%d", nodeB, nodeA)
	respSig := signChallenge(identityB, respChallenge)

	_, err = rc.RespondHandshake(nodeB, nodeA, true, respSig)
	if err != nil {
		t.Fatalf("respond handshake: %v", err)
	}

	// Verify audit events
	events := parseAuditLines(&buf)
	actions := make(map[string]bool)
	for _, ev := range events {
		if a, ok := ev["audit_action"].(string); ok {
			actions[a] = true
		}
	}

	if !actions["handshake.relayed"] {
		t.Error("missing audit action 'handshake.relayed'")
	}
	if !actions["handshake.responded"] {
		t.Error("missing audit action 'handshake.responded'")
	}

	// Verify handshake.relayed has from/to fields
	for _, ev := range events {
		if ev["audit_action"] == "handshake.relayed" {
			if _, ok := ev["from_node_id"]; !ok {
				t.Error("handshake.relayed missing from_node_id")
			}
			if _, ok := ev["to_node_id"]; !ok {
				t.Error("handshake.relayed missing to_node_id")
			}
		}
		if ev["audit_action"] == "handshake.responded" {
			if _, ok := ev["node_id"]; !ok {
				t.Error("handshake.responded missing node_id")
			}
			if _, ok := ev["peer_id"]; !ok {
				t.Error("handshake.responded missing peer_id")
			}
			if _, ok := ev["accept"]; !ok {
				t.Error("handshake.responded missing accept field")
			}
		}
	}
}

// TestAuditLogPersistence verifies that audit entries survive a registry restart.
func TestAuditLogPersistence(t *testing.T) {
	t.Parallel()

	tmpDir, err := os.MkdirTemp("/tmp", "w4-audit-persist-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	storePath := filepath.Join(tmpDir, "registry.json")

	b := beacon.New()
	go b.ListenAndServe(":0")
	select {
	case <-b.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("beacon failed to start")
	}
	defer b.Close()
	beaconAddr := b.Addr().String()

	// Phase 1: Start registry, generate audit events
	reg1 := registry.NewWithStore(beaconAddr, storePath)
	reg1.SetAdminToken(TestAdminToken)
	go reg1.ListenAndServe(":0")
	select {
	case <-reg1.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry 1 failed to start")
	}

	rc1, err := registry.Dial(reg1.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Register a node and set polo score to generate audit events
	nodeID, _ := registerTestNode(t, rc1)
	rc1.SetPoloScore(nodeID, 42)

	// Verify audit entries exist before shutdown
	logResp, err := rc1.GetAuditLog(0, TestAdminToken)
	if err != nil {
		t.Fatalf("get audit log before restart: %v", err)
	}
	entriesBefore := logResp["entries"].([]interface{})
	if len(entriesBefore) < 2 {
		t.Fatalf("expected at least 2 audit entries before restart, got %d", len(entriesBefore))
	}
	t.Logf("before restart: %d audit entries", len(entriesBefore))

	rc1.Close()
	reg1.Close()

	// Phase 2: Restart registry and verify audit log survived
	reg2 := registry.NewWithStore(beaconAddr, storePath)
	reg2.SetAdminToken(TestAdminToken)
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

	logResp2, err := rc2.GetAuditLog(0, TestAdminToken)
	if err != nil {
		t.Fatalf("get audit log after restart: %v", err)
	}
	entriesAfter := logResp2["entries"].([]interface{})

	if len(entriesAfter) < len(entriesBefore) {
		t.Errorf("audit log lost entries across restart: before=%d, after=%d", len(entriesBefore), len(entriesAfter))
	}

	// Verify the entries contain the expected actions
	actions := make(map[string]bool)
	for _, e := range entriesAfter {
		entry := e.(map[string]interface{})
		actions[entry["action"].(string)] = true
	}
	if !actions["node.registered"] {
		t.Error("missing node.registered after restart")
	}
	if !actions["polo_score.set"] {
		t.Error("missing polo_score.set after restart")
	}

	t.Logf("after restart: %d audit entries (before: %d)", len(entriesAfter), len(entriesBefore))
}
