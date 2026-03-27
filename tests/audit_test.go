package tests

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

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
	resp, err := rc.CreateNetwork(nodeA, "audit-net", "open", "", TestAdminToken)
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
	resp, err := rc.CreateNetwork(creatorID, "audit-invite-net", "invite", "", TestAdminToken)
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
	rc.CreateNetwork(nodeID, "fields-check-net", "open", "", TestAdminToken)

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
			rc.CreateNetwork(nodeID, strings.Repeat("x", i+1)+"-concurrent-net", "open", "", TestAdminToken)
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
