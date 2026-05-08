// SPDX-License-Identifier: AGPL-3.0-or-later

package trust_test

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/registry/server/trust"
)

// --- test doubles ---

// fakeNodes is a test implementation of NodeView.
type fakeNodes struct {
	nodes      map[uint32]fakeNode
	adminToken string
}

type fakeNode struct {
	pubKey   []byte
	networks []uint16
}

func (f *fakeNodes) LookupNode(id uint32) (pubKey []byte, networks []uint16, ok bool) {
	n, found := f.nodes[id]
	return n.pubKey, n.networks, found
}

func (f *fakeNodes) AdminToken() string {
	return f.adminToken
}

// newFakeNodes builds a NodeView with the given node IDs (no public keys,
// admin-token auth path).
func newFakeNodes(adminToken string, ids ...uint32) *fakeNodes {
	fn := &fakeNodes{
		nodes:      make(map[uint32]fakeNode),
		adminToken: adminToken,
	}
	for _, id := range ids {
		fn.nodes[id] = fakeNode{}
	}
	return fn
}

// noopCallbacks returns a Callbacks where every function is a no-op.
func noopCallbacks() trust.Callbacks {
	return trust.Callbacks{
		Save:                 func() {},
		Audit:                func(_ string, _ ...any) {},
		IncTrustReports:      func() {},
		IncTrustRevocations:  func() {},
		IncHandshakeRequests: func() {},
	}
}

// --- tests ---

// TestReportAndCheckTrust exercises the basic trust-pair lifecycle:
// report creates a pair, check_trust reflects it, and Count() tracks it.
func TestReportAndCheckTrust(t *testing.T) {
	t.Parallel()
	nodes := newFakeNodes("secret", 1, 2)
	st := trust.NewStore(nodes, noopCallbacks())

	// Initially not trusted.
	if st.IsTrusted(1, 2) {
		t.Fatal("expected no trust pair before report")
	}
	if st.Count() != 0 {
		t.Fatalf("Count() = %d, want 0", st.Count())
	}

	// HandleReportTrust via admin token (no pubkey on nodes → admin path).
	resp, err := st.HandleReportTrust(map[string]interface{}{
		"node_id":     float64(1),
		"peer_id":     float64(2),
		"admin_token": "secret",
	})
	if err != nil {
		t.Fatalf("HandleReportTrust: %v", err)
	}
	if resp["type"] != "report_trust_ok" {
		t.Fatalf("unexpected response type: %v", resp["type"])
	}

	// Now trusted.
	if !st.IsTrusted(1, 2) {
		t.Fatal("expected trust pair after report")
	}
	if !st.IsTrusted(2, 1) {
		t.Fatal("IsTrusted should be symmetric")
	}
	if st.Count() != 1 {
		t.Fatalf("Count() = %d, want 1", st.Count())
	}

	// HandleCheckTrust should reflect the pair.
	checkResp, err := st.HandleCheckTrust(map[string]interface{}{
		"node_id": float64(1),
		"peer_id": float64(2),
	})
	if err != nil {
		t.Fatalf("HandleCheckTrust: %v", err)
	}
	trusted, _ := checkResp["trusted"].(bool)
	if !trusted {
		t.Fatal("check_trust returned trusted=false after report")
	}
}

// TestRevokeTrust verifies that a trust pair can be removed.
func TestRevokeTrust(t *testing.T) {
	t.Parallel()
	nodes := newFakeNodes("secret", 10, 20)
	st := trust.NewStore(nodes, noopCallbacks())

	// Seed via RestorePairs so we don't depend on HandleReportTrust.
	st.RestorePairs([]string{"10:20"})
	if !st.IsTrusted(10, 20) {
		t.Fatal("expected trust pair after RestorePairs")
	}

	// Revoke.
	resp, err := st.HandleRevokeTrust(map[string]interface{}{
		"node_id":     float64(10),
		"peer_id":     float64(20),
		"admin_token": "secret",
	})
	if err != nil {
		t.Fatalf("HandleRevokeTrust: %v", err)
	}
	if resp["type"] != "revoke_trust_ok" {
		t.Fatalf("unexpected response type: %v", resp["type"])
	}
	if st.IsTrusted(10, 20) {
		t.Fatal("trust pair should be gone after revoke")
	}

	// Revoking again should error.
	_, err = st.HandleRevokeTrust(map[string]interface{}{
		"node_id":     float64(10),
		"peer_id":     float64(20),
		"admin_token": "secret",
	})
	if err == nil {
		t.Fatal("expected error revoking non-existent pair")
	}
}

// TestCheckTrustSharedNetwork verifies that two nodes sharing a non-backbone
// network are reported as trusted even without an explicit trust pair.
func TestCheckTrustSharedNetwork(t *testing.T) {
	t.Parallel()
	nodes := &fakeNodes{
		adminToken: "secret",
		nodes: map[uint32]fakeNode{
			100: {networks: []uint16{0, 7}},
			200: {networks: []uint16{7, 9}},
		},
	}
	st := trust.NewStore(nodes, noopCallbacks())

	// No explicit trust pair, but both nodes share network 7.
	resp, err := st.HandleCheckTrust(map[string]interface{}{
		"node_id": float64(100),
		"peer_id": float64(200),
	})
	if err != nil {
		t.Fatalf("HandleCheckTrust: %v", err)
	}
	trusted, _ := resp["trusted"].(bool)
	if !trusted {
		t.Fatal("expected trusted=true due to shared non-backbone network")
	}
}

// TestRequestPollRespondHandshake exercises the full handshake relay flow:
// request → poll (inbox) → respond (approve) → poll (response).
func TestRequestPollRespondHandshake(t *testing.T) {
	t.Parallel()
	nodes := newFakeNodes("secret", 1, 2)
	st := trust.NewStore(nodes, noopCallbacks())

	// Node 1 requests a handshake with node 2.
	_, err := st.HandleRequestHandshake(map[string]interface{}{
		"from_node_id":  float64(1),
		"to_node_id":    float64(2),
		"justification": "want to collaborate",
		"admin_token":   "secret",
	})
	if err != nil {
		t.Fatalf("HandleRequestHandshake: %v", err)
	}

	// Node 2 polls its inbox and should see the request.
	pollResp, err := st.HandlePollHandshakes(map[string]interface{}{
		"node_id":     float64(2),
		"admin_token": "secret",
	})
	if err != nil {
		t.Fatalf("HandlePollHandshakes: %v", err)
	}
	requests, _ := pollResp["requests"].([]map[string]interface{})
	if len(requests) != 1 {
		t.Fatalf("got %d requests, want 1", len(requests))
	}
	if fromID, _ := requests[0]["from_node_id"].(uint32); fromID != 1 {
		// JSON numbers are float64 in interface{}
		if fromIDf, ok := requests[0]["from_node_id"].(float64); !ok || fromIDf != 1 {
			t.Fatalf("from_node_id = %v, want 1", requests[0]["from_node_id"])
		}
	}
	justification, _ := requests[0]["justification"].(string)
	if justification != "want to collaborate" {
		t.Fatalf("justification = %q, want 'want to collaborate'", justification)
	}

	// Inbox is consumed: second poll returns empty.
	pollResp2, err := st.HandlePollHandshakes(map[string]interface{}{
		"node_id":     float64(2),
		"admin_token": "secret",
	})
	if err != nil {
		t.Fatalf("second poll: %v", err)
	}
	requests2, _ := pollResp2["requests"].([]map[string]interface{})
	if len(requests2) != 0 {
		t.Fatalf("expected empty inbox on second poll, got %d", len(requests2))
	}

	// Node 2 approves the handshake.
	respondResp, err := st.HandleRespondHandshake(map[string]interface{}{
		"node_id":     float64(2),
		"peer_id":     float64(1),
		"accept":      true,
		"admin_token": "secret",
	})
	if err != nil {
		t.Fatalf("HandleRespondHandshake: %v", err)
	}
	if respondResp["type"] != "respond_handshake_ok" {
		t.Fatalf("unexpected response: %v", respondResp["type"])
	}

	// Trust pair should now be established.
	if !st.IsTrusted(1, 2) {
		t.Fatal("expected trust pair after approved handshake")
	}

	// Node 1 polls its inbox and should see the approval response.
	pollResp3, err := st.HandlePollHandshakes(map[string]interface{}{
		"node_id":     float64(1),
		"admin_token": "secret",
	})
	if err != nil {
		t.Fatalf("node 1 poll: %v", err)
	}
	responses, _ := pollResp3["responses"].([]map[string]interface{})
	if len(responses) != 1 {
		t.Fatalf("got %d responses, want 1", len(responses))
	}
	accepted, _ := responses[0]["accept"].(bool)
	if !accepted {
		t.Fatal("expected accept=true in response")
	}
}

// TestHandshakeRejection verifies that a reject response does NOT create a
// trust pair.
func TestHandshakeRejection(t *testing.T) {
	t.Parallel()
	nodes := newFakeNodes("secret", 5, 6)
	st := trust.NewStore(nodes, noopCallbacks())

	// Request a handshake.
	_, err := st.HandleRequestHandshake(map[string]interface{}{
		"from_node_id": float64(5),
		"to_node_id":   float64(6),
		"admin_token":  "secret",
	})
	if err != nil {
		t.Fatalf("HandleRequestHandshake: %v", err)
	}

	// Consume the inbox.
	_, err = st.HandlePollHandshakes(map[string]interface{}{
		"node_id":     float64(6),
		"admin_token": "secret",
	})
	if err != nil {
		t.Fatalf("poll: %v", err)
	}

	// Reject the handshake.
	_, err = st.HandleRespondHandshake(map[string]interface{}{
		"node_id":     float64(6),
		"peer_id":     float64(5),
		"accept":      false,
		"admin_token": "secret",
	})
	if err != nil {
		t.Fatalf("HandleRespondHandshake: %v", err)
	}

	// Trust pair must NOT be created.
	if st.IsTrusted(5, 6) {
		t.Fatal("trust pair must NOT be created on rejection")
	}
}

// TestSnapshotRoundtrip verifies that Pairs()/RestorePairs() and
// InboxSnapshot()/RestoreInbox() preserve state across a simulated restart.
func TestSnapshotRoundtrip(t *testing.T) {
	t.Parallel()
	nodes := newFakeNodes("secret", 1, 2, 3)
	st := trust.NewStore(nodes, noopCallbacks())

	// Add a trust pair.
	st.RestorePairs([]string{"1:2", "2:3"})

	// Add a handshake request.
	_, err := st.HandleRequestHandshake(map[string]interface{}{
		"from_node_id": float64(1),
		"to_node_id":   float64(3),
		"admin_token":  "secret",
	})
	if err != nil {
		t.Fatalf("HandleRequestHandshake: %v", err)
	}

	// Snapshot.
	pairs := st.Pairs()
	inbox, responses := st.InboxSnapshot()

	// Restore into a fresh Store.
	st2 := trust.NewStore(nodes, noopCallbacks())
	st2.RestorePairs(pairs)
	st2.RestoreInbox(inbox, responses)

	// Trust pairs preserved.
	if !st2.IsTrusted(1, 2) {
		t.Fatal("pair 1:2 not preserved after restore")
	}
	if !st2.IsTrusted(2, 3) {
		t.Fatal("pair 2:3 not preserved after restore")
	}
	if st2.Count() != 2 {
		t.Fatalf("Count() = %d, want 2", st2.Count())
	}

	// Handshake inbox preserved: poll should return the pending request.
	pollResp, err := st2.HandlePollHandshakes(map[string]interface{}{
		"node_id":     float64(3),
		"admin_token": "secret",
	})
	if err != nil {
		t.Fatalf("poll after restore: %v", err)
	}
	reqs, _ := pollResp["requests"].([]map[string]interface{})
	if len(reqs) != 1 {
		t.Fatalf("got %d inbox requests after restore, want 1", len(reqs))
	}
}

// TestInboxSizeLimits verifies that the inbox cap is enforced.
func TestInboxSizeLimits(t *testing.T) {
	t.Parallel()
	// We need 101 distinct senders and 1 recipient.
	nodeIDs := make([]uint32, 102)
	for i := range nodeIDs {
		nodeIDs[i] = uint32(i + 1)
	}
	nodes := newFakeNodes("secret", nodeIDs...)
	st := trust.NewStore(nodes, noopCallbacks())

	toNode := uint32(1)
	// Fill the inbox to capacity (100 entries).
	for i := 2; i <= 101; i++ {
		_, err := st.HandleRequestHandshake(map[string]interface{}{
			"from_node_id": float64(i),
			"to_node_id":   float64(toNode),
			"admin_token":  "secret",
		})
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}

	// The 101st should be rejected.
	_, err := st.HandleRequestHandshake(map[string]interface{}{
		"from_node_id": float64(102),
		"to_node_id":   float64(toNode),
		"admin_token":  "secret",
	})
	if err == nil {
		t.Fatal("expected inbox-full error on 101st request")
	}
}

// TestJustificationSizeLimit checks that oversized justifications are rejected.
func TestJustificationSizeLimit(t *testing.T) {
	t.Parallel()
	nodes := newFakeNodes("secret", 1, 2)
	st := trust.NewStore(nodes, noopCallbacks())

	bigJustification := make([]byte, 1025)
	for i := range bigJustification {
		bigJustification[i] = 'x'
	}

	_, err := st.HandleRequestHandshake(map[string]interface{}{
		"from_node_id":  float64(1),
		"to_node_id":    float64(2),
		"justification": string(bigJustification),
		"admin_token":   "secret",
	})
	if err == nil {
		t.Fatal("expected error for oversized justification")
	}
}

// TestDuplicateHandshakeRequest ensures a duplicate request from the same
// sender is rejected.
func TestDuplicateHandshakeRequest(t *testing.T) {
	t.Parallel()
	nodes := newFakeNodes("secret", 10, 20)
	st := trust.NewStore(nodes, noopCallbacks())

	req := map[string]interface{}{
		"from_node_id": float64(10),
		"to_node_id":   float64(20),
		"admin_token":  "secret",
	}
	if _, err := st.HandleRequestHandshake(req); err != nil {
		t.Fatalf("first request: %v", err)
	}
	_, err := st.HandleRequestHandshake(req)
	if err == nil {
		t.Fatal("expected error for duplicate handshake request")
	}
}

// TestNodeNotFound checks error paths when nodes don't exist.
func TestNodeNotFound(t *testing.T) {
	t.Parallel()
	nodes := newFakeNodes("secret", 1)
	st := trust.NewStore(nodes, noopCallbacks())

	_, err := st.HandleReportTrust(map[string]interface{}{
		"node_id":     float64(1),
		"peer_id":     float64(999), // doesn't exist
		"admin_token": "secret",
	})
	if err == nil {
		t.Fatal("expected error when peer not found")
	}

	_, err = st.HandleRequestHandshake(map[string]interface{}{
		"from_node_id": float64(1),
		"to_node_id":   float64(999), // doesn't exist
		"admin_token":  "secret",
	})
	if err == nil {
		t.Fatal("expected error when target node not found")
	}
}

// TestInboxSizeMetrics verifies InboxSize returns correct counts.
func TestInboxSizeMetrics(t *testing.T) {
	t.Parallel()
	nodes := newFakeNodes("secret", 1, 2, 3)
	st := trust.NewStore(nodes, noopCallbacks())

	reqCount, respCount := st.InboxSize()
	if reqCount != 0 || respCount != 0 {
		t.Fatalf("expected (0,0) initially, got (%d,%d)", reqCount, respCount)
	}

	// Add one handshake request.
	_, err := st.HandleRequestHandshake(map[string]interface{}{
		"from_node_id": float64(1),
		"to_node_id":   float64(2),
		"admin_token":  "secret",
	})
	if err != nil {
		t.Fatalf("HandleRequestHandshake: %v", err)
	}

	reqCount, respCount = st.InboxSize()
	if reqCount != 1 || respCount != 0 {
		t.Fatalf("expected (1,0), got (%d,%d)", reqCount, respCount)
	}

	// Poll node 2 to drain the inbox (not checking response here).
	_, err = st.HandlePollHandshakes(map[string]interface{}{
		"node_id":     float64(2),
		"admin_token": "secret",
	})
	if err != nil {
		t.Fatalf("poll: %v", err)
	}

	// Add a respond to node 1's response inbox.
	_, err = st.HandleRespondHandshake(map[string]interface{}{
		"node_id":     float64(2),
		"peer_id":     float64(1),
		"accept":      true,
		"admin_token": "secret",
	})
	if err != nil {
		t.Fatalf("HandleRespondHandshake: %v", err)
	}

	reqCount, respCount = st.InboxSize()
	if reqCount != 0 || respCount != 1 {
		t.Fatalf("expected (0,1) after respond, got (%d,%d)", reqCount, respCount)
	}

	// Drain response inbox.
	_, _ = st.HandlePollHandshakes(map[string]interface{}{
		"node_id":     float64(1),
		"admin_token": "secret",
	})

	reqCount, respCount = st.InboxSize()
	if reqCount != 0 || respCount != 0 {
		t.Fatalf("expected (0,0) after draining, got (%d,%d)", reqCount, respCount)
	}
}

// Ensure the timestamp in handshake relay messages is non-zero.
func TestHandshakeTimestampSet(t *testing.T) {
	t.Parallel()
	nodes := newFakeNodes("secret", 1, 2)
	st := trust.NewStore(nodes, noopCallbacks())

	before := time.Now().Truncate(time.Second)
	_, err := st.HandleRequestHandshake(map[string]interface{}{
		"from_node_id": float64(1),
		"to_node_id":   float64(2),
		"admin_token":  "secret",
	})
	if err != nil {
		t.Fatalf("HandleRequestHandshake: %v", err)
	}

	pollResp, err := st.HandlePollHandshakes(map[string]interface{}{
		"node_id":     float64(2),
		"admin_token": "secret",
	})
	if err != nil {
		t.Fatalf("poll: %v", err)
	}

	requests, _ := pollResp["requests"].([]map[string]interface{})
	if len(requests) == 0 {
		t.Fatal("expected at least one request")
	}
	tsRaw := requests[0]["timestamp"]
	tsUnix, ok := tsRaw.(int64)
	if !ok {
		t.Fatalf("timestamp has unexpected type %T: %v", tsRaw, tsRaw)
	}
	ts := time.Unix(tsUnix, 0)
	// The stored timestamp is Unix seconds; truncate before to the same
	// resolution so a sub-second race doesn't cause a spurious failure.
	if ts.Before(before.Truncate(time.Second)) {
		t.Fatalf("timestamp %v is before request was made (%v)", ts, before)
	}
}
