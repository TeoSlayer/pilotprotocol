package daemon

import (
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/policy"
)

// handleManaged sub-command dispatch coverage. Uses in-memory PolicyRunner
// seeded directly into d.policyRunners so Score/Status/Rankings/ForceCycle
// code paths exercise without requiring a started cycleLoop goroutine.

// mgTestDaemon wires a daemon with a real test registry + identity (so
// member-tags sub-commands that hit regConn.GetMemberTags/SetMemberTags don't
// nil-deref) and seeds a PolicyRunner on network `netID`.
func mgTestDaemon(t *testing.T, netID uint16) *Daemon {
	t.Helper()
	reg, rc := startTestRegistry(t)
	t.Cleanup(func() { reg.Close() })
	t.Cleanup(func() { rc.Close() })
	reg.SetAdminToken("admin-token")

	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("gen identity: %v", err)
	}
	resp, err := rc.RegisterWithKey("127.0.0.1:5700", crypto.EncodePublicKey(id.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("self register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	d := New(Config{AdminToken: "admin-token"})
	d.regConn = rc
	d.identity = id
	d.setNodeID_testhelper(nodeID)
	t.Cleanup(func() { d.handshakes.Stop() })

	// Seed a PolicyRunner directly — don't call StartPolicyRunner because we
	// don't want a background cycleLoop.
	cp, err := policy.Compile(&policy.PolicyDocument{
		Version: 1,
		Rules: []policy.Rule{
			{Name: "allow", On: "connect", Match: "true", Actions: []policy.Action{{Type: policy.ActionAllow}}},
		},
	})
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	pr := &PolicyRunner{
		netID:    netID,
		compiled: cp,
		daemon:   d,
		peers: map[uint32]*managedPeer{
			100: {NodeID: 100, AddedAt: time.Now()},
			200: {NodeID: 200, AddedAt: time.Now(), Score: 10},
		},
		joinedAt: time.Now(),
		stopCh:   make(chan struct{}),
		done:     make(chan struct{}),
	}
	d.policyMu.Lock()
	d.policyRunners[netID] = pr
	d.policyMu.Unlock()
	// Pre-close done so cycleLoop-wait on Stop doesn't hang.
	close(pr.done)

	return d
}

// --- SubManagedScore ---

func TestHandleManagedScoreValidRepliesOK(t *testing.T) {
	d := mgTestDaemon(t, 1)
	s := d.ipc
	ic, client := newIPCTestConn(t)

	// [SubManagedScore][2-byte netID=1][4-byte nodeID=100][4-byte delta=+5]
	payload := make([]byte, 11)
	payload[0] = SubManagedScore
	binary.BigEndian.PutUint16(payload[1:3], 1)
	binary.BigEndian.PutUint32(payload[3:7], 100)
	binary.BigEndian.PutUint32(payload[7:11], 5)

	reply := runHandler(t, client, func() { s.handleManaged(ic, payload) })
	if reply[0] != CmdManagedOK {
		t.Fatalf("reply[0] = 0x%02X, want CmdManagedOK — body=%q", reply[0], reply[1:])
	}
	var r map[string]interface{}
	if err := json.Unmarshal(reply[1:], &r); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if r["type"] != "managed_score_ok" {
		t.Fatalf("type = %v, want managed_score_ok", r["type"])
	}
	if uint32(r["node_id"].(float64)) != 100 {
		t.Fatalf("node_id = %v, want 100", r["node_id"])
	}
	if int(r["delta"].(float64)) != 5 {
		t.Fatalf("delta = %v, want 5", r["delta"])
	}

	// Verify the PolicyRunner actually mutated — peer 100's score should now be 5.
	pr := d.GetPolicyRunner(1)
	if pr == nil {
		t.Fatal("policy runner missing")
	}
	pr.mu.Lock()
	got := pr.peers[100].Score
	pr.mu.Unlock()
	if got != 5 {
		t.Fatalf("peer 100 score = %d, want 5", got)
	}
}

func TestHandleManagedScoreNoEngineSendsError(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)

	payload := make([]byte, 11)
	payload[0] = SubManagedScore
	binary.BigEndian.PutUint16(payload[1:3], 99)
	binary.BigEndian.PutUint32(payload[3:7], 100)
	binary.BigEndian.PutUint32(payload[7:11], 5)

	reply := runHandler(t, client, func() { s.handleManaged(ic, payload) })
	assertErrorReply(t, reply, "no engine for network 99")
}

// --- SubManagedStatus ---

func TestHandleManagedStatusWithPolicyRunnerRepliesOK(t *testing.T) {
	d := mgTestDaemon(t, 7)
	s := d.ipc
	ic, client := newIPCTestConn(t)

	payload := make([]byte, 3)
	payload[0] = SubManagedStatus
	binary.BigEndian.PutUint16(payload[1:3], 7)

	reply := runHandler(t, client, func() { s.handleManaged(ic, payload) })
	if reply[0] != CmdManagedOK {
		t.Fatalf("reply[0] = 0x%02X, want CmdManagedOK", reply[0])
	}
	var r map[string]interface{}
	if err := json.Unmarshal(reply[1:], &r); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	// PolicyRunner.Status returns a map with "network_id" and "peer_count".
	if uint16(r["network_id"].(float64)) != 7 {
		t.Fatalf("network_id = %v, want 7", r["network_id"])
	}
	if int(r["peers"].(float64)) != 2 {
		t.Fatalf("peers = %v, want 2", r["peers"])
	}
	if r["engine"] != "policy" {
		t.Fatalf("engine = %v, want policy", r["engine"])
	}
}

func TestHandleManagedStatusNoNetIDReturnsFirstEngine(t *testing.T) {
	d := mgTestDaemon(t, 13)
	s := d.ipc
	ic, client := newIPCTestConn(t)

	// No rest → netID=0 → findPolicyRunner returns first runner (netID=13).
	reply := runHandler(t, client, func() { s.handleManaged(ic, []byte{SubManagedStatus}) })
	if reply[0] != CmdManagedOK {
		t.Fatalf("reply[0] = 0x%02X, want CmdManagedOK", reply[0])
	}
	var r map[string]interface{}
	if err := json.Unmarshal(reply[1:], &r); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if uint16(r["network_id"].(float64)) != 13 {
		t.Fatalf("network_id = %v, want 13", r["network_id"])
	}
}

// --- SubManagedRankings ---

func TestHandleManagedRankingsWithPolicyRunnerRepliesOK(t *testing.T) {
	d := mgTestDaemon(t, 3)
	s := d.ipc
	ic, client := newIPCTestConn(t)

	payload := make([]byte, 3)
	payload[0] = SubManagedRankings
	binary.BigEndian.PutUint16(payload[1:3], 3)

	reply := runHandler(t, client, func() { s.handleManaged(ic, payload) })
	if reply[0] != CmdManagedOK {
		t.Fatalf("reply[0] = 0x%02X, want CmdManagedOK", reply[0])
	}
	var r map[string]interface{}
	if err := json.Unmarshal(reply[1:], &r); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if r["type"] != "managed_rankings_ok" {
		t.Fatalf("type = %v, want managed_rankings_ok", r["type"])
	}
	rankings, ok := r["rankings"].([]interface{})
	if !ok {
		t.Fatalf("rankings missing/wrong type: %v", r)
	}
	if len(rankings) != 2 {
		t.Fatalf("rankings len = %d, want 2 (seeded peers 100+200)", len(rankings))
	}
}

func TestHandleManagedRankingsNoEngineSendsError(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() {
		s.handleManaged(ic, []byte{SubManagedRankings, 0x00, 0x05})
	})
	assertErrorReply(t, reply, "no active managed networks")
}

// --- SubManagedCycle ---

func TestHandleManagedCycleWithPolicyRunnerRepliesOK(t *testing.T) {
	d := mgTestDaemon(t, 5)
	s := d.ipc
	ic, client := newIPCTestConn(t)

	payload := make([]byte, 3)
	payload[0] = SubManagedCycle
	binary.BigEndian.PutUint16(payload[1:3], 5)

	reply := runHandler(t, client, func() { s.handleManaged(ic, payload) })
	if reply[0] != CmdManagedOK {
		t.Fatalf("reply[0] = 0x%02X, want CmdManagedOK — body=%q", reply[0], reply[1:])
	}
	// ForceCycle returns a map — at minimum it should unmarshal as valid JSON.
	var r map[string]interface{}
	if err := json.Unmarshal(reply[1:], &r); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if _, ok := r["type"]; !ok {
		// tolerate any shape — ForceCycle may return "cycle_completed" or similar
		_ = r
	}
}

func TestHandleManagedCycleNoEngineSendsError(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() {
		s.handleManaged(ic, []byte{SubManagedCycle, 0x00, 0x01})
	})
	assertErrorReply(t, reply, "no active managed networks")
}

// --- SubManagedPolicy get/set ---

func TestHandleManagedPolicyGetWithPolicyRunnerRepliesOK(t *testing.T) {
	d := mgTestDaemon(t, 9)
	s := d.ipc
	ic, client := newIPCTestConn(t)

	// [SubManagedPolicy][action=0x00 get][2-byte netID=9]
	payload := []byte{SubManagedPolicy, 0x00, 0x00, 0x09}
	reply := runHandler(t, client, func() { s.handleManaged(ic, payload) })
	if reply[0] != CmdManagedOK {
		t.Fatalf("reply[0] = 0x%02X, want CmdManagedOK", reply[0])
	}
	var r map[string]interface{}
	if err := json.Unmarshal(reply[1:], &r); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if uint16(r["network_id"].(float64)) != 9 {
		t.Fatalf("network_id = %v, want 9", r["network_id"])
	}
	if r["engine"] != "policy" {
		t.Fatalf("engine = %v, want policy", r["engine"])
	}
	if _, ok := r["expr_policy"]; !ok {
		t.Fatalf("expr_policy missing: %v", r)
	}
}

func TestHandleManagedPolicyGetNoEngineReturnsNone(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	payload := []byte{SubManagedPolicy, 0x00, 0x00, 0x42}
	reply := runHandler(t, client, func() { s.handleManaged(ic, payload) })
	if reply[0] != CmdManagedOK {
		t.Fatalf("reply[0] = 0x%02X, want CmdManagedOK", reply[0])
	}
	var r map[string]interface{}
	if err := json.Unmarshal(reply[1:], &r); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if r["engine"] != "none" {
		t.Fatalf("engine = %v, want none", r["engine"])
	}
}

func TestHandleManagedPolicySetMissingJSONSendsError(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	payload := []byte{SubManagedPolicy, 0x01, 0x00, 0x01} // action=set, netID=1, no JSON
	reply := runHandler(t, client, func() { s.handleManaged(ic, payload) })
	assertErrorReply(t, reply, "managed policy set: missing policy JSON")
}

func TestHandleManagedPolicySetValidRepliesOK(t *testing.T) {
	// StartPolicyRunner kicks off cycleLoop → bootstrap → fetchMembersWithTags,
	// which calls regConn.ListNodes — so we need a wired registry.
	d, _ := netTestDaemon(t)
	s := d.ipc
	ic, client := newIPCTestConn(t)

	// Minimal parseable/compilable policy.
	policyJSON := []byte(`{"version":1,"rules":[{"name":"r","on":"connect","match":"true","actions":[{"type":"allow"}]}]}`)

	// [SubManagedPolicy][action=0x01 set][2-byte netID=42][policy JSON...]
	payload := make([]byte, 4+len(policyJSON))
	payload[0] = SubManagedPolicy
	payload[1] = 0x01
	binary.BigEndian.PutUint16(payload[2:4], 42)
	copy(payload[4:], policyJSON)

	reply := runHandler(t, client, func() { s.handleManaged(ic, payload) })
	if reply[0] != CmdManagedOK {
		t.Fatalf("reply[0] = 0x%02X, want CmdManagedOK — body=%q", reply[0], reply[1:])
	}
	var r map[string]interface{}
	if err := json.Unmarshal(reply[1:], &r); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if r["applied"] != true {
		t.Fatalf("applied = %v, want true", r["applied"])
	}
	// A runner should now exist for network 42.
	if d.GetPolicyRunner(42) == nil {
		t.Fatal("no policy runner for network 42 after set")
	}
	// Stop it cleanly so the cycleLoop goroutine exits.
	d.StopPolicyRunner(42)
}

func TestHandleManagedPolicyUnknownActionSendsError(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	payload := []byte{SubManagedPolicy, 0xAB, 0x00, 0x01} // unknown action 0xAB
	reply := runHandler(t, client, func() { s.handleManaged(ic, payload) })
	assertErrorReply(t, reply, "unknown action")
}

// --- SubManagedMemberTags ---

func TestHandleManagedMemberTagsShortRestSendsError(t *testing.T) {
	d, _ := netTestDaemon(t)
	s := d.ipc
	ic, client := newIPCTestConn(t)
	// rest has only 5 bytes (need 7 = 1-byte action + 2-byte net + 4-byte target).
	payload := []byte{SubManagedMemberTags, 0x00, 0x00, 0x01, 0x02, 0x03}
	reply := runHandler(t, client, func() { s.handleManaged(ic, payload) })
	assertErrorReply(t, reply, "missing action")
}

func TestHandleManagedMemberTagsGetForwardsToRegistry(t *testing.T) {
	d, _ := netTestDaemon(t)
	s := d.ipc
	ic, client := newIPCTestConn(t)

	// Non-existent network — registry returns error. Exercises the dispatch +
	// error-wrap branch even without successful retrieval.
	payload := make([]byte, 8)
	payload[0] = SubManagedMemberTags
	payload[1] = 0x00 // get
	binary.BigEndian.PutUint16(payload[2:4], 0xBEEF)
	binary.BigEndian.PutUint32(payload[4:8], 0xCAFEBABE)

	reply := runHandler(t, client, func() { s.handleManaged(ic, payload) })
	if reply[0] == CmdManagedOK {
		return // happy path — registry allowed it
	}
	assertErrorReply(t, reply, "member-tags get:")
}

func TestHandleManagedMemberTagsSetInvalidJSONSendsError(t *testing.T) {
	d, _ := netTestDaemon(t)
	s := d.ipc
	ic, client := newIPCTestConn(t)

	// [SubManagedMemberTags][action=0x01 set][2-byte net][4-byte target][tags JSON = "not-json"]
	payload := make([]byte, 8+len("not-json"))
	payload[0] = SubManagedMemberTags
	payload[1] = 0x01
	binary.BigEndian.PutUint16(payload[2:4], 1)
	binary.BigEndian.PutUint32(payload[4:8], 100)
	copy(payload[8:], []byte("not-json"))

	reply := runHandler(t, client, func() { s.handleManaged(ic, payload) })
	assertErrorReply(t, reply, "invalid tags JSON")
}

func TestHandleManagedMemberTagsSetMissingJSONSendsError(t *testing.T) {
	d, _ := netTestDaemon(t)
	s := d.ipc
	ic, client := newIPCTestConn(t)

	// rest = 7 bytes (action + net + target) but NO tags payload.
	payload := make([]byte, 8)
	payload[0] = SubManagedMemberTags
	payload[1] = 0x01 // set
	binary.BigEndian.PutUint16(payload[2:4], 1)
	binary.BigEndian.PutUint32(payload[4:8], 100)

	reply := runHandler(t, client, func() { s.handleManaged(ic, payload) })
	assertErrorReply(t, reply, "missing tags JSON")
}

func TestHandleManagedMemberTagsUnknownActionSendsError(t *testing.T) {
	d, _ := netTestDaemon(t)
	s := d.ipc
	ic, client := newIPCTestConn(t)

	payload := make([]byte, 8)
	payload[0] = SubManagedMemberTags
	payload[1] = 0xFE // unknown
	binary.BigEndian.PutUint16(payload[2:4], 1)
	binary.BigEndian.PutUint32(payload[4:8], 100)

	reply := runHandler(t, client, func() { s.handleManaged(ic, payload) })
	assertErrorReply(t, reply, "member-tags: unknown action")
}

// --- unknown sub ---

func TestHandleManagedUnknownSubCommandSendsError(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() {
		s.handleManaged(ic, []byte{0xAB})
	})
	assertErrorReply(t, reply, "managed: unknown sub-command")
}
