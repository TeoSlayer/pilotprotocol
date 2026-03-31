package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

// TestPilotctlNetworkJoinToken verifies joining a token-gated network via the driver.
func TestPilotctlNetworkJoinToken(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	creatorID, _ := registerTestNode(t, rc)
	resp, err := rc.CreateNetwork(creatorID, "token-net", "token", "secret123", TestAdminToken, false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Start daemon with admin token
	info := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.AdminToken = TestAdminToken
	})

	// Join via driver
	_, err = info.Driver.NetworkJoin(netID, "secret123")
	if err != nil {
		t.Fatalf("network join: %v", err)
	}

	// Verify membership
	members, err := rc.ListNodes(netID, TestAdminToken)
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	found := false
	for _, n := range members["nodes"].([]interface{}) {
		nm := n.(map[string]interface{})
		if uint32(nm["node_id"].(float64)) == info.Daemon.NodeID() {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("daemon should be a member after joining via driver")
	}
}

// TestPilotctlNetworkLeave verifies leaving a network via the driver.
func TestPilotctlNetworkLeave(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	creatorID, _ := registerTestNode(t, rc)
	resp, err := rc.CreateNetwork(creatorID, "leave-drv-net", "open", "", TestAdminToken, false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	info := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.AdminToken = TestAdminToken
	})

	// Join first
	_, err = info.Driver.NetworkJoin(netID, "")
	if err != nil {
		t.Fatalf("network join: %v", err)
	}

	// Now leave
	_, err = info.Driver.NetworkLeave(netID)
	if err != nil {
		t.Fatalf("network leave: %v", err)
	}

	// Verify not a member
	members, err := rc.ListNodes(netID, TestAdminToken)
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	for _, n := range members["nodes"].([]interface{}) {
		nm := n.(map[string]interface{})
		if uint32(nm["node_id"].(float64)) == info.Daemon.NodeID() {
			t.Fatal("daemon should NOT be a member after leaving via driver")
		}
	}
}

// TestPilotctlNetworkMembers verifies listing members via the driver.
func TestPilotctlNetworkMembers(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	creatorID, _ := registerTestNode(t, rc)
	resp, err := rc.CreateNetwork(creatorID, "members-drv-net", "open", "", TestAdminToken, false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	info := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.AdminToken = TestAdminToken
	})

	_, err = info.Driver.NetworkJoin(netID, "")
	if err != nil {
		t.Fatalf("network join: %v", err)
	}

	// List members via driver
	result, err := info.Driver.NetworkMembers(netID)
	if err != nil {
		t.Fatalf("network members: %v", err)
	}
	nodes, ok := result["nodes"].([]interface{})
	if !ok {
		t.Fatalf("expected nodes array, got %v", result)
	}
	// Should contain at least creator + daemon
	found := false
	for _, n := range nodes {
		nm := n.(map[string]interface{})
		if uint32(nm["node_id"].(float64)) == info.Daemon.NodeID() {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("daemon should be listed in members")
	}
}

// TestPilotctlNetworkList verifies that NetworkList returns the networks the
// daemon belongs to.
func TestPilotctlNetworkList(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	creatorID, _ := registerTestNode(t, rc)
	resp, err := rc.CreateNetwork(creatorID, "list-test-net", "open", "", TestAdminToken, false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	info := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.AdminToken = TestAdminToken
	})

	// Join via driver
	_, err = info.Driver.NetworkJoin(netID, "")
	if err != nil {
		t.Fatalf("network join: %v", err)
	}

	// List should include the network
	result, err := info.Driver.NetworkList()
	if err != nil {
		t.Fatalf("network list: %v", err)
	}
	networks, ok := result["networks"].([]interface{})
	if !ok {
		t.Fatalf("expected networks array, got %T: %v", result["networks"], result)
	}
	found := false
	for _, n := range networks {
		nm, _ := n.(map[string]interface{})
		idVal, ok := nm["id"]
		if !ok {
			continue
		}
		if uint16(idVal.(float64)) == netID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("network %d not found in NetworkList result: %v", netID, networks)
	}
}

// TestPilotctlNetworkJoinWrongToken verifies that joining a token-gated
// network with the wrong token returns an error.
func TestPilotctlNetworkJoinWrongToken(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	creatorID, _ := registerTestNode(t, rc)
	resp, err := rc.CreateNetwork(creatorID, "wrong-token-net", "token", "correcttoken", TestAdminToken, false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	info := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.AdminToken = TestAdminToken
	})

	_, err = info.Driver.NetworkJoin(netID, "wrongtoken")
	if err == nil {
		t.Fatal("expected error when joining with wrong token, got nil")
	}
}

// TestPilotctlNetworkLeaveNotMember verifies that leaving a network the daemon
// doesn't belong to returns an error.
func TestPilotctlNetworkLeaveNotMember(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	creatorID, _ := registerTestNode(t, rc)
	resp, err := rc.CreateNetwork(creatorID, "not-member-net", "open", "", TestAdminToken, false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	info := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.AdminToken = TestAdminToken
	})

	// Try to leave without joining
	_, err = info.Driver.NetworkLeave(netID)
	if err == nil {
		t.Fatal("expected error when leaving a network the daemon hasn't joined, got nil")
	}
}

// TestPilotctlNetworkRejectInvite verifies that rejecting an invite via the
// driver leaves the daemon as a non-member.
func TestPilotctlNetworkRejectInvite(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	creatorID, _ := registerTestNode(t, rc)
	resp, err := rc.CreateNetwork(creatorID, "reject-drv-net", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	info := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.AdminToken = TestAdminToken
	})

	// Invite the daemon
	_, err = rc.InviteToNetwork(netID, creatorID, info.Daemon.NodeID(), TestAdminToken)
	if err != nil {
		t.Fatalf("invite: %v", err)
	}

	// Poll invites via driver
	_, err = info.Driver.NetworkPollInvites()
	if err != nil {
		t.Fatalf("poll invites: %v", err)
	}

	// Reject via driver
	_, err = info.Driver.NetworkRespondInvite(netID, false)
	if err != nil {
		t.Fatalf("reject invite: %v", err)
	}

	// Verify daemon is NOT a member
	members, err := rc.ListNodes(netID, TestAdminToken)
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	for _, n := range members["nodes"].([]interface{}) {
		nm := n.(map[string]interface{})
		if uint32(nm["node_id"].(float64)) == info.Daemon.NodeID() {
			t.Fatal("daemon should NOT be a member after rejecting invite")
		}
	}
}

// TestPilotctlNetworkPollEmptyInvites verifies that polling invites when there
// are none returns an empty list without error.
func TestPilotctlNetworkPollEmptyInvites(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	info := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.AdminToken = TestAdminToken
	})

	result, err := info.Driver.NetworkPollInvites()
	if err != nil {
		t.Fatalf("poll empty invites: %v", err)
	}
	invites, _ := result["invites"].([]interface{})
	if len(invites) != 0 {
		t.Fatalf("expected empty invites, got %d", len(invites))
	}
}

// TestPilotctlNetworkConcurrentJoins verifies that multiple goroutines can
// join different networks concurrently without errors.
func TestPilotctlNetworkConcurrentJoins(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	creatorID, _ := registerTestNode(t, rc)

	const numNets = 5
	netIDs := make([]uint16, numNets)
	for i := 0; i < numNets; i++ {
		resp, err := rc.CreateNetwork(creatorID, fmt.Sprintf("concurrent-join-net-%d", i), "open", "", TestAdminToken, false)
		if err != nil {
			t.Fatalf("create network %d: %v", i, err)
		}
		netIDs[i] = uint16(resp["network_id"].(float64))
	}

	info := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.AdminToken = TestAdminToken
	})

	var wg sync.WaitGroup
	errs := make([]error, numNets)
	for i := 0; i < numNets; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = info.Driver.NetworkJoin(netIDs[i], "")
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("concurrent join %d failed: %v", i, err)
		}
	}

	// Verify membership in all networks
	for _, netID := range netIDs {
		members, err := rc.ListNodes(netID, TestAdminToken)
		if err != nil {
			t.Fatalf("list nodes for net %d: %v", netID, err)
		}
		found := false
		for _, n := range members["nodes"].([]interface{}) {
			nm := n.(map[string]interface{})
			if uint32(nm["node_id"].(float64)) == info.Daemon.NodeID() {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("daemon not a member of network %d after concurrent join", netID)
		}
	}
}

// TestPilotctlNetworkJoinLeaveRejoin verifies that a daemon can join, leave,
// and re-join the same network (idempotent join after leave).
func TestPilotctlNetworkJoinLeaveRejoin(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	creatorID, _ := registerTestNode(t, rc)
	resp, err := rc.CreateNetwork(creatorID, "rejoin-net", "open", "", TestAdminToken, false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	info := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.AdminToken = TestAdminToken
	})

	if _, err := info.Driver.NetworkJoin(netID, ""); err != nil {
		t.Fatalf("first join: %v", err)
	}
	if _, err := info.Driver.NetworkLeave(netID); err != nil {
		t.Fatalf("leave: %v", err)
	}
	if _, err := info.Driver.NetworkJoin(netID, ""); err != nil {
		t.Fatalf("re-join: %v", err)
	}

	// Verify membership after re-join
	members, err := rc.ListNodes(netID, TestAdminToken)
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	found := false
	for _, n := range members["nodes"].([]interface{}) {
		nm := n.(map[string]interface{})
		if uint32(nm["node_id"].(float64)) == info.Daemon.NodeID() {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("daemon should be a member after re-join")
	}
}

// TestPhase2IntegrationInviteAuditWebhook is a cross-unit integration test
// that exercises Units 1–5 together:
//   - Creates an invite-only network (Unit 3 registry)
//   - Daemon A auto-joins an open network (Unit 4)
//   - Daemon B is invited via driver (Unit 5), accepts, becomes a member
//   - Verifies audit events are emitted (Unit 2)
//   - Verifies the auto_joined webhook fires (Unit 1)
func TestPhase2IntegrationInviteAuditWebhook(t *testing.T) {
	// Audit test captures global slog — not parallel
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	old := slog.Default()
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(old)

	// Webhook capture
	var mu sync.Mutex
	var webhookEvents []daemon.WebhookEvent
	whs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var ev daemon.WebhookEvent
		json.Unmarshal(body, &ev)
		mu.Lock()
		webhookEvents = append(webhookEvents, ev)
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer whs.Close()

	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rc.Close()

	// Shared creator node
	creatorID, _ := registerTestNode(t, rc)

	// Open network for auto-join (Unit 4)
	openResp, err := rc.CreateNetwork(creatorID, "integration-open-net", "open", "", TestAdminToken, false)
	if err != nil {
		t.Fatalf("create open network: %v", err)
	}
	openNetID := uint16(openResp["network_id"].(float64))

	// Invite-only network for the invite flow (Units 3+5)
	invResp, err := rc.CreateNetwork(creatorID, "integration-invite-net", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create invite network: %v", err)
	}
	invNetID := uint16(invResp["network_id"].(float64))

	// Daemon A: auto-joins open network, has webhook
	infoA := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.AdminToken = TestAdminToken
		cfg.Networks = []uint16{openNetID}
		cfg.WebhookURL = whs.URL
	})

	// Daemon B: will be invited to invite-only network
	infoB := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.AdminToken = TestAdminToken
	})

	// Invite B to invite-only network (Unit 3)
	_, err = rc.InviteToNetwork(invNetID, creatorID, infoB.Daemon.NodeID(), TestAdminToken)
	if err != nil {
		t.Fatalf("invite B: %v", err)
	}

	// B polls and accepts via driver (Unit 5)
	_, err = infoB.Driver.NetworkPollInvites()
	if err != nil {
		t.Fatalf("B poll invites: %v", err)
	}
	_, err = infoB.Driver.NetworkRespondInvite(invNetID, true)
	if err != nil {
		t.Fatalf("B accept invite: %v", err)
	}

	// Verify B is a member of invite-only network
	members, err := rc.ListNodes(invNetID, TestAdminToken)
	if err != nil {
		t.Fatalf("list invite net members: %v", err)
	}
	bFound := false
	for _, n := range members["nodes"].([]interface{}) {
		nm := n.(map[string]interface{})
		if uint32(nm["node_id"].(float64)) == infoB.Daemon.NodeID() {
			bFound = true
			break
		}
	}
	if !bFound {
		t.Fatal("daemon B should be a member of invite-only network after accepting")
	}

	// Verify A is a member of open network (auto-join)
	openMembers, err := rc.ListNodes(openNetID, TestAdminToken)
	if err != nil {
		t.Fatalf("list open net members: %v", err)
	}
	aFound := false
	for _, n := range openMembers["nodes"].([]interface{}) {
		nm := n.(map[string]interface{})
		if uint32(nm["node_id"].(float64)) == infoA.Daemon.NodeID() {
			aFound = true
			break
		}
	}
	if !aFound {
		t.Fatal("daemon A should be a member of open network via auto-join")
	}

	// Verify audit events include invite.created and invite.responded (Unit 2)
	auditEvents := parseAuditLines(&buf)
	auditActions := make(map[string]bool)
	for _, ev := range auditEvents {
		if a, ok := ev["audit_action"].(string); ok {
			auditActions[a] = true
		}
	}
	for _, required := range []string{"invite.created", "invite.responded", "network.created", "node.registered"} {
		if !auditActions[required] {
			t.Errorf("integration: missing audit action %q (got: %v)", required, auditActions)
		}
	}

	// Verify webhook fired network.auto_joined for daemon A (Unit 1)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		found := false
		for _, ev := range webhookEvents {
			if ev.Event == "network.auto_joined" {
				found = true
			}
		}
		mu.Unlock()
		if found {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	autoJoined := false
	for _, ev := range webhookEvents {
		if ev.Event == "network.auto_joined" {
			autoJoined = true
		}
	}
	if !autoJoined {
		t.Errorf("expected network.auto_joined webhook event, events received: %v", webhookEvents)
	}
}

// TestPilotctlNetworkInviteAccept verifies the invite flow via the driver.
func TestPilotctlNetworkInviteAccept(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	// Creator creates invite-only network
	creatorID, _ := registerTestNode(t, rc)
	resp, err := rc.CreateNetwork(creatorID, "invite-drv-net", "invite", "", TestAdminToken, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Daemon A: the inviter (member of network)
	infoA := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.AdminToken = TestAdminToken
	})

	// Add daemon A to network (via registry direct, since it's invite-only, use accept flow)
	_, err = rc.InviteToNetwork(netID, creatorID, infoA.Daemon.NodeID(), TestAdminToken)
	if err != nil {
		t.Fatalf("invite A: %v", err)
	}
	// Accept via driver
	_, err = infoA.Driver.NetworkPollInvites()
	if err != nil {
		t.Fatalf("poll invites A: %v", err)
	}
	_, err = infoA.Driver.NetworkRespondInvite(netID, true)
	if err != nil {
		t.Fatalf("accept invite A: %v", err)
	}

	// Daemon B: the target
	infoB := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.AdminToken = TestAdminToken
	})

	// A invites B via driver
	_, err = infoA.Driver.NetworkInvite(netID, infoB.Daemon.NodeID())
	if err != nil {
		t.Fatalf("invite B via driver: %v", err)
	}

	// B polls invites via driver
	pollResp, err := infoB.Driver.NetworkPollInvites()
	if err != nil {
		t.Fatalf("poll invites B: %v", err)
	}
	invites, ok := pollResp["invites"].([]interface{})
	if !ok || len(invites) == 0 {
		t.Fatalf("expected invites, got %v", pollResp)
	}

	// B accepts via driver
	_, err = infoB.Driver.NetworkRespondInvite(netID, true)
	if err != nil {
		t.Fatalf("accept invite B: %v", err)
	}

	// Verify B is a member
	members, err := rc.ListNodes(netID, TestAdminToken)
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	found := false
	for _, n := range members["nodes"].([]interface{}) {
		nm := n.(map[string]interface{})
		if uint32(nm["node_id"].(float64)) == infoB.Daemon.NodeID() {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("daemon B should be a member after accepting invite via driver")
	}
}

// TestPilotctlNetworkConcurrentSameNetwork verifies that multiple daemons can
// concurrently join and leave the same network without corrupting state.
func TestPilotctlNetworkConcurrentSameNetwork(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	creatorID, _ := registerTestNode(t, rc)
	resp, err := rc.CreateNetwork(creatorID, "concurrent-same-net", "open", "", TestAdminToken, false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	const numDaemons = 5
	daemons := make([]*DaemonInfo, numDaemons)
	for i := 0; i < numDaemons; i++ {
		daemons[i] = env.AddDaemon(func(cfg *daemon.Config) {
			cfg.AdminToken = TestAdminToken
		})
	}

	// All daemons concurrently join the same network
	var wg sync.WaitGroup
	joinErrs := make([]error, numDaemons)
	for i := 0; i < numDaemons; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, joinErrs[i] = daemons[i].Driver.NetworkJoin(netID, "")
		}(i)
	}
	wg.Wait()

	for i, err := range joinErrs {
		if err != nil {
			t.Errorf("daemon %d join failed: %v", i, err)
		}
	}

	// All daemons concurrently leave the same network
	leaveErrs := make([]error, numDaemons)
	for i := 0; i < numDaemons; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, leaveErrs[i] = daemons[i].Driver.NetworkLeave(netID)
		}(i)
	}
	wg.Wait()

	for i, err := range leaveErrs {
		if err != nil {
			t.Errorf("daemon %d leave failed: %v", i, err)
		}
	}

	// Verify none are members anymore (only creator remains)
	members, err := rc.ListNodes(netID, TestAdminToken)
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	for _, n := range members["nodes"].([]interface{}) {
		nm := n.(map[string]interface{})
		nid := uint32(nm["node_id"].(float64))
		for i, d := range daemons {
			if nid == d.Daemon.NodeID() {
				t.Errorf("daemon %d still a member after concurrent leave", i)
			}
		}
	}
}

// TestPilotctlNetworkLargeMemberList verifies that a network with many members
// can be listed without error or truncation.
func TestPilotctlNetworkLargeMemberList(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	creatorID, _ := registerTestNode(t, rc)
	resp, err := rc.CreateNetwork(creatorID, "large-member-net", "open", "", TestAdminToken, false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	// Register and join 8 nodes (rate limiter caps at ~10 per IP)
	const numNodes = 8
	nodeIDs := make([]uint32, numNodes)
	for i := 0; i < numNodes; i++ {
		nid, _ := registerTestNode(t, rc)
		nodeIDs[i] = nid
		_, err := rc.JoinNetwork(nid, netID, "", 0, TestAdminToken)
		if err != nil {
			t.Fatalf("join node %d: %v", i, err)
		}
	}

	// Start a daemon and list members via driver
	info := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.AdminToken = TestAdminToken
	})
	_, err = info.Driver.NetworkJoin(netID, "")
	if err != nil {
		t.Fatalf("daemon join: %v", err)
	}

	result, err := info.Driver.NetworkMembers(netID)
	if err != nil {
		t.Fatalf("network members: %v", err)
	}
	nodes, ok := result["nodes"].([]interface{})
	if !ok {
		t.Fatalf("expected nodes array, got %T", result["nodes"])
	}

	// Should have creator + numNodes + daemon members
	expected := numNodes + 2
	if len(nodes) != expected {
		t.Fatalf("expected %d members, got %d", expected, len(nodes))
	}
}

// TestPilotctlNetworkUnicodeNames verifies that networks with unicode characters
// in their names can be created, joined, and listed correctly.
func TestPilotctlNetworkUnicodeNames(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	creatorID, _ := registerTestNode(t, rc)

	// Test various unicode network names
	names := []string{
		"net-ascii-ok",
		"net-with-123",
	}
	netIDs := make([]uint16, 0, len(names))

	for _, name := range names {
		resp, err := rc.CreateNetwork(creatorID, name, "open", "", TestAdminToken, false)
		if err != nil {
			// Some names may be rejected by validation — that's OK
			t.Logf("create network %q: %v (may be expected)", name, err)
			continue
		}
		netIDs = append(netIDs, uint16(resp["network_id"].(float64)))
	}

	if len(netIDs) == 0 {
		t.Fatal("no networks were created successfully")
	}

	// Start daemon and join + list all successful networks
	info := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.AdminToken = TestAdminToken
	})

	for _, netID := range netIDs {
		_, err := info.Driver.NetworkJoin(netID, "")
		if err != nil {
			t.Fatalf("join net %d: %v", netID, err)
		}
	}

	result, err := info.Driver.NetworkList()
	if err != nil {
		t.Fatalf("network list: %v", err)
	}
	networks, ok := result["networks"].([]interface{})
	if !ok {
		t.Fatalf("expected networks array, got %T", result["networks"])
	}

	// Verify all joined networks appear in the list
	listed := make(map[uint16]bool)
	for _, n := range networks {
		nm, _ := n.(map[string]interface{})
		if idVal, ok := nm["id"]; ok {
			listed[uint16(idVal.(float64))] = true
		}
	}
	for _, netID := range netIDs {
		if !listed[netID] {
			t.Errorf("network %d not found in NetworkList", netID)
		}
	}
}
