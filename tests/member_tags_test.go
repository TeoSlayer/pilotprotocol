package tests

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/policy"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

func TestMemberTagsSetGet(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeA, _ := registerTestNode(t, rc)
	nodeB, _ := registerTestNode(t, rc)

	netResp, err := rc.CreateNetwork(nodeA, "tag-test", "open", "", TestAdminToken, false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(netResp["network_id"].(float64))

	_, err = rc.JoinNetwork(nodeB, netID, "", 0, TestAdminToken)
	if err != nil {
		t.Fatalf("join network: %v", err)
	}

	resp, err := rc.SetMemberTags(netID, nodeA, []string{"service", "primary"}, TestAdminToken)
	if err != nil {
		t.Fatalf("set member tags: %v", err)
	}
	if resp["type"] != "set_member_tags_ok" {
		t.Fatalf("expected set_member_tags_ok, got %v", resp["type"])
	}

	resp, err = rc.GetMemberTags(netID, nodeA)
	if err != nil {
		t.Fatalf("get member tags: %v", err)
	}
	tags, ok := resp["tags"].([]interface{})
	if !ok || len(tags) != 2 {
		t.Fatalf("expected 2 tags, got %v", resp["tags"])
	}

	resp, err = rc.GetMemberTags(netID, nodeB)
	if err != nil {
		t.Fatalf("get member tags for B: %v", err)
	}
	tagsB, ok := resp["tags"].([]interface{})
	if !ok || len(tagsB) != 0 {
		t.Fatalf("expected empty tags for B, got %v", resp["tags"])
	}

	resp, err = rc.GetMemberTags(netID, 0)
	if err != nil {
		t.Fatalf("get all member tags: %v", err)
	}
	members, ok := resp["members"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected members map, got %v", resp["members"])
	}
	if len(members) < 2 {
		t.Fatalf("expected at least 2 members, got %d", len(members))
	}
}

func TestMemberTagsRequiresAdmin(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeA, _ := registerTestNode(t, rc)

	netResp, err := rc.CreateNetwork(nodeA, "auth-test", "open", "", TestAdminToken, false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(netResp["network_id"].(float64))

	_, err = rc.SetMemberTags(netID, nodeA, []string{"service"}, "wrong-token")
	if err == nil {
		t.Fatal("expected error when setting member tags without admin token")
	}
}

func TestMemberTagsInListNodes(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeA, _ := registerTestNode(t, rc)

	netResp, err := rc.CreateNetwork(nodeA, "list-tags-test", "open", "", TestAdminToken, false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(netResp["network_id"].(float64))

	_, err = rc.SetMemberTags(netID, nodeA, []string{"service"}, TestAdminToken)
	if err != nil {
		t.Fatalf("set member tags: %v", err)
	}

	resp, err := rc.ListNodes(netID, TestAdminToken)
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	nodes := resp["nodes"].([]interface{})
	nodeMap := nodes[0].(map[string]interface{})
	mt := nodeMap["member_tags"].([]interface{})
	if len(mt) != 1 || mt[0] != "service" {
		t.Fatalf("expected member_tags=[service], got %v", mt)
	}
}

func TestMemberTagsClearOnEmpty(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeA, _ := registerTestNode(t, rc)

	netResp, err := rc.CreateNetwork(nodeA, "clear-test", "open", "", TestAdminToken, false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(netResp["network_id"].(float64))

	_, _ = rc.SetMemberTags(netID, nodeA, []string{"service"}, TestAdminToken)
	_, _ = rc.SetMemberTags(netID, nodeA, []string{}, TestAdminToken)

	resp, err := rc.GetMemberTags(netID, nodeA)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	tags := resp["tags"].([]interface{})
	if len(tags) != 0 {
		t.Fatalf("expected empty, got %v", tags)
	}
}

func TestMemberTagsNonMemberRejected(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistryWithAdmin(t)
	defer cleanup()

	nodeA, _ := registerTestNode(t, rc)
	nodeB, _ := registerTestNode(t, rc)

	netResp, err := rc.CreateNetwork(nodeA, "nonmember-test", "open", "", TestAdminToken, false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(netResp["network_id"].(float64))

	_, err = rc.SetMemberTags(netID, nodeB, []string{"service"}, TestAdminToken)
	if err == nil {
		t.Fatal("expected error when tagging non-member")
	}
}

func TestMemberTagsPersistence(t *testing.T) {
	t.Parallel()

	tmpDir, err := os.MkdirTemp("/tmp", "w4-member-tags-persist-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	storePath := filepath.Join(tmpDir, "registry.json")

	reg1 := registry.NewWithStore("127.0.0.1:9001", storePath)
	reg1.SetAdminToken(TestAdminToken)
	go reg1.ListenAndServe(":0")
	<-reg1.Ready()

	rc1, err := registry.Dial(resolveLocalAddr(reg1.Addr()))
	if err != nil {
		t.Fatalf("dial1: %v", err)
	}

	nodeA, _ := registerTestNode(t, rc1)
	netResp, err := rc1.CreateNetwork(nodeA, "persist-tags", "open", "", TestAdminToken, false)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	netID := uint16(netResp["network_id"].(float64))

	_, err = rc1.SetMemberTags(netID, nodeA, []string{"service", "data"}, TestAdminToken)
	if err != nil {
		t.Fatalf("set: %v", err)
	}

	rc1.Close()
	reg1.Close()

	reg2 := registry.NewWithStore("127.0.0.1:9001", storePath)
	reg2.SetAdminToken(TestAdminToken)
	go reg2.ListenAndServe(":0")
	<-reg2.Ready()
	defer reg2.Close()

	rc2, err := registry.Dial(resolveLocalAddr(reg2.Addr()))
	if err != nil {
		t.Fatalf("dial2: %v", err)
	}
	defer rc2.Close()

	resp, err := rc2.GetMemberTags(netID, nodeA)
	if err != nil {
		t.Fatalf("get after reload: %v", err)
	}
	tags := resp["tags"].([]interface{})
	if len(tags) != 2 || tags[0] != "service" || tags[1] != "data" {
		t.Fatalf("expected [service, data] after reload, got %v", tags)
	}
}

func TestHostnameClashAtRegistration(t *testing.T) {
	t.Parallel()
	rc, _, cleanup := startTestRegistry(t)
	defer cleanup()

	idA, _ := crypto.GenerateIdentity()
	respA, err := rc.Send(map[string]interface{}{
		"type":       "register",
		"public_key": crypto.EncodePublicKey(idA.PublicKey),
		"hostname":   "taken-name",
	})
	if err != nil {
		t.Fatalf("register A: %v", err)
	}
	if respA["hostname"] != "taken-name" {
		t.Fatalf("expected hostname for A, got %v", respA["hostname"])
	}

	idB, _ := crypto.GenerateIdentity()
	respB, err := rc.Send(map[string]interface{}{
		"type":       "register",
		"public_key": crypto.EncodePublicKey(idB.PublicKey),
		"hostname":   "taken-name",
	})
	if err != nil {
		t.Fatalf("register B: %v", err)
	}

	if _, ok := respB["hostname"]; ok {
		t.Fatal("should not have hostname in response when taken")
	}
	if errMsg, ok := respB["hostname_error"].(string); !ok || errMsg == "" {
		t.Fatalf("expected hostname_error, got %v", respB["hostname_error"])
	}
}

func TestPolicyLocalTagsCompile(t *testing.T) {
	t.Parallel()

	policyJSON := json.RawMessage(`{
		"version": 1,
		"rules": [
			{"name": "svc-conn", "on": "connect", "match": "has_tag(local_tags, \"service\")", "actions": [{"type": "allow"}]},
			{"name": "svc-dial", "on": "dial", "match": "has_tag(peer_tags, \"service\")", "actions": [{"type": "allow"}]},
			{"name": "svc-dg", "on": "datagram", "match": "has_tag(local_tags, \"service\") || has_tag(peer_tags, \"service\")", "actions": [{"type": "allow"}]},
			{"name": "deny-conn", "on": "connect", "match": "true", "actions": [{"type": "deny"}]},
			{"name": "deny-dial", "on": "dial", "match": "true", "actions": [{"type": "deny"}]},
			{"name": "deny-dg", "on": "datagram", "match": "true", "actions": [{"type": "deny"}]}
		]
	}`)

	doc, err := policy.Parse(policyJSON)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cp, err := policy.Compile(doc)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// Service connect: allow
	dirs, _ := cp.Evaluate(policy.EventConnect, map[string]interface{}{
		"peer_id": 1, "port": 80, "network_id": 1,
		"local_tags": []string{"service"}, "peer_tags": []string{},
		"peer_score": 0, "peer_age_s": 0.0, "members": 5,
	})
	if len(dirs) == 0 || dirs[0].Type != policy.DirectiveAllow {
		t.Fatal("expected allow for service connect")
	}

	// Normie connect: deny
	dirs, _ = cp.Evaluate(policy.EventConnect, map[string]interface{}{
		"peer_id": 2, "port": 80, "network_id": 1,
		"local_tags": []string{}, "peer_tags": []string{},
		"peer_score": 0, "peer_age_s": 0.0, "members": 5,
	})
	if len(dirs) == 0 || dirs[0].Type != policy.DirectiveDeny {
		t.Fatal("expected deny for normie connect")
	}

	// Normie dial to service: allow
	dirs, _ = cp.Evaluate(policy.EventDial, map[string]interface{}{
		"peer_id": 3, "port": 80, "network_id": 1,
		"local_tags": []string{}, "peer_tags": []string{"service"},
		"peer_score": 0, "peer_age_s": 0.0, "members": 5,
	})
	if len(dirs) == 0 || dirs[0].Type != policy.DirectiveAllow {
		t.Fatal("expected allow for dial to service")
	}

	// Service datagram: allow
	dirs, _ = cp.Evaluate(policy.EventDatagram, map[string]interface{}{
		"peer_id": 4, "port": 80, "network_id": 1,
		"local_tags": []string{"service"}, "peer_tags": []string{},
		"peer_score": 0, "peer_age_s": 0.0, "members": 5,
		"size": 100, "direction": "out",
	})
	if len(dirs) == 0 || dirs[0].Type != policy.DirectiveAllow {
		t.Fatal("expected allow for service datagram")
	}

	// Normie datagram: deny
	dirs, _ = cp.Evaluate(policy.EventDatagram, map[string]interface{}{
		"peer_id": 5, "port": 80, "network_id": 1,
		"local_tags": []string{}, "peer_tags": []string{},
		"peer_score": 0, "peer_age_s": 0.0, "members": 5,
		"size": 100, "direction": "out",
	})
	if len(dirs) == 0 || dirs[0].Type != policy.DirectiveDeny {
		t.Fatal("expected deny for normie datagram")
	}
}
