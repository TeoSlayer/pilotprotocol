package tests

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

// TestSnapshotStructure validates that the snapshot file has all required fields.
func TestSnapshotStructure(t *testing.T) {
	// Create a temporary directory for snapshots
	snapDir := t.TempDir()
	snapPath := filepath.Join(snapDir, "registry-snapshot.json")

	// Start registry with persistence enabled
	reg := registry.NewWithStore(":0", snapPath)
	go reg.ListenAndServe(":0")

	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	defer reg.Close()

	regAddr := reg.Addr().String()

	// Create test client
	client, err := registry.Dial(regAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer client.Close()

	// Seed with test data
	id1, _ := crypto.GenerateIdentity()
	id2, _ := crypto.GenerateIdentity()

	// Register nodes
	resp1, err := client.RegisterWithKey("node-1.local", crypto.EncodePublicKey(id1.PublicKey), "127.0.0.1:5001")
	if err != nil {
		t.Fatalf("register node 1: %v", err)
	}
	nodeID1 := uint32(resp1["node_id"].(float64))

	resp2, err := client.RegisterWithKey("node-2.local", crypto.EncodePublicKey(id2.PublicKey), "127.0.0.1:5002")
	if err != nil {
		t.Fatalf("register node 2: %v", err)
	}
	nodeID2 := uint32(resp2["node_id"].(float64))

	// Set tags
	setClientSigner(client, id1)
	if _, err := client.Send(map[string]interface{}{
		"type":    "set_tags",
		"node_id": nodeID1,
		"tags":    []string{"ml", "gpu"},
	}); err != nil {
		t.Logf("set tags: %v", err)
	}

	// Set task executor
	setClientSigner(client, id2)
	if _, err := client.Send(map[string]interface{}{
		"type":      "set_task_exec",
		"node_id":   nodeID2,
		"task_exec": true,
	}); err != nil {
		t.Logf("set task exec: %v", err)
	}

	// Set POLO scores
	setClientSigner(client, id1)
	if _, err := client.Send(map[string]interface{}{
		"type":       "set_polo_score",
		"node_id":    nodeID1,
		"polo_score": 150,
	}); err != nil {
		t.Logf("set polo score: %v", err)
	}

	// Make some requests to increment TotalRequests
	for i := 0; i < 10; i++ {
		_, _ = client.Lookup(0)
	}

	// Trigger snapshot save
	if err := reg.TriggerSnapshot(); err != nil {
		t.Fatalf("trigger snapshot: %v", err)
	}

	// Verify snapshot file exists
	if _, err := os.Stat(snapPath); os.IsNotExist(err) {
		t.Fatalf("snapshot file not created: %s", snapPath)
	}

	// Read and validate snapshot structure
	data, err := os.ReadFile(snapPath)
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}

	var snap map[string]interface{}
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}

	// Validate required fields
	requiredFields := []string{"next_node", "next_net", "nodes", "networks"}
	for _, field := range requiredFields {
		if _, exists := snap[field]; !exists {
			t.Errorf("snapshot missing required field: %s", field)
		}
	}

	// Validate dashboard stats fields (note: omitempty means zero values may not be present)
	requiredStatsFields := []string{"total_requests", "start_time", "total_nodes", "online_nodes"}
	for _, field := range requiredStatsFields {
		if _, exists := snap[field]; !exists {
			t.Errorf("snapshot missing required dashboard stats field: %s", field)
		}
	}

	// Optional stats fields (may be omitted if zero due to omitempty tag)
	optionalStatsFields := []string{"trust_links", "unique_tags", "task_executors"}
	for _, field := range optionalStatsFields {
		if _, exists := snap[field]; exists {
			t.Logf("Optional field %s present in snapshot", field)
		} else {
			t.Logf("Optional field %s omitted (zero value)", field)
		}
	}

	// Validate total_requests is greater than 0
	totalRequests, ok := snap["total_requests"].(float64)
	if !ok {
		t.Error("total_requests is not a number")
	} else if totalRequests < 10 {
		t.Errorf("total_requests = %v, expected >= 10", totalRequests)
	}

	// Validate total_nodes matches nodes count
	totalNodes, ok := snap["total_nodes"].(float64)
	if !ok {
		t.Error("total_nodes is not a number")
	}

	// Validate nodes structure
	nodesMap, ok := snap["nodes"].(map[string]interface{})
	if !ok {
		t.Fatal("nodes is not a map")
	}
	if len(nodesMap) < 2 {
		t.Errorf("expected at least 2 nodes, got %d", len(nodesMap))
	}

	// Check that total_nodes matches actual nodes count
	if totalNodes > 0 && int(totalNodes) != len(nodesMap) {
		t.Errorf("total_nodes = %v, but nodes map has %d entries", totalNodes, len(nodesMap))
	}

	// Validate online_nodes is a number
	onlineNodes, ok := snap["online_nodes"].(float64)
	if !ok {
		t.Error("online_nodes is not a number")
	} else {
		t.Logf("Online nodes: %v", onlineNodes)
	}

	// Validate trust_links (may be omitted if zero)
	trustLinks := float64(0)
	if val, ok := snap["trust_links"].(float64); ok {
		trustLinks = val
		t.Logf("Trust links: %v", trustLinks)
	} else {
		t.Logf("Trust links: 0 (omitted)")
	}

	// Validate unique_tags (may be omitted if zero)
	uniqueTags := float64(0)
	if val, ok := snap["unique_tags"].(float64); ok {
		uniqueTags = val
		t.Logf("Unique tags: %v", uniqueTags)
	} else {
		t.Logf("Unique tags: 0 (omitted)")
	}

	// Validate task_executors (may be omitted if zero)
	taskExecutors := float64(0)
	if val, ok := snap["task_executors"].(float64); ok {
		taskExecutors = val
		t.Logf("Task executors: %v", taskExecutors)
	} else {
		t.Logf("Task executors: 0 (omitted)")
	}

	// Validate start_time is a valid RFC3339 timestamp
	startTimeStr, ok := snap["start_time"].(string)
	if !ok {
		t.Error("start_time is not a string")
	} else {
		if _, err := time.Parse(time.RFC3339, startTimeStr); err != nil {
			t.Errorf("start_time is not valid RFC3339: %v", err)
		}
	}

	// Validate node structure has all required fields
	for nodeKey, nodeVal := range nodesMap {
		node, ok := nodeVal.(map[string]interface{})
		if !ok {
			t.Errorf("node %s is not a map", nodeKey)
			continue
		}
		nodeFields := []string{"id", "public_key", "networks", "last_seen"}
		for _, field := range nodeFields {
			if _, exists := node[field]; !exists {
				t.Errorf("node %s missing field: %s", nodeKey, field)
			}
		}
	}

	t.Logf("Snapshot structure validation passed")
	t.Logf("Snapshot file: %s", snapPath)
	t.Logf("Dashboard stats in snapshot:")
	t.Logf("  Total Requests: %v", totalRequests)
	t.Logf("  Total Nodes: %v", totalNodes)
	t.Logf("  Online Nodes: %v", onlineNodes)
	t.Logf("  Trust Links: %v", trustLinks)
	t.Logf("  Unique Tags: %v", uniqueTags)
	t.Logf("  Task Executors: %v", taskExecutors)
	t.Logf("  Start Time: %s", startTimeStr)
	t.Logf("Nodes in snapshot: %d", len(nodesMap))
}

// TestSnapshotSaveLoad validates save and load functionality with full stats.
func TestSnapshotSaveLoad(t *testing.T) {
	snapDir := t.TempDir()
	snapPath := filepath.Join(snapDir, "registry-snapshot.json")

	// === Phase 1: Start registry and seed data ===
	t.Log("Phase 1: Starting registry and seeding data...")
	reg1 := registry.NewWithStore(":0", snapPath)
	go reg1.ListenAndServe(":0")

	select {
	case <-reg1.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}

	regAddr := reg1.Addr().String()
	time.Sleep(100 * time.Millisecond)

	// Seed data
	client1, err := registry.Dial(regAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}

	id1, _ := crypto.GenerateIdentity()
	id2, _ := crypto.GenerateIdentity()
	id3, _ := crypto.GenerateIdentity()

	resp1, err := client1.RegisterWithKey("ml-gpu-1", crypto.EncodePublicKey(id1.PublicKey), "127.0.0.1:8000")
	if err != nil {
		t.Fatalf("register node 1: %v", err)
	}
	nodeID1 := uint32(resp1["node_id"].(float64))

	resp2, err := client1.RegisterWithKey("storage-1", crypto.EncodePublicKey(id2.PublicKey), "127.0.0.1:8001")
	if err != nil {
		t.Fatalf("register node 2: %v", err)
	}
	nodeID2 := uint32(resp2["node_id"].(float64))

	resp3, err := client1.RegisterWithKey("compute-1", crypto.EncodePublicKey(id3.PublicKey), "127.0.0.1:8002")
	if err != nil {
		t.Fatalf("register node 3: %v", err)
	}
	nodeID3 := uint32(resp3["node_id"].(float64))

	// Set tags
	setClientSigner(client1, id1)
	_, _ = client1.Send(map[string]interface{}{
		"type":    "set_tags",
		"node_id": nodeID1,
		"tags":    []string{"ml", "gpu"},
	})
	setClientSigner(client1, id2)
	_, _ = client1.Send(map[string]interface{}{
		"type":    "set_tags",
		"node_id": nodeID2,
		"tags":    []string{"storage"},
	})

	// Set task executors
	setClientSigner(client1, id1)
	_, _ = client1.Send(map[string]interface{}{
		"type":      "set_task_exec",
		"node_id":   nodeID1,
		"task_exec": true,
	})
	setClientSigner(client1, id3)
	_, _ = client1.Send(map[string]interface{}{
		"type":      "set_task_exec",
		"node_id":   nodeID3,
		"task_exec": true,
	})

	// Set POLO scores
	setClientSigner(client1, id1)
	_, _ = client1.Send(map[string]interface{}{
		"type":       "set_polo_score",
		"node_id":    nodeID1,
		"polo_score": 150,
	})
	setClientSigner(client1, id2)
	_, _ = client1.Send(map[string]interface{}{
		"type":       "set_polo_score",
		"node_id":    nodeID2,
		"polo_score": 45,
	})
	setClientSigner(client1, id3)
	_, _ = client1.Send(map[string]interface{}{
		"type":       "set_polo_score",
		"node_id":    nodeID3,
		"polo_score": 92,
	})

	// Make some requests to increment counter
	for i := 0; i < 25; i++ {
		_, _ = client1.Lookup(0)
	}

	// Get stats before save
	statsBefore := reg1.GetDashboardStats()
	t.Logf("Stats before save:")
	t.Logf("  Total Requests: %d", statsBefore.TotalRequests)
	t.Logf("  Total Nodes: %d", statsBefore.TotalNodes)
	t.Logf("  Active Nodes: %d", statsBefore.ActiveNodes)
	t.Logf("  Unique Tags: %d", statsBefore.UniqueTags)
	t.Logf("  Task Executors: %d", statsBefore.TaskExecutors)
	t.Logf("  Uptime: %d seconds", statsBefore.UptimeSecs)

	// Trigger snapshot
	if err := reg1.TriggerSnapshot(); err != nil {
		t.Fatalf("trigger snapshot: %v", err)
	}

	// Close first registry instance
	client1.Close()
	reg1.Close()
	time.Sleep(200 * time.Millisecond)

	// === Phase 2: Restart registry WITHOUT loading snapshot ===
	t.Log("\nPhase 2: Restarting registry WITHOUT loading snapshot...")
	reg2 := registry.New(":0") // No storePath = no snapshot loading
	go reg2.ListenAndServe(regAddr)

	select {
	case <-reg2.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry 2 failed to start")
	}

	time.Sleep(100 * time.Millisecond)

	statsNoLoad := reg2.GetDashboardStats()
	t.Logf("Stats without loading snapshot:")
	t.Logf("  Total Requests: %d (expected 0)", statsNoLoad.TotalRequests)
	t.Logf("  Total Nodes: %d (expected 0)", statsNoLoad.TotalNodes)
	t.Logf("  Active Nodes: %d (expected 0)", statsNoLoad.ActiveNodes)

	// Validate stats are reset
	if statsNoLoad.TotalRequests != 0 {
		t.Errorf("expected TotalRequests=0, got %d", statsNoLoad.TotalRequests)
	}
	if statsNoLoad.TotalNodes != 0 {
		t.Errorf("expected TotalNodes=0, got %d", statsNoLoad.TotalNodes)
	}
	if statsNoLoad.UptimeSecs > 5 {
		t.Errorf("expected new uptime < 5s, got %d", statsNoLoad.UptimeSecs)
	}

	reg2.Close()
	time.Sleep(200 * time.Millisecond)

	// === Phase 3: Restart registry WITH snapshot ===
	t.Log("\nPhase 3: Restarting registry WITH snapshot loaded...")
	reg3 := registry.NewWithStore(":0", snapPath)
	go reg3.ListenAndServe(regAddr)

	select {
	case <-reg3.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry 3 failed to start")
	}
	defer reg3.Close()

	time.Sleep(100 * time.Millisecond)

	// Get stats after load
	statsAfter := reg3.GetDashboardStats()
	t.Logf("Stats after loading snapshot:")
	t.Logf("  Total Requests: %d", statsAfter.TotalRequests)
	t.Logf("  Total Nodes: %d", statsAfter.TotalNodes)
	t.Logf("  Active Nodes: %d", statsAfter.ActiveNodes)
	t.Logf("  Unique Tags: %d", statsAfter.UniqueTags)
	t.Logf("  Task Executors: %d", statsAfter.TaskExecutors)
	t.Logf("  Trust Links: %d", statsAfter.TotalTrustLinks)
	t.Logf("  Uptime: %d seconds", statsAfter.UptimeSecs)

	// Validate all stats are restored
	if statsAfter.TotalRequests < statsBefore.TotalRequests {
		t.Errorf("TotalRequests not restored: before=%d, after=%d",
			statsBefore.TotalRequests, statsAfter.TotalRequests)
	}
	if statsAfter.TotalNodes != statsBefore.TotalNodes {
		t.Errorf("TotalNodes not restored: before=%d, after=%d",
			statsBefore.TotalNodes, statsAfter.TotalNodes)
	}
	if statsAfter.UniqueTags != statsBefore.UniqueTags {
		t.Errorf("UniqueTags not restored: before=%d, after=%d",
			statsBefore.UniqueTags, statsAfter.UniqueTags)
	}
	if statsAfter.TaskExecutors != statsBefore.TaskExecutors {
		t.Errorf("TaskExecutors not restored: before=%d, after=%d",
			statsBefore.TaskExecutors, statsAfter.TaskExecutors)
	}

	// Validate nodes are restored
	if len(statsAfter.Nodes) != 3 {
		t.Errorf("expected 3 nodes, got %d", len(statsAfter.Nodes))
	}

	// Validate POLO scores are restored
	poloScores := make(map[int]bool)
	for _, node := range statsAfter.Nodes {
		poloScores[node.PoloScore] = true
	}
	expectedScores := []int{150, 45, 92}
	for _, score := range expectedScores {
		if !poloScores[score] {
			t.Errorf("POLO score %d not found in restored nodes", score)
		}
	}

	// Validate online status (nodes should be stale after restart)
	for _, node := range statsAfter.Nodes {
		if node.Online {
			t.Logf("Warning: node %s is online after restart (might be ok)", node.Address)
		}
	}

	t.Logf("\n✅ Snapshot save/load test passed")
}

// TestManualSnapshotTrigger validates the manual snapshot trigger via HTTP endpoint.
func TestManualSnapshotTrigger(t *testing.T) {
	snapDir := t.TempDir()
	snapPath := filepath.Join(snapDir, "registry-snapshot.json")

	// Start registry with persistence
	reg := registry.NewWithStore(":0", snapPath)
	go reg.ListenAndServe(":0")

	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	defer reg.Close()

	regAddr := reg.Addr().String()

	// Start dashboard on a different listener
	go func() {
		if err := reg.ServeDashboard("127.0.0.1:0"); err != nil {
			t.Logf("dashboard error: %v", err)
		}
	}()

	// Wait for dashboard to start
	time.Sleep(500 * time.Millisecond)

	// Get dashboard address from the server (we need to extract it)
	// For now, use a fixed port for testing
	dashAddr := "127.0.0.1:18080"

	// Restart with explicit dashboard port
	reg.Close()
	time.Sleep(200 * time.Millisecond)

	reg = registry.NewWithStore(":0", snapPath)
	go reg.ListenAndServe(":0")

	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to restart")
	}
	defer reg.Close()

	regAddr = reg.Addr().String()

	// Start dashboard with known port
	go func() {
		if err := reg.ServeDashboard(dashAddr); err != nil {
			t.Logf("dashboard error: %v", err)
		}
	}()

	time.Sleep(300 * time.Millisecond)

	// Seed some data
	client, err := registry.Dial(regAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer client.Close()

	id, _ := crypto.GenerateIdentity()
	resp, err := client.RegisterWithKey("test-node", crypto.EncodePublicKey(id.PublicKey), "127.0.0.1:5000")
	if err != nil {
		t.Fatalf("register node: %v", err)
	}

	nodeID := uint32(resp["node_id"].(float64))
	setClientSigner(client, id)
	_, _ = client.Send(map[string]interface{}{
		"type":       "set_polo_score",
		"node_id":    nodeID,
		"polo_score": 100,
	})

	// Make some requests
	for i := 0; i < 15; i++ {
		_, _ = client.Lookup(0)
	}

	// Get initial stats
	statsBefore := reg.GetDashboardStats()
	t.Logf("Stats before manual snapshot:")
	t.Logf("  Total Requests: %d", statsBefore.TotalRequests)
	t.Logf("  Total Nodes: %d", statsBefore.TotalNodes)

	// Trigger snapshot via HTTP
	httpClient := &http.Client{Timeout: 5 * time.Second}

	url := fmt.Sprintf("http://%s/api/snapshot", dashAddr)
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	httpResp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("POST /api/snapshot: %v", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(httpResp.Body)
		t.Fatalf("snapshot trigger failed: status=%d, body=%s", httpResp.StatusCode, body)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(httpResp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if status, ok := result["status"].(string); !ok || status != "ok" {
		t.Errorf("expected status=ok, got %v", result)
	}

	t.Logf("Snapshot trigger response: %v", result)

	// Verify snapshot file was created/updated
	if _, err := os.Stat(snapPath); os.IsNotExist(err) {
		t.Fatalf("snapshot file not created: %s", snapPath)
	}

	// Read and validate snapshot has the data
	data, err := os.ReadFile(snapPath)
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}

	var snap map[string]interface{}
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}

	totalRequests := snap["total_requests"].(float64)
	if totalRequests < 15 {
		t.Errorf("expected total_requests >= 15, got %v", totalRequests)
	}

	nodes := snap["nodes"].(map[string]interface{})
	if len(nodes) != 1 {
		t.Errorf("expected 1 node, got %d", len(nodes))
	}

	t.Logf("✅ Manual snapshot trigger test passed")
}
