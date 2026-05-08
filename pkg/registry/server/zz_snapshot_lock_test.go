// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestSnapshotJSONShape locks down the shape contract: snapshotJSON must
// produce parseable JSON with the expected top-level fields after the
// outside-RLock refactor.
func TestSnapshotJSONShape(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")

	// Seed 3 nodes + 2 networks with overlapping membership.
	s.mu.Lock()
	s.nodes[101] = &NodeInfo{
		ID:        101,
		Owner:     "alice",
		PublicKey: []byte("pk-101"),
		Networks:  []uint16{0, 1},
		LANAddrs:  []string{"10.0.0.1"},
		Tags:      []string{"role:dev"},
	}
	s.nodes[101].SetLastSeen(time.Now())

	s.nodes[102] = &NodeInfo{
		ID:        102,
		Owner:     "bob",
		PublicKey: []byte("pk-102"),
		Networks:  []uint16{0},
	}
	s.nodes[102].SetLastSeen(time.Now())

	s.nodes[103] = &NodeInfo{
		ID:        103,
		Owner:     "carol",
		PublicKey: []byte("pk-103"),
		Networks:  []uint16{1},
	}
	s.nodes[103].SetLastSeen(time.Now())

	s.networks[1] = &NetworkInfo{
		ID:       1,
		Name:     "alpha",
		JoinRule: "open",
		Members:  []uint32{101, 103},
		Created:  time.Now(),
	}
	s.nextNode = 200
	s.nextNet = 5
	s.mu.Unlock()

	data := s.snapshotJSON()
	if len(data) == 0 {
		t.Fatalf("snapshotJSON returned empty bytes")
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v\npayload: %s", err, string(data))
	}

	nodesAny, ok := parsed["nodes"]
	if !ok {
		t.Fatalf("snapshot missing 'nodes' field; got keys: %v", keys(parsed))
	}
	nodes, ok := nodesAny.(map[string]interface{})
	if !ok {
		t.Fatalf("'nodes' should be object, got %T", nodesAny)
	}
	if got, want := len(nodes), 3; got != want {
		t.Fatalf("nodes count = %d, want %d", got, want)
	}

	netsAny := parsed["networks"]
	nets, _ := netsAny.(map[string]interface{})
	if len(nets) < 1 {
		t.Fatalf("networks count = %d, want >= 1", len(nets))
	}

	// Confirm nextNode/nextNet preserved.
	if got, _ := parsed["next_node"].(float64); uint32(got) != 200 {
		t.Fatalf("next_node = %v, want 200", parsed["next_node"])
	}
}

// TestSnapshotJSONConcurrentMutation drives the lock-release refactor.
// While snapshotJSON runs in one goroutine, another mutates aliasable
// slice fields (Networks, Tags, Members). Run under -race; if the new
// lock-release pattern aliases a live slice, this trips.
func TestSnapshotJSONConcurrentMutation(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")

	const nodeID uint32 = 555
	const netID uint16 = 7

	s.mu.Lock()
	s.nodes[nodeID] = &NodeInfo{
		ID:        nodeID,
		Owner:     "stress",
		PublicKey: []byte("pk"),
		Networks:  []uint16{0},
		Tags:      []string{"a"},
		LANAddrs:  []string{"10.0.0.1"},
	}
	s.nodes[nodeID].SetLastSeen(time.Now())
	s.networks[netID] = &NetworkInfo{
		ID:       netID,
		Name:     "stress-net",
		JoinRule: "open",
		Members:  []uint32{nodeID},
		Created:  time.Now(),
	}
	s.mu.Unlock()

	const iterations = 100
	var stop atomic.Bool
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations && !stop.Load(); i++ {
			data := s.snapshotJSON()
			if len(data) == 0 {
				t.Errorf("snapshotJSON returned empty bytes at iter %d", i)
				return
			}
			var parsed map[string]interface{}
			if err := json.Unmarshal(data, &parsed); err != nil {
				t.Errorf("unmarshal at iter %d: %v", i, err)
				return
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations && !stop.Load(); i++ {
			s.mu.Lock()
			n := s.nodes[nodeID]
			if n != nil {
				// Append + truncate cycle to stress slice growth + re-slicing,
				// the failure modes the lock-release refactor must protect against.
				n.Networks = append(n.Networks, uint16(i+10))
				n.Tags = append(n.Tags, "tag")
				n.LANAddrs = append(n.LANAddrs, "10.0.0.2")
				if len(n.Networks) > 4 {
					n.Networks = n.Networks[:1]
					n.Tags = n.Tags[:1]
					n.LANAddrs = n.LANAddrs[:1]
				}
			}
			net := s.networks[netID]
			if net != nil {
				net.Members = append(net.Members, uint32(i+1000))
				if len(net.Members) > 4 {
					net.Members = net.Members[:1]
				}
			}
			s.mu.Unlock()
		}
	}()

	wg.Wait()
	stop.Store(true)
}

func keys(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
