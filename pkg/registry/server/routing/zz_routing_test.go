// SPDX-License-Identifier: AGPL-3.0-or-later

package routing_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/registry/server/routing"
)

// --- stub PunchBackend ---

type stubBackend struct {
	nodes map[uint32]struct {
		pubKey string
		addr   string
	}
	adminToken string
}

func (b *stubBackend) NodePubKeyAndAdminToken(nodeID uint32) ([]byte, string, bool) {
	n, ok := b.nodes[nodeID]
	if !ok {
		return nil, "", false
	}
	return []byte(n.pubKey), b.adminToken, true
}

func (b *stubBackend) VerifyPunchSignature(_ []byte, _ string, _ map[string]interface{}, _ string) error {
	// stub: always accept (unit-test focus is routing logic, not crypto)
	return nil
}

func (b *stubBackend) NodeAddrs(nodeA, nodeB uint32) (string, bool, string, bool) {
	a, okA := b.nodes[nodeA]
	bv, okB := b.nodes[nodeB]
	return a.addr, okA, bv.addr, okB
}

// --- tests ---

func TestBeaconRegisterAndList(t *testing.T) {
	t.Parallel()
	st := routing.NewStore(nil)

	// Register two beacons.
	for _, tc := range []struct{ id uint32; addr string }{
		{1, "1.2.3.4:9001"},
		{2, "5.6.7.8:9001"},
	} {
		resp, err := st.HandleBeaconRegister(map[string]interface{}{
			"beacon_id": float64(tc.id),
			"addr":      tc.addr,
		})
		if err != nil {
			t.Fatalf("register beacon %d: %v", tc.id, err)
		}
		if resp["type"] != "beacon_register_ok" {
			t.Fatalf("unexpected type: %v", resp["type"])
		}
	}

	// List them back.
	resp, err := st.HandleBeaconList()
	if err != nil {
		t.Fatal(err)
	}
	list, ok := resp["beacons"].([]map[string]interface{})
	if !ok {
		t.Fatalf("beacons field has wrong type: %T", resp["beacons"])
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 beacons, got %d", len(list))
	}
}

func TestBeaconRegisterMissingFields(t *testing.T) {
	t.Parallel()
	st := routing.NewStore(nil)

	if _, err := st.HandleBeaconRegister(map[string]interface{}{"addr": "1.2.3.4:9001"}); err == nil {
		t.Fatal("expected error for missing beacon_id")
	}
	if _, err := st.HandleBeaconRegister(map[string]interface{}{"beacon_id": float64(1)}); err == nil {
		t.Fatal("expected error for missing addr")
	}
}

func TestBeaconListExpiresStale(t *testing.T) {
	t.Parallel()
	st := routing.NewStore(nil)

	// Use a fixed clock — register at t=0 then advance by 2×TTL.
	base := time.Now()
	st.SetClock(func() time.Time { return base })

	_, err := st.HandleBeaconRegister(map[string]interface{}{
		"beacon_id": float64(10),
		"addr":      "10.0.0.1:9001",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Advance clock past TTL.
	st.SetClock(func() time.Time { return base.Add(2 * routing.BeaconTTL) })

	resp, err := st.HandleBeaconList()
	if err != nil {
		t.Fatal(err)
	}
	list := resp["beacons"].([]map[string]interface{})
	if len(list) != 0 {
		t.Fatalf("expected 0 live beacons after TTL, got %d", len(list))
	}
}

func TestReapStale(t *testing.T) {
	t.Parallel()
	st := routing.NewStore(nil)

	base := time.Now()
	st.SetClock(func() time.Time { return base })

	_, _ = st.HandleBeaconRegister(map[string]interface{}{
		"beacon_id": float64(7),
		"addr":      "7.7.7.7:9001",
	})

	// Advance and reap.
	st.SetClock(func() time.Time { return base.Add(2 * routing.BeaconTTL) })
	st.ReapStale()

	resp, _ := st.HandleBeaconList()
	list := resp["beacons"].([]map[string]interface{})
	if len(list) != 0 {
		t.Fatalf("expected 0 beacons after reap, got %d", len(list))
	}
}

func TestHandlePunchSuccess(t *testing.T) {
	t.Parallel()
	be := &stubBackend{
		nodes: map[uint32]struct {
			pubKey string
			addr   string
		}{
			1: {"pk1", "1.1.1.1:4000"},
			2: {"pk2", "2.2.2.2:4000"},
		},
	}
	st := routing.NewStore(be)

	resp, err := st.HandlePunch(map[string]interface{}{
		"requester_id": float64(1),
		"node_a":       float64(1),
		"node_b":       float64(2),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp["type"] != "punch_ok" {
		t.Fatalf("expected punch_ok, got %v", resp["type"])
	}
	if resp["node_a_addr"] != "1.1.1.1:4000" {
		t.Fatalf("wrong node_a_addr: %v", resp["node_a_addr"])
	}
	if resp["node_b_addr"] != "2.2.2.2:4000" {
		t.Fatalf("wrong node_b_addr: %v", resp["node_b_addr"])
	}
}

func TestHandlePunchRequesterNotParticipant(t *testing.T) {
	t.Parallel()
	be := &stubBackend{
		nodes: map[uint32]struct {
			pubKey string
			addr   string
		}{
			1: {"pk1", "1.1.1.1:4000"},
			2: {"pk2", "2.2.2.2:4000"},
			3: {"pk3", "3.3.3.3:4000"},
		},
	}
	st := routing.NewStore(be)

	_, err := st.HandlePunch(map[string]interface{}{
		"requester_id": float64(3), // third party — not a or b
		"node_a":       float64(1),
		"node_b":       float64(2),
	})
	if err == nil {
		t.Fatal("expected error for non-participant requester")
	}
}

func TestHandlePunchBackendVerifyError(t *testing.T) {
	t.Parallel()
	be := &stubBackend{
		nodes: map[uint32]struct {
			pubKey string
			addr   string
		}{
			1: {"pk1", "1.1.1.1:4000"},
			2: {"pk2", "2.2.2.2:4000"},
		},
	}
	// Override verify to fail.
	errBe := &failVerifyBackend{inner: be}
	st := routing.NewStore(errBe)

	_, err := st.HandlePunch(map[string]interface{}{
		"requester_id": float64(1),
		"node_a":       float64(1),
		"node_b":       float64(2),
	})
	if err == nil {
		t.Fatal("expected verification error")
	}
}

// failVerifyBackend wraps stubBackend but always fails signature verification.
type failVerifyBackend struct {
	inner *stubBackend
}

func (f *failVerifyBackend) NodePubKeyAndAdminToken(id uint32) ([]byte, string, bool) {
	return f.inner.NodePubKeyAndAdminToken(id)
}
func (f *failVerifyBackend) VerifyPunchSignature(_ []byte, _ string, _ map[string]interface{}, _ string) error {
	return fmt.Errorf("bad signature")
}
func (f *failVerifyBackend) NodeAddrs(a, b uint32) (string, bool, string, bool) {
	return f.inner.NodeAddrs(a, b)
}
