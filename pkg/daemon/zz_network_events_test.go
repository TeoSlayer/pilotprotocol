// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"sync"
	"testing"
	"time"

	"github.com/pilot-protocol/common/crypto"
)

// captureBusEvents subscribes to the daemon's bus on `pattern` and
// returns a synchronous getter for the captured slice plus a cancel
// func. Tests use this to assert the publish-side of T4.3
// reconcileMembership.
func captureBusEvents(t *testing.T, d *Daemon, pattern string) (func() []Event, func()) {
	t.Helper()
	if d.bus == nil {
		t.Fatal("daemon bus not initialized")
	}
	ch, cancel := d.bus.Subscribe(pattern)
	var mu sync.Mutex
	var got []Event
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ev := range ch {
			mu.Lock()
			got = append(got, ev)
			mu.Unlock()
		}
	}()
	getter := func() []Event {
		mu.Lock()
		defer mu.Unlock()
		out := make([]Event, len(got))
		copy(out, got)
		return out
	}
	stop := func() {
		cancel()
		<-done
	}
	return getter, stop
}

// waitForEvent polls the getter until at least one event matches the
// predicate or the timeout elapses. Returns the matching event or the
// zero Event on timeout.
func waitForEvent(getter func() []Event, match func(Event) bool, timeout time.Duration) (Event, bool) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, ev := range getter() {
			if match(ev) {
				return ev, true
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	return Event{}, false
}

// initBusForTest replaces the test daemon's nil bus with a freshly
// constructed in-process bus rooted at the daemon's NodeID. Tests
// that bypass Start() must do this before any publishEvent call,
// otherwise the bus is nil and publishes silently no-op.
func initBusForTest(d *Daemon) {
	if d.bus == nil {
		d.bus = newInProcessBus(d.NodeID)
	}
}

// --- T4.3 capture-replay tests ----------------------------------------------

// TestNetworkJoinedEventEmitted verifies reconcileMembership publishes
// a network.joined bus event when the registry's authoritative
// membership list contains a network the daemon was not previously
// tracking.
func TestNetworkJoinedEventEmitted(t *testing.T) {
	t.Parallel()
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	defer rc.Close()
	reg.SetAdminToken("admin-token")

	// Owner creates a network with rules so the join payload carries
	// the rules field — exercises the full payload-build path.
	ownerID, _ := crypto.GenerateIdentity()
	ownerResp, err := rc.RegisterWithKey("127.0.0.1:5310", crypto.EncodePublicKey(ownerID.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("owner register: %v", err)
	}
	ownerNodeID := uint32(ownerResp["node_id"].(float64))

	createResp, err := rc.CreateNetwork(ownerNodeID, "joined-event-net", "open", "", "admin-token", false)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	netID := uint16(createResp["network_id"].(float64))

	// Self daemon joins the network.
	selfID, _ := crypto.GenerateIdentity()
	selfResp, err := rc.RegisterWithKey("127.0.0.1:5311", crypto.EncodePublicKey(selfID.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("self register: %v", err)
	}
	selfNodeID := uint32(selfResp["node_id"].(float64))

	if _, err := rc.JoinNetwork(selfNodeID, netID, "", 0, "admin-token"); err != nil {
		t.Fatalf("join: %v", err)
	}

	d := New(Config{AdminToken: "admin-token"})
	d.regConn = rc
	d.setNodeID_testhelper(selfNodeID)
	initBusForTest(d)

	getter, stop := captureBusEvents(t, d, "network.*")
	defer stop()

	d.reconcileMembership()

	ev, ok := waitForEvent(getter, func(ev Event) bool {
		if ev.Topic != TopicNetworkJoined {
			return false
		}
		id, _ := networkIDFromBusPayload(ev.Payload)
		return id == netID
	}, 2*time.Second)
	if !ok {
		t.Fatalf("expected %s event for network %d, got %v", TopicNetworkJoined, netID, getter())
	}
	if id, _ := networkIDFromBusPayload(ev.Payload); id != netID {
		t.Fatalf("network_id = %d, want %d", id, netID)
	}
	if _, ok := ev.Payload["member_tags"]; !ok {
		t.Fatal("payload missing member_tags field (must always be present)")
	}
}

// TestNetworkLeftEventEmitted verifies reconcileMembership publishes
// a network.left event when a previously-joined network drops out of
// the registry's membership list (e.g. via leave_network).
func TestNetworkLeftEventEmitted(t *testing.T) {
	t.Parallel()
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	defer rc.Close()
	reg.SetAdminToken("admin-token")

	ownerID, _ := crypto.GenerateIdentity()
	ownerResp, err := rc.RegisterWithKey("127.0.0.1:5320", crypto.EncodePublicKey(ownerID.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("owner register: %v", err)
	}
	ownerNodeID := uint32(ownerResp["node_id"].(float64))

	createResp, err := rc.CreateNetwork(ownerNodeID, "left-event-net", "open", "", "admin-token", false)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	netID := uint16(createResp["network_id"].(float64))

	selfID, _ := crypto.GenerateIdentity()
	selfResp, err := rc.RegisterWithKey("127.0.0.1:5321", crypto.EncodePublicKey(selfID.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("self register: %v", err)
	}
	selfNodeID := uint32(selfResp["node_id"].(float64))

	if _, err := rc.JoinNetwork(selfNodeID, netID, "", 0, "admin-token"); err != nil {
		t.Fatalf("join: %v", err)
	}

	d := New(Config{AdminToken: "admin-token"})
	d.regConn = rc
	d.setNodeID_testhelper(selfNodeID)
	initBusForTest(d)

	// First tick: observe the join so the network is in the known
	// set — required so the next reconcileMembership treats the
	// removal as a delta.
	d.reconcileMembership()

	if _, err := rc.LeaveNetwork(selfNodeID, netID, "admin-token"); err != nil {
		t.Fatalf("leave: %v", err)
	}

	getter, stop := captureBusEvents(t, d, "network.*")
	defer stop()

	d.reconcileMembership()

	_, ok := waitForEvent(getter, func(ev Event) bool {
		if ev.Topic != TopicNetworkLeft {
			return false
		}
		id, _ := networkIDFromBusPayload(ev.Payload)
		return id == netID
	}, 2*time.Second)
	if !ok {
		t.Fatalf("expected %s event for network %d, got %v", TopicNetworkLeft, netID, getter())
	}
}

// TestNetworkTagsChangedEventEmitted verifies reconcileMembership
// publishes a network.tags_changed event when the registry's
// authoritative member-tag list for a network differs from the
// previously-cached value.
func TestNetworkTagsChangedEventEmitted(t *testing.T) {
	t.Parallel()
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	defer rc.Close()
	reg.SetAdminToken("admin-token")

	ownerID, _ := crypto.GenerateIdentity()
	ownerResp, err := rc.RegisterWithKey("127.0.0.1:5330", crypto.EncodePublicKey(ownerID.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("owner register: %v", err)
	}
	ownerNodeID := uint32(ownerResp["node_id"].(float64))

	createResp, err := rc.CreateNetwork(ownerNodeID, "tags-event-net", "open", "", "admin-token", false)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	netID := uint16(createResp["network_id"].(float64))

	selfID, _ := crypto.GenerateIdentity()
	selfResp, err := rc.RegisterWithKey("127.0.0.1:5331", crypto.EncodePublicKey(selfID.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("self register: %v", err)
	}
	selfNodeID := uint32(selfResp["node_id"].(float64))

	if _, err := rc.JoinNetwork(selfNodeID, netID, "", 0, "admin-token"); err != nil {
		t.Fatalf("join: %v", err)
	}

	d := New(Config{AdminToken: "admin-token"})
	d.regConn = rc
	d.setNodeID_testhelper(selfNodeID)
	initBusForTest(d)

	// First tick: cache empty tag set; the join event itself fires
	// (tags = nil). The tag-diff for an unchanged-empty cache must
	// NOT emit network.tags_changed.
	d.reconcileMembership()

	// Mutate tags via the registry, then expect the next tick's
	// reconcile to publish network.tags_changed.
	if _, err := rc.SetMemberTags(netID, selfNodeID, []string{"alpha", "beta"}, "admin-token"); err != nil {
		t.Fatalf("set tags: %v", err)
	}

	getter, stop := captureBusEvents(t, d, "network.*")
	defer stop()

	d.reconcileMembership()

	ev, ok := waitForEvent(getter, func(ev Event) bool {
		if ev.Topic != TopicNetworkTagsChanged {
			return false
		}
		id, _ := networkIDFromBusPayload(ev.Payload)
		return id == netID
	}, 2*time.Second)
	if !ok {
		t.Fatalf("expected %s event for network %d, got %v", TopicNetworkTagsChanged, netID, getter())
	}
	tagsRaw, _ := ev.Payload["tags"].([]string)
	if len(tagsRaw) != 2 || tagsRaw[0] != "alpha" || tagsRaw[1] != "beta" {
		t.Fatalf("tags = %v, want [alpha beta]", tagsRaw)
	}
}

// TestNetworkJoinedReachesBusWildcard pins the property that
// publishing TopicNetworkJoined dispatches to a wildcard ("*")
// subscriber. The webhook plugin (plugins/webhook) subscribes to "*"
// at Start, so this is what guarantees network.* events reach the
// HTTP webhook downstream — without keeping a webhook field on the
// daemon (T4.1 moved that to the plugin). A regression that swapped
// "*" for "tunnel.*" in the bus matcher would surface here.
func TestNetworkJoinedReachesBusWildcard(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	initBusForTest(d)

	ch, unsub := d.bus.Subscribe("*")
	defer unsub()

	d.publishEvent(TopicNetworkJoined, map[string]any{
		"network_id":  uint16(7),
		"member_tags": []string{},
	})

	select {
	case ev := <-ch:
		if ev.Topic != TopicNetworkJoined {
			t.Fatalf("event topic = %q, want %q", ev.Topic, TopicNetworkJoined)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("network.joined did not reach wildcard subscriber within 2 s")
	}
}

// TestNetworkTagsChangedSuppressedWhenNoDelta ensures the daemon does
// NOT spam tags_changed events on every tick when the registry's tag
// list is unchanged. Otherwise managed-engine and downstream
// subscribers would react redundantly.
func TestNetworkTagsChangedSuppressedWhenNoDelta(t *testing.T) {
	t.Parallel()
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	defer rc.Close()
	reg.SetAdminToken("admin-token")

	ownerID, _ := crypto.GenerateIdentity()
	ownerResp, _ := rc.RegisterWithKey("127.0.0.1:5340", crypto.EncodePublicKey(ownerID.PublicKey), "", nil)
	ownerNodeID := uint32(ownerResp["node_id"].(float64))

	createResp, _ := rc.CreateNetwork(ownerNodeID, "tags-stable-net", "open", "", "admin-token", false)
	netID := uint16(createResp["network_id"].(float64))

	selfID, _ := crypto.GenerateIdentity()
	selfResp, _ := rc.RegisterWithKey("127.0.0.1:5341", crypto.EncodePublicKey(selfID.PublicKey), "", nil)
	selfNodeID := uint32(selfResp["node_id"].(float64))

	if _, err := rc.JoinNetwork(selfNodeID, netID, "", 0, "admin-token"); err != nil {
		t.Fatalf("join: %v", err)
	}
	if _, err := rc.SetMemberTags(netID, selfNodeID, []string{"x"}, "admin-token"); err != nil {
		t.Fatalf("set tags: %v", err)
	}

	d := New(Config{AdminToken: "admin-token"})
	d.regConn = rc
	d.setNodeID_testhelper(selfNodeID)
	initBusForTest(d)

	// First tick: cache populated with [x]; no prior cache, so the
	// initial tags_changed for [x] is allowed (cache had nil; new is
	// [x]). Drain it.
	d.reconcileMembership()

	getter, stop := captureBusEvents(t, d, "network.tags_changed")
	defer stop()

	// Second tick with unchanged tags must not publish.
	d.reconcileMembership()

	time.Sleep(100 * time.Millisecond)
	if events := getter(); len(events) != 0 {
		t.Fatalf("expected no tags_changed events on stable cache, got %v", events)
	}
}
