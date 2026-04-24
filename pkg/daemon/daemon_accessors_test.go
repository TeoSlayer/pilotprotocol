// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"encoding/json"
	"net"
	"reflect"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/policy"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

// --- SetMemberTags / GetMemberTags ---

func TestSetAndGetMemberTagsEmptyByDefault(t *testing.T) {
	d := New(Config{})
	if got := d.GetMemberTags(42); got != nil {
		t.Fatalf("GetMemberTags(42) = %v, want nil", got)
	}
}

func TestSetMemberTagsRoundTrip(t *testing.T) {
	d := New(Config{})
	want := []string{"alpha", "beta", "gamma"}
	d.SetMemberTags(7, want)
	got := d.GetMemberTags(7)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("GetMemberTags(7) = %v, want %v", got, want)
	}
}

func TestSetMemberTagsIsScopedPerNetwork(t *testing.T) {
	d := New(Config{})
	d.SetMemberTags(1, []string{"one"})
	d.SetMemberTags(2, []string{"two"})
	if got := d.GetMemberTags(1); !reflect.DeepEqual(got, []string{"one"}) {
		t.Fatalf("network 1 tags = %v, want [one]", got)
	}
	if got := d.GetMemberTags(2); !reflect.DeepEqual(got, []string{"two"}) {
		t.Fatalf("network 2 tags = %v, want [two]", got)
	}
}

func TestSetMemberTagsOverwritesPrevious(t *testing.T) {
	d := New(Config{})
	d.SetMemberTags(3, []string{"old"})
	d.SetMemberTags(3, []string{"new", "newer"})
	if got := d.GetMemberTags(3); !reflect.DeepEqual(got, []string{"new", "newer"}) {
		t.Fatalf("tags = %v, want [new newer]", got)
	}
}

func TestSetMemberTagsAcceptsNilSlice(t *testing.T) {
	d := New(Config{})
	d.SetMemberTags(5, []string{"something"})
	d.SetMemberTags(5, nil) // clear
	if got := d.GetMemberTags(5); got != nil {
		t.Fatalf("expected nil after clearing; got %v", got)
	}
}

// --- GetManagedEngine / StartManagedEngine / StopManagedEngine ---

func TestGetManagedEngineNilWhenAbsent(t *testing.T) {
	d := New(Config{})
	if me := d.GetManagedEngine(99); me != nil {
		t.Fatalf("GetManagedEngine(99) = %p, want nil", me)
	}
}

// newTestManagedEngine builds a ManagedEngine without a daemon wire-up and with
// a seeded peer map so cycleLoop skips the regConn-dependent Bootstrap path.
func newTestManagedEngine(d *Daemon, netID uint16) *ManagedEngine {
	me := NewManagedEngine(netID, &registry.NetworkRules{Cycle: "10s"}, d)
	// Seed a dummy peer so cycleLoop's `needBootstrap` branch is false.
	me.peers[1] = &managedPeer{NodeID: 1}
	return me
}

func TestStartManagedEngineRegistersAndCanBeRetrieved(t *testing.T) {
	d := New(Config{})
	// Insert directly to avoid the goroutine started by the public API,
	// which would try to call into a nil regConn.
	me := newTestManagedEngine(d, 100)
	d.managedMu.Lock()
	d.managed[100] = me
	d.managedMu.Unlock()

	got := d.GetManagedEngine(100)
	if got != me {
		t.Fatalf("GetManagedEngine(100) = %p, want %p", got, me)
	}
	if got.netID != 100 {
		t.Fatalf("netID = %d, want 100", got.netID)
	}
}

func TestStartManagedEngineIsIdempotent(t *testing.T) {
	d := New(Config{})
	// Pre-register directly; StartManagedEngine should detect existing entry
	// and early-return WITHOUT constructing + starting a new engine (which
	// would try to start a goroutine that needs a live regConn).
	first := newTestManagedEngine(d, 101)
	d.managedMu.Lock()
	d.managed[101] = first
	d.managedMu.Unlock()

	d.StartManagedEngine(101, &registry.NetworkRules{Cycle: "10s"})

	second := d.GetManagedEngine(101)
	if first != second {
		t.Fatalf("StartManagedEngine should not replace existing engine (got %p, want %p)", second, first)
	}
}

func TestStopManagedEngineRemovesEntry(t *testing.T) {
	d := New(Config{})
	me := newTestManagedEngine(d, 102)
	// We must Start() so that Stop() can drain <-done. Pre-seeded peers make
	// cycleLoop skip Bootstrap, and the 10s ticker won't fire before we Stop.
	me.Start()
	d.managedMu.Lock()
	d.managed[102] = me
	d.managedMu.Unlock()

	d.StopManagedEngine(102)
	if got := d.GetManagedEngine(102); got != nil {
		t.Fatalf("engine should be removed after StopManagedEngine; got %p", got)
	}
}

func TestStopManagedEngineMissingIsNoop(t *testing.T) {
	d := New(Config{})
	// No panic, no hang.
	d.StopManagedEngine(12345)
}

// --- GetPolicyRunner / StartPolicyRunner / StopPolicyRunner ---

func TestGetPolicyRunnerNilWhenAbsent(t *testing.T) {
	d := New(Config{})
	if pr := d.GetPolicyRunner(200); pr != nil {
		t.Fatalf("GetPolicyRunner(200) = %p, want nil", pr)
	}
}

func TestStartPolicyRunnerInvalidJSONReturnsError(t *testing.T) {
	d := New(Config{})
	err := d.StartPolicyRunner(201, json.RawMessage("{not json"))
	if err == nil {
		t.Fatalf("expected parse error for invalid JSON")
	}
}

// newTestPolicyRunner builds a PolicyRunner via NewPolicyRunner + Start with a
// valid compiled policy, relying on the fact that cycleLoop's bootstrap
// function logs-and-continues on a nil regConn-derived failure. If bootstrap
// fails because fetchMembersWithTags panics, we cannot use Start — instead we
// pre-register the runner directly in the map.

func TestStopPolicyRunnerMissingIsNoop(t *testing.T) {
	d := New(Config{})
	d.StopPolicyRunner(0xFFFF) // should not panic
}

func TestGetPolicyRunnerReturnsRegisteredInstance(t *testing.T) {
	d := New(Config{})
	// Build a compiled policy + runner WITHOUT calling Start (which would
	// spawn a goroutine that touches nil regConn).
	doc, err := policy.Parse(json.RawMessage(`{"version":1,"rules":[{"name":"r1","on":"connect","match":"true","actions":[{"type":"allow"}]}]}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cp, err := policy.Compile(doc)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pr := NewPolicyRunner(250, cp, d)
	d.policyMu.Lock()
	d.policyRunners[250] = pr
	d.policyMu.Unlock()

	if got := d.GetPolicyRunner(250); got != pr {
		t.Fatalf("GetPolicyRunner(250) = %p, want %p", got, pr)
	}
}

func TestStopPolicyRunnerRemovesEntryFromMap(t *testing.T) {
	d := New(Config{})
	doc, err := policy.Parse(json.RawMessage(`{"version":1,"rules":[{"name":"r1","on":"connect","match":"true","actions":[{"type":"allow"}]}]}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cp, err := policy.Compile(doc)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pr := NewPolicyRunner(251, cp, d)
	// Pre-close both channels so pr.Stop() (which waits on <-done) doesn't
	// block us — we don't need to exercise the real cycleLoop here.
	close(pr.stopCh)
	close(pr.done)
	d.policyMu.Lock()
	d.policyRunners[251] = pr
	d.policyMu.Unlock()

	d.StopPolicyRunner(251)
	if got := d.GetPolicyRunner(251); got != nil {
		t.Fatalf("runner should be removed; got %p", got)
	}
}

// --- Trivial accessors ---

func TestDaemonIdentityNilByDefault(t *testing.T) {
	d := New(Config{})
	if id := d.Identity(); id != nil {
		t.Fatalf("Identity() = %p, want nil", id)
	}
}

func TestDaemonTaskQueueNonNil(t *testing.T) {
	d := New(Config{})
	if q := d.TaskQueue(); q == nil {
		t.Fatalf("TaskQueue() should be non-nil")
	}
}

func TestDaemonAddTunnelPeerRegistersPeer(t *testing.T) {
	d := New(Config{})
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
	d.AddTunnelPeer(42, addr)
	if !d.tunnels.HasPeer(42) {
		t.Fatalf("AddTunnelPeer should register peer 42")
	}
}

func TestDaemonTunnelAddrNilBeforeListen(t *testing.T) {
	d := New(Config{})
	if a := d.TunnelAddr(); a != nil {
		t.Fatalf("TunnelAddr before Listen = %v, want nil", a)
	}
}

func TestDaemonTunnelAddrPopulatedAfterListen(t *testing.T) {
	d := New(Config{})
	if err := d.tunnels.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer d.tunnels.Close()
	if a := d.TunnelAddr(); a == nil {
		t.Fatalf("TunnelAddr after Listen should be non-nil")
	}
}

func TestDaemonAddrZeroValueByDefault(t *testing.T) {
	d := New(Config{})
	a := d.Addr()
	zero := protocol.Addr{}
	if a != zero {
		t.Fatalf("Addr() default = %v, want zero", a)
	}
}

// --- stopping() ---

func TestStoppingFalseBeforeStop(t *testing.T) {
	d := New(Config{})
	if d.stopping() {
		t.Fatalf("stopping() should be false before Stop")
	}
}

func TestStoppingTrueAfterStopChClosed(t *testing.T) {
	d := New(Config{})
	// We don't want to run the full Stop() (it touches tunnels/ipc/webhook),
	// so just close the stop channel directly to exercise stopping().
	close(d.stopCh)
	if !d.stopping() {
		t.Fatalf("stopping() should be true after stopCh is closed")
	}
}

// --- stopManaged / stopPolicyRunners no-op on empty maps ---

func TestStopManagedOnEmptyMapIsNoop(t *testing.T) {
	d := New(Config{})
	d.stopManaged() // must not panic or deadlock
}

func TestStopPolicyRunnersOnEmptyMapIsNoop(t *testing.T) {
	d := New(Config{})
	d.stopPolicyRunners()
}

// --- stopManaged stops pre-registered engines ---

func TestStopManagedStopsAllRegisteredEngines(t *testing.T) {
	d := New(Config{})
	me1 := newTestManagedEngine(d, 300)
	me1.Start()
	me2 := newTestManagedEngine(d, 301)
	me2.Start()
	d.managedMu.Lock()
	d.managed[300] = me1
	d.managed[301] = me2
	d.managedMu.Unlock()

	// stopManaged does NOT delete from the map; it only stops them.
	d.stopManaged()

	// Subsequent StopManagedEngine is idempotent on already-stopped engines.
	d.StopManagedEngine(300)
	d.StopManagedEngine(301)
}

// --- stopPolicyRunners stops pre-registered runners ---

func TestStopPolicyRunnersStopsAllRegisteredRunners(t *testing.T) {
	d := New(Config{})
	doc, err := policy.Parse(json.RawMessage(`{"version":1,"rules":[{"name":"r1","on":"connect","match":"true","actions":[{"type":"allow"}]}]}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cp, err := policy.Compile(doc)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pr1 := NewPolicyRunner(400, cp, d)
	close(pr1.stopCh)
	close(pr1.done)
	pr2 := NewPolicyRunner(401, cp, d)
	close(pr2.stopCh)
	close(pr2.done)
	d.policyMu.Lock()
	d.policyRunners[400] = pr1
	d.policyRunners[401] = pr2
	d.policyMu.Unlock()

	d.stopPolicyRunners()
	// Map is not cleared, but runners are stopped; explicit StopPolicyRunner is idempotent.
	d.StopPolicyRunner(400)
	d.StopPolicyRunner(401)
}

// --- peerTagsFor (canonical peer-tag merge for policy evaluator) ---

func TestPeerTagsForReturnsEmptyWhenNoSources(t *testing.T) {
	d := New(Config{})
	t.Cleanup(func() { d.handshakes.Stop() })
	got := d.peerTagsFor(42, nil)
	if len(got) != 0 {
		t.Fatalf("peerTagsFor with no sources = %v, want empty", got)
	}
}

func TestPeerTagsForMergesNodeInfoAndLocal(t *testing.T) {
	d := New(Config{})
	t.Cleanup(func() { d.handshakes.Stop() })
	d.cacheResolve(42, map[string]interface{}{
		"tags": []interface{}{"service", "prod"},
	})
	got := d.peerTagsFor(42, []string{"vip"})
	want := []string{"service", "prod", "vip"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("peerTagsFor = %v, want %v", got, want)
	}
}

func TestPeerTagsForDedupsAcrossSources(t *testing.T) {
	d := New(Config{})
	t.Cleanup(func() { d.handshakes.Stop() })
	d.cacheResolve(42, map[string]interface{}{
		"tags": []interface{}{"service", "shared"},
	})
	got := d.peerTagsFor(42, []string{"shared", "vip"})
	want := []string{"service", "shared", "vip"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("peerTagsFor dedup = %v, want %v", got, want)
	}
}

func TestPeerTagsForReturnsNodeInfoOnlyWhenNoLocal(t *testing.T) {
	d := New(Config{})
	t.Cleanup(func() { d.handshakes.Stop() })
	d.cacheResolve(42, map[string]interface{}{
		"tags": []interface{}{"service"},
	})
	got := d.peerTagsFor(42, nil)
	if !reflect.DeepEqual(got, []string{"service"}) {
		t.Fatalf("peerTagsFor NodeInfo-only = %v, want [service]", got)
	}
}

func TestPeerTagsForIgnoresNonStringTagEntries(t *testing.T) {
	d := New(Config{})
	t.Cleanup(func() { d.handshakes.Stop() })
	d.cacheResolve(42, map[string]interface{}{
		"tags": []interface{}{"service", 12345, nil, "prod"},
	})
	got := d.peerTagsFor(42, nil)
	if !reflect.DeepEqual(got, []string{"service", "prod"}) {
		t.Fatalf("peerTagsFor skip non-string = %v, want [service prod]", got)
	}
}
