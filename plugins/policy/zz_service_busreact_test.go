// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !no_policy
// +build !no_policy

package policy

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/coreapi"
)

// stubBus is the minimal coreapi.EventBus used by the bus-reaction
// tests below. It supports a single subscriber (the policy Service)
// and exposes Publish so the test can inject network.* events.
type stubBus struct {
	mu          sync.Mutex
	subscribers []chan coreapi.Event
	closed      []bool
}

func newStubBus() *stubBus { return &stubBus{} }

func (b *stubBus) Publish(topic string, payload map[string]any) {
	b.mu.Lock()
	subs := append([]chan coreapi.Event(nil), b.subscribers...)
	b.mu.Unlock()
	ev := coreapi.Event{
		Topic:   topic,
		Time:    time.Now().UTC(),
		Payload: payload,
	}
	for _, ch := range subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

func (b *stubBus) Subscribe(_ string) (<-chan coreapi.Event, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	idx := len(b.subscribers)
	ch := make(chan coreapi.Event, 16)
	b.subscribers = append(b.subscribers, ch)
	b.closed = append(b.closed, false)
	cancel := func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if !b.closed[idx] {
			b.closed[idx] = true
			close(ch)
		}
	}
	return ch, cancel
}

// TestPolicyPluginReactsToNetworkJoined verifies the bus-inversion
// contract for T4.3: when reconcileMembership emits network.joined
// with a non-empty expr_policy, the policy plugin starts a runner
// (mirroring what the old syncPolicyRunners did via direct
// daemon→plugin calls).
func TestPolicyPluginReactsToNetworkJoined(t *testing.T) {
	t.Parallel()
	bus := newStubBus()
	svc := NewService(&fakeRuntime{})
	t.Cleanup(func() { _ = svc.Stop(context.Background()) })

	if err := svc.Start(context.Background(), coreapi.Deps{Events: bus}); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// allow_all expr policy — minimal valid JSON the policy parser
	// accepts. Same shape registry's get_expr_policy returns when
	// stored as a string (see daemon syncPolicyRunners pre-T4.3).
	bus.Publish("network.joined", map[string]any{
		"network_id":  uint16(42),
		"expr_policy": `{"version":1,"rules":[{"name":"r1","on":"connect","match":"true","actions":[{"type":"allow"}]}]}`,
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if svc.Manager().Get(42) != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if svc.Manager().Get(42) == nil {
		t.Fatal("expected policy runner for network 42 after network.joined event")
	}
}

// TestPolicyPluginReactsToNetworkLeft verifies the symmetric path:
// network.left stops a previously-started runner.
func TestPolicyPluginReactsToNetworkLeft(t *testing.T) {
	t.Parallel()
	bus := newStubBus()
	svc := NewService(&fakeRuntime{})
	t.Cleanup(func() { _ = svc.Stop(context.Background()) })

	if err := svc.Start(context.Background(), coreapi.Deps{Events: bus}); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Pre-seed: start a runner via the manager view, then publish leave.
	if _, err := svc.Manager().Start(99, []byte(`{"version":1,"rules":[{"name":"r1","on":"connect","match":"true","actions":[{"type":"allow"}]}]}`)); err != nil {
		t.Fatalf("seed runner: %v", err)
	}
	if svc.Manager().Get(99) == nil {
		t.Fatal("seed precondition: runner should exist")
	}

	bus.Publish("network.left", map[string]any{"network_id": uint16(99)})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if svc.Manager().Get(99) == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if svc.Manager().Get(99) != nil {
		t.Fatal("expected policy runner to be stopped after network.left event")
	}
}

// TestPolicyPluginIgnoresJoinedWithoutExprPolicy: networks without an
// expr_policy must not cause a runner to spin up. Mirrors the
// has_expr_policy=false skip in the old syncPolicyRunners.
func TestPolicyPluginIgnoresJoinedWithoutExprPolicy(t *testing.T) {
	t.Parallel()
	bus := newStubBus()
	svc := NewService(&fakeRuntime{})
	t.Cleanup(func() { _ = svc.Stop(context.Background()) })

	if err := svc.Start(context.Background(), coreapi.Deps{Events: bus}); err != nil {
		t.Fatalf("Start: %v", err)
	}

	bus.Publish("network.joined", map[string]any{
		"network_id": uint16(7),
	})

	// Give the dispatcher goroutine a tick to process and (correctly)
	// ignore the event.
	time.Sleep(50 * time.Millisecond)

	if svc.Manager().Get(7) != nil {
		t.Fatal("must not start a runner without expr_policy in payload")
	}
}

// TestPolicyPluginJoinedAcceptsObjectExprPolicy: registry's
// GetExprPolicy returns the expr_policy as a parsed object when the
// stored value is JSON. The reconciler forwards that as-is in the
// payload — the plugin must Marshal it back into bytes for Parse.
func TestPolicyPluginJoinedAcceptsObjectExprPolicy(t *testing.T) {
	t.Parallel()
	bus := newStubBus()
	svc := NewService(&fakeRuntime{})
	t.Cleanup(func() { _ = svc.Stop(context.Background()) })

	if err := svc.Start(context.Background(), coreapi.Deps{Events: bus}); err != nil {
		t.Fatalf("Start: %v", err)
	}

	bus.Publish("network.joined", map[string]any{
		"network_id": uint16(5),
		"expr_policy": map[string]any{
			"version": float64(1),
			"rules": []any{
				map[string]any{
					"name":    "r1",
					"on":      "connect",
					"match":   "true",
					"actions": []any{map[string]any{"type": "allow"}},
				},
			},
		},
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if svc.Manager().Get(5) != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if svc.Manager().Get(5) == nil {
		t.Fatal("expected runner for network 5 after object-form expr_policy")
	}
}
