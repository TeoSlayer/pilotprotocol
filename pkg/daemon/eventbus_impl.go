// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"github.com/pilot-protocol/common/daemonapi"
	"strings"
	"sync"
	"time"
)

// Event is the daemon-local view of a published event. plugins/runtime
// adapts this to coreapi.Event when wrapping the bus for plugin Deps.
// Defined here (instead of importing pkg/coreapi) to keep pkg/daemon
// free of L10 imports (T7.1).
type Event = daemonapi.Event

// inProcessBus is the daemon's in-memory pub/sub event bus.
//
// Publish is non-blocking with a per-subscriber bounded buffer.
// Subscribers slower than the publish rate observe drops at their
// own channel; the publisher continues regardless.
type inProcessBus struct {
	mu          sync.RWMutex
	subscribers []*busSubscription
	getNodeID   func() uint32
}

type busSubscription struct {
	pattern string
	ch      chan Event
}

const busSubscriptionBuffer = 1024

func newInProcessBus(getNodeID func() uint32) *inProcessBus {
	return &inProcessBus{getNodeID: getNodeID}
}

func (b *inProcessBus) Publish(topic string, payload map[string]any) {
	if b == nil {
		return
	}
	var nodeID uint32
	if b.getNodeID != nil {
		nodeID = b.getNodeID()
	}
	ev := Event{
		Topic:   topic,
		NodeID:  nodeID,
		Time:    time.Now().UTC(),
		Payload: payload,
	}
	// Hold RLock for the entire iteration. The non-blocking send below
	// is safe under RLock; unsubscribers (which take Lock to close
	// sub.ch) wait until iteration completes. Without this, a
	// concurrent unsubscribe could close sub.ch between our snapshot
	// and the select, causing a send-on-closed-channel panic.
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, s := range b.subscribers {
		if !matchPattern(s.pattern, topic) {
			continue
		}
		select {
		case s.ch <- ev:
		default:
			// drop — slow subscriber
		}
	}
}

func (b *inProcessBus) Subscribe(pattern string) (<-chan Event, func()) {
	if b == nil {
		ch := make(chan Event)
		close(ch)
		return ch, func() {}
	}
	sub := &busSubscription{
		pattern: pattern,
		ch:      make(chan Event, busSubscriptionBuffer),
	}
	b.mu.Lock()
	b.subscribers = append(b.subscribers, sub)
	b.mu.Unlock()
	return sub.ch, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		// Fresh backing array — never reuse b.subscribers[:0] because
		// any in-flight Publish snapshot would alias the same array
		// and observe writes mid-iteration.
		out := make([]*busSubscription, 0, len(b.subscribers))
		for _, s := range b.subscribers {
			if s == sub {
				continue
			}
			out = append(out, s)
		}
		b.subscribers = out
		// Closing sub.ch under Lock is safe: any concurrent Publish is
		// blocked on RLock; once we Unlock, Publish (re)acquires
		// RLock and rebuilds its iteration view, which no longer
		// contains `sub`.
		close(sub.ch)
	}
}

func matchPattern(pattern, topic string) bool {
	if pattern == "*" || pattern == "" {
		return true
	}
	if strings.HasSuffix(pattern, ".*") {
		prefix := strings.TrimSuffix(pattern, ".*")
		return strings.HasPrefix(topic, prefix+".")
	}
	return pattern == topic
}
