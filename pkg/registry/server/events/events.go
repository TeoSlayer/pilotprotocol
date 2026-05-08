// SPDX-License-Identifier: AGPL-3.0-or-later

// Package events provides an in-process publish/subscribe event bus for
// the registry server's internal layers (R2-R7) to communicate without
// importing each other.
//
// The bus is the structural fix for the R5 sibling rule defined in
// architecture-notes/07-REGISTRY-LAYERS.md: directory, membership,
// trust, policy, polo, identity, and routing stores never import each
// other. Cross-store side effects (e.g. directory cache invalidation
// when membership changes, key-index updates when identity rotates a
// key) flow through Bus.Publish / Bus.Subscribe instead.
//
// Same shape as pkg/coreapi.EventBus on the daemon side; different
// package because the registry server's L8 surface is distinct from
// the daemon's L10 plugin ABI.
//
// This file is Tier R0.2 of the registry-server extraction plan
// (architecture-notes/08-REGISTRY-EXTRACTION.md). It has zero
// consumers; subsequent tiers wire it into existing handlers.
package events

import (
	"strings"
	"sync"
)

// Event is one item published to the Bus. Source is the publishing
// store ("directory", "membership", "trust", ...). Type is the
// dot-namespaced event name within that source ("node.deleted",
// "membership.changed", "key.rotated", ...). Payload keys/values are
// publisher-defined; subscribers parse them.
type Event struct {
	Source  string
	Type    string
	Payload map[string]any
}

// Bus is the publish/subscribe surface every R-layer codes against.
//
// Publish is non-blocking. If a subscriber's channel is full, the event
// is dropped for THAT subscriber only; the publisher and other
// subscribers are unaffected. This keeps mutation-handler latency
// bounded regardless of subscriber speed.
//
// Subscribe returns a buffered channel and an unsubscribe func. The
// pattern is matched against Event.Type. Patterns ending in ".*" match
// any Type beginning with the prefix (e.g. "membership.*" matches
// "membership.changed" and "membership.created" but not "membership").
// A bare "*" matches every Type. Any other pattern matches Type
// exactly. Source is not part of pattern matching today.
//
// The unsubscribe func removes the subscription and closes the channel.
// It is safe to call exactly once; further calls are no-ops.
type Bus interface {
	Publish(evt Event)
	Subscribe(pattern string) (<-chan Event, func())
}

// NewInProcessBus returns an in-memory Bus. bufSize is the per-subscriber
// channel capacity; values <=0 fall back to defaultBufSize. Each
// subscriber gets its own independent buffer so a slow consumer cannot
// stall the publisher or peer subscribers.
func NewInProcessBus(bufSize int) Bus {
	if bufSize <= 0 {
		bufSize = defaultBufSize
	}
	return &inProcessBus{bufSize: bufSize}
}

const defaultBufSize = 1024

type inProcessBus struct {
	mu          sync.RWMutex
	subscribers []*subscription
	bufSize     int
}

type subscription struct {
	pattern string
	ch      chan Event
	once    sync.Once
}

func (b *inProcessBus) Publish(evt Event) {
	if b == nil {
		return
	}
	// Hold RLock for the entire iteration. The non-blocking send below
	// is safe under RLock; unsubscribers (which take Lock to close
	// sub.ch) wait until iteration completes. Without this, a
	// concurrent unsubscribe could close sub.ch between our match check
	// and the select, causing a send-on-closed-channel panic.
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, s := range b.subscribers {
		if !matchPattern(s.pattern, evt.Type) {
			continue
		}
		select {
		case s.ch <- evt:
		default:
			// drop — slow subscriber. Per-subscriber drop policy keeps
			// the publisher and peer subscribers unaffected.
		}
	}
}

func (b *inProcessBus) Subscribe(pattern string) (<-chan Event, func()) {
	if b == nil {
		ch := make(chan Event)
		close(ch)
		return ch, func() {}
	}
	sub := &subscription{
		pattern: pattern,
		ch:      make(chan Event, b.bufSize),
	}
	b.mu.Lock()
	b.subscribers = append(b.subscribers, sub)
	b.mu.Unlock()

	unsubscribe := func() {
		sub.once.Do(func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			// Fresh backing array — never reuse b.subscribers[:0]
			// because any in-flight Publish snapshot would alias the
			// same array and observe writes mid-iteration.
			out := make([]*subscription, 0, len(b.subscribers))
			for _, s := range b.subscribers {
				if s == sub {
					continue
				}
				out = append(out, s)
			}
			b.subscribers = out
			// Closing sub.ch under Lock is safe: any concurrent Publish
			// is blocked on RLock; once we Unlock, Publish (re)acquires
			// RLock and rebuilds its iteration view, which no longer
			// contains `sub`.
			close(sub.ch)
		})
	}
	return sub.ch, unsubscribe
}

// matchPattern reports whether eventType satisfies pattern.
// "*" or "" matches everything; "prefix.*" matches any type beginning
// with "prefix."; any other pattern requires an exact match.
func matchPattern(pattern, eventType string) bool {
	if pattern == "*" || pattern == "" {
		return true
	}
	if strings.HasSuffix(pattern, ".*") {
		prefix := strings.TrimSuffix(pattern, ".*")
		return strings.HasPrefix(eventType, prefix+".")
	}
	return pattern == eventType
}
