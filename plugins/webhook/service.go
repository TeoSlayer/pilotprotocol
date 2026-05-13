// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !no_webhook
// +build !no_webhook

package webhook

import (
	"context"
	"log/slog"
	"sync"

	"github.com/TeoSlayer/pilotprotocol/pkg/coreapi"
)

// Service is the L11 plugin that delivers core daemon events to an
// HTTP(S) endpoint. Implements coreapi.Service: on Start, subscribes
// to the bus ("*") and forwards every event to its internal Client.
// On Stop, cancels the subscription and drains the Client.
//
// The URL can be hot-swapped at runtime via SetURL — that path is
// invoked from cmd/daemon when IPC's set-webhook handler fires.
//
// As of the topic-filter change, the bridge optionally consults a
// per-Service allow-list before forwarding; empty allow-list = legacy
// "forward every event" behavior. See SetTopics for the operator path.
type Service struct {
	mu sync.Mutex

	initialURL string
	opts       []Option

	deps   coreapi.Deps
	client *Client
	cancel func()
	done   chan struct{}

	// topics is the optional event-topic allow-list. nil/empty = forward
	// all events (legacy behavior). When set, the bridge loop matches
	// ev.Topic against this set and drops misses. Read/written under mu.
	topics map[string]struct{}
}

// Stats is the snapshot of per-Client counters needed by daemon's
// DaemonInfo response. Returned by (*Service).Stats(); each call
// reads the underlying atomics. Nil-safe at the Service level —
// returns the zero value if no Client is configured.
type Stats struct {
	Dropped      uint64
	CircuitSkips uint64
}

// NewService constructs a webhook plugin Service. initialURL is taken
// from the daemon's -webhook flag; if empty, the plugin tries the
// persisted URL file (~/.pilot/webhook_url) on Start.
func NewService(initialURL string, opts ...Option) *Service {
	return &Service{initialURL: initialURL, opts: opts}
}

// --- coreapi.Service ---

func (s *Service) Name() string { return "webhook" }

// Order: webhook starts AFTER core foundation (50-79: trust/identity)
// but BEFORE app services (100+) so it captures their startup events
// (node.registered, agent.registered, network.auto_joined). 90 is the
// observability slot per coreapi/lifecycle.go.
func (s *Service) Order() int { return 90 }

func (s *Service) Start(_ context.Context, deps coreapi.Deps) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deps = deps

	url := s.initialURL
	if url == "" {
		if persisted, err := LoadPersistedURL(); err == nil && persisted != "" {
			url = persisted
		}
	}
	// Load the persisted topic allow-list, if any. Missing file = nil
	// map = forward-all (pre-filter behavior).
	if topics, err := LoadPersistedTopics(); err == nil && len(topics) > 0 {
		s.topics = topicSet(topics)
	}
	s.startClientLocked(url)
	return nil
}

// topicSet converts a list into the lookup set used on the hot path.
// Caller owns the input slice; the returned map is a fresh allocation.
func topicSet(topics []string) map[string]struct{} {
	m := make(map[string]struct{}, len(topics))
	for _, t := range topics {
		if t == "" {
			continue
		}
		m[t] = struct{}{}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

func (s *Service) Stop(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopClientLocked()
	return nil
}

// SetURL hot-swaps the webhook URL. Called from cmd/daemon's IPC
// adapter when `pilotctl set-webhook <url>` fires. An empty url
// disables webhook delivery (becomes a no-op until set again).
func (s *Service) SetURL(url string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopClientLocked()
	s.startClientLocked(url)
	if err := SavePersistedURL(url); err != nil {
		slog.Warn("failed to persist webhook URL", "err", err)
	}
	if url != "" {
		slog.Info("webhook updated", "url", url)
	} else {
		slog.Info("webhook cleared")
	}
}

// SetTopics swaps the event-topic allow-list. An empty / nil slice
// disables filtering (forward every event — pre-filter default).
// Persists to ~/.pilot/webhook_topics so it survives daemon restart.
// The bridge goroutine doesn't have to be restarted — it reads the
// filter from the Service on every event under s.mu.
func (s *Service) SetTopics(topics []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.topics = topicSet(topics)
	if err := SavePersistedTopics(topics); err != nil {
		slog.Warn("failed to persist webhook topics", "err", err)
	}
	if len(s.topics) == 0 {
		slog.Info("webhook topic filter cleared (forwarding all events)")
	} else {
		slog.Info("webhook topic filter updated", "count", len(s.topics))
	}
}

// Topics returns the current allow-list as a sorted slice for
// inspection by daemon Info() / pilotctl introspection. Nil/empty
// return means "forward all."
func (s *Service) Topics() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.topics) == 0 {
		return nil
	}
	out := make([]string, 0, len(s.topics))
	for t := range s.topics {
		out = append(out, t)
	}
	return out
}

// Stats returns dispatcher counters for the daemon's Info() response.
// Nil-safe across "no client configured" and "service stopped."
func (s *Service) Stats() Stats {
	s.mu.Lock()
	c := s.client
	s.mu.Unlock()
	if c == nil {
		return Stats{}
	}
	return Stats{
		Dropped:      c.Dropped(),
		CircuitSkips: c.CircuitSkips(),
	}
}

// startClientLocked builds a fresh Client for url and wires the
// bus → Client subscriber loop. Caller holds s.mu. No-op if url == "".
func (s *Service) startClientLocked(url string) {
	if s.deps.Events == nil {
		return
	}
	if url == "" {
		return
	}
	nodeID := func() uint32 {
		if s.deps.Identity == nil {
			return 0
		}
		return s.deps.Identity.NodeID()
	}
	s.client = NewClient(url, nodeID, s.opts...)
	if s.client == nil {
		return
	}
	ch, cancel := s.deps.Events.Subscribe("*")
	s.cancel = cancel
	done := make(chan struct{})
	s.done = done
	wc := s.client
	events := s.deps.Events
	svc := s // captured for the filter probe; the map is read under svc.mu
	go func() {
		defer close(done)
		// L11 panic boundary: a panic in Emit (or in the channel
		// receive path) must not kill the webhook bridge goroutine.
		// TODO(03-INVARIANTS.md §8): per-plugin supervisor would
		// restart the bridge.
		defer coreapi.RecoverPlugin("webhook", "bridgeLoop", events, nil)
		for ev := range ch {
			// Topic filter, if configured. Holding mu briefly is cheap
			// here — the map lookup is O(1) and contention is bounded
			// by the rare SetTopics call. nil map = forward everything.
			svc.mu.Lock()
			topics := svc.topics
			svc.mu.Unlock()
			if topics != nil {
				if _, ok := topics[ev.Topic]; !ok {
					continue
				}
			}
			wc.Emit(ev.Topic, ev.Payload)
		}
	}()
}

// stopClientLocked cancels the bus subscription, waits for the bridge
// goroutine to exit (synchronous so Close can drain the queue), and
// closes the underlying Client. Caller holds s.mu.
func (s *Service) stopClientLocked() {
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	if s.done != nil {
		<-s.done
		s.done = nil
	}
	if s.client != nil {
		s.client.Close()
		s.client = nil
	}
}

// Compile-time guard.
var _ coreapi.Service = (*Service)(nil)
