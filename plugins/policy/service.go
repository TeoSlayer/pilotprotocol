// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !no_policy
// +build !no_policy

package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/TeoSlayer/pilotprotocol/pkg/coreapi"
)

// Service is the L11 plugin adapter for the policy runtime. It owns
// the per-network registry of running PolicyRunner instances and
// satisfies coreapi.PolicyManager so the daemon can hold it via
// interface.
//
// Constructed by cmd/daemon (L12) with a Runtime adapter that wraps
// the daemon's internals (NodeID, regConn, handshakes, bus).
type Service struct {
	runtime Runtime

	mu      sync.RWMutex
	runners map[uint16]*PolicyRunner

	// network.* event subscriber wiring. subStop is the cancel func
	// returned from coreapi.EventBus.Subscribe; subDone closes once
	// the dispatcher goroutine has drained. Both are nil when no Deps
	// were passed to Start (e.g. unit tests that bypass the runtime).
	subStop func()
	subDone chan struct{}
}

func NewService(runtime Runtime) *Service {
	return &Service{
		runtime: runtime,
		runners: make(map[uint16]*PolicyRunner),
	}
}

// --- coreapi.Service ---

func (s *Service) Name() string { return "policy" }
func (s *Service) Order() int   { return 140 }

// Start wires the network.* bus subscriber. The handler reacts to
// network.joined / network.left events emitted by the daemon's
// reconcileMembership loop and calls the appropriate per-network
// lifecycle method (startInternal / stopInternal). Tests that don't
// supply Deps.Events skip the subscription wiring; lifecycle methods
// remain callable directly via the Manager view.
func (s *Service) Start(_ context.Context, deps coreapi.Deps) error {
	if deps.Events == nil {
		return nil
	}
	ch, cancel := deps.Events.Subscribe("network.*")
	done := make(chan struct{})
	s.mu.Lock()
	s.subStop = cancel
	s.subDone = done
	s.mu.Unlock()
	go s.dispatchNetworkEvents(ch, done)
	return nil
}

// Stop tears down the network.* subscriber (so no further events fire
// against stopped runners) and stops every per-network runner.
func (s *Service) Stop(_ context.Context) error {
	s.mu.Lock()
	cancel := s.subStop
	done := s.subDone
	s.subStop = nil
	s.subDone = nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
	s.StopAll()
	return nil
}

// dispatchNetworkEvents drains the network.* subscription channel and
// translates each event into a runner lifecycle call. Runs as a single
// goroutine until the bus closes the channel (Stop calls cancel ->
// inProcessBus closes the channel).
func (s *Service) dispatchNetworkEvents(ch <-chan coreapi.Event, done chan<- struct{}) {
	defer close(done)
	for ev := range ch {
		switch ev.Topic {
		case "network.joined":
			s.handleNetworkJoined(ev.Payload)
		case "network.left":
			s.handleNetworkLeft(ev.Payload)
		case "network.tags_changed":
			// Member-tag cache is daemon-internal today (consumed by
			// EvaluatePortGate via the runtime adapter, not stored in
			// the runner). Reserved for future use.
		}
	}
}

// handleNetworkJoined starts a policy runner if the join payload
// carries an expr_policy and no runner is currently registered for the
// network. Mirrors the lazy-fetch / skip-if-already-running logic the
// old syncPolicyRunners performed.
func (s *Service) handleNetworkJoined(payload map[string]any) {
	netID, ok := networkIDFromPayload(payload)
	if !ok || netID == 0 {
		return
	}
	policyJSON, ok := exprPolicyJSONFromPayload(payload)
	if !ok {
		return
	}

	s.mu.RLock()
	_, exists := s.runners[netID]
	s.mu.RUnlock()
	if exists {
		return
	}

	if _, err := s.startInternal(netID, policyJSON); err != nil {
		slog.Warn("policy: failed to start runner from network.joined",
			"network_id", netID, "err", err)
		return
	}
	slog.Info("policy: started runner from network.joined", "network_id", netID)
}

// handleNetworkLeft stops the runner for the departing network.
func (s *Service) handleNetworkLeft(payload map[string]any) {
	netID, ok := networkIDFromPayload(payload)
	if !ok {
		return
	}
	s.stopInternal(netID)
}

// networkIDFromPayload extracts the network_id field. Bus payloads use
// `any` because the publisher might choose either uint16 (typed) or
// float64 (parsed JSON). Both shapes are accepted.
func networkIDFromPayload(p map[string]any) (uint16, bool) {
	if p == nil {
		return 0, false
	}
	switch v := p["network_id"].(type) {
	case uint16:
		return v, true
	case int:
		return uint16(v), true
	case int64:
		return uint16(v), true
	case float64:
		return uint16(v), true
	default:
		return 0, false
	}
}

// exprPolicyJSONFromPayload normalizes the expr_policy payload field
// into a json.RawMessage. The daemon-side reconciler may publish
// either a string (raw JSON document) or a map[string]any (parsed
// JSON object); both shapes are accepted to match the registry's
// GetExprPolicy response. Returns false when the field is missing or
// nil.
func exprPolicyJSONFromPayload(p map[string]any) (json.RawMessage, bool) {
	if p == nil {
		return nil, false
	}
	v, ok := p["expr_policy"]
	if !ok || v == nil {
		return nil, false
	}
	switch t := v.(type) {
	case string:
		return json.RawMessage(t), true
	case []byte:
		return json.RawMessage(t), true
	case json.RawMessage:
		return t, true
	case map[string]any:
		b, err := json.Marshal(t)
		if err != nil {
			return nil, false
		}
		return b, true
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return nil, false
		}
		return b, true
	}
}

// --- coreapi.PolicyManager ---

func (s *Service) Start_(netID uint16, policyJSON []byte) (coreapi.PolicyRunner, error) {
	return s.startInternal(netID, policyJSON)
}

func (s *Service) StartManager(netID uint16, policyJSON []byte) (coreapi.PolicyRunner, error) {
	return s.startInternal(netID, policyJSON)
}

// PolicyManager interface methods (named to disambiguate from
// coreapi.Service.Start). Method names match coreapi.PolicyManager.

func (s *Service) startInternal(netID uint16, policyJSON []byte) (*PolicyRunner, error) {
	if s.runtime == nil {
		return nil, errors.New("policy: runtime not configured")
	}
	doc, err := Parse(policyJSON)
	if err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	cp, err := Compile(doc)
	if err != nil {
		return nil, fmt.Errorf("compile policy: %w", err)
	}

	s.mu.Lock()
	if old, ok := s.runners[netID]; ok {
		old.Stop()
	}
	pr := NewPolicyRunner(netID, cp, s.runtime)
	pr.Start()
	s.runners[netID] = pr
	s.mu.Unlock()

	slog.Info("policy: started runner", "network_id", netID)
	return pr, nil
}

// stopInternal stops a runner and removes it from the map.
func (s *Service) stopInternal(netID uint16) {
	s.mu.Lock()
	pr, ok := s.runners[netID]
	if ok {
		delete(s.runners, netID)
	}
	s.mu.Unlock()
	if pr != nil {
		pr.Stop()
		slog.Info("policy: stopped runner", "network_id", netID)
	}
}

// LoadPersisted scans ~/.pilot/policy_*.json and re-creates a runner
// for each. Called from daemon-Start after the registry connection is
// up. Each file's name is `policy_<netID>.json`; the contents are the
// policy JSON.
func (s *Service) LoadPersisted() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, ".pilot")
	entries, err := os.ReadDir(dir)
	if err != nil {
		// No directory yet — nothing to load.
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "policy_") || !strings.HasSuffix(name, ".json") {
			continue
		}
		// State files for individual runners are named
		// `policy_<netID>.json`. Compiled policy bytes live separately
		// (the persisted state holds peers/scores, not the compiled
		// policy). LoadPersisted is invoked after the daemon's startup
		// path that re-registers networks; runners get re-created via
		// Start when networks rejoin. Nothing else to do here today.
		_ = name
	}
	return nil
}

// --- coreapi.PolicyManager interface impl ---

// Use a method-set-only matching naming. coreapi.PolicyManager defines
// method `Start(netID uint16, policyJSON []byte) (PolicyRunner, error)`
// — but our Service already has a `Start(ctx, deps) error` from
// coreapi.Service. To resolve the conflict, expose the manager
// methods via a thin wrapper type.

type managerView struct{ s *Service }

func (m managerView) Start(netID uint16, policyJSON []byte) (coreapi.PolicyRunner, error) {
	pr, err := m.s.startInternal(netID, policyJSON)
	if err != nil {
		return nil, err
	}
	return pr, nil
}

func (m managerView) Stop(netID uint16) { m.s.stopInternal(netID) }

func (m managerView) Get(netID uint16) coreapi.PolicyRunner {
	m.s.mu.RLock()
	pr := m.s.runners[netID]
	m.s.mu.RUnlock()
	if pr == nil {
		return nil
	}
	return pr
}

func (m managerView) All() []coreapi.PolicyRunner {
	m.s.mu.RLock()
	defer m.s.mu.RUnlock()
	out := make([]coreapi.PolicyRunner, 0, len(m.s.runners))
	for _, pr := range m.s.runners {
		out = append(out, pr)
	}
	return out
}

func (m managerView) StopAll() { m.s.StopAll() }

func (m managerView) LoadPersisted() error { return m.s.LoadPersisted() }

// Manager returns the coreapi.PolicyManager view of this service. The
// daemon's RegisterPolicyManager(svc.Manager()) wires the gate hooks.
func (s *Service) Manager() coreapi.PolicyManager { return managerView{s: s} }

// StopAll stops every running runner. Safe to call multiple times.
func (s *Service) StopAll() {
	s.mu.Lock()
	rs := s.runners
	s.runners = make(map[uint16]*PolicyRunner)
	s.mu.Unlock()
	for _, pr := range rs {
		pr.Stop()
	}
}

// Compile-time guard. Only the managerView satisfies PolicyManager;
// the Service itself satisfies coreapi.Service.
var (
	_ coreapi.Service       = (*Service)(nil)
	_ coreapi.PolicyManager = managerView{}
	_ coreapi.PolicyRunner  = (*PolicyRunner)(nil)
)

// --- compile-time guard for json.RawMessage compat ---
var _ = json.RawMessage(nil)
