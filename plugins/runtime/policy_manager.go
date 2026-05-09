// SPDX-License-Identifier: AGPL-3.0-or-later

package runtime

import (
	"github.com/TeoSlayer/pilotprotocol/pkg/coreapi"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
)

// AsDaemonPolicyManager adapts a coreapi.PolicyManager (returned by
// plugins/policy.Service.Manager()) to daemon.PolicyManager. The two
// interfaces have identical method shapes; the adapter does the
// PolicyRunner element-type conversion on All() and Get().
func AsDaemonPolicyManager(pm coreapi.PolicyManager) daemon.PolicyManager {
	if pm == nil {
		return nil
	}
	return policyManagerAdapter{inner: pm}
}

type policyManagerAdapter struct{ inner coreapi.PolicyManager }

func (a policyManagerAdapter) Start(netID uint16, policyJSON []byte) (daemon.PolicyRunner, error) {
	pr, err := a.inner.Start(netID, policyJSON)
	if err != nil {
		return nil, err
	}
	return wrapRunner(pr), nil
}

func (a policyManagerAdapter) Stop(netID uint16) { a.inner.Stop(netID) }

func (a policyManagerAdapter) Get(netID uint16) daemon.PolicyRunner {
	return wrapRunner(a.inner.Get(netID))
}

func (a policyManagerAdapter) All() []daemon.PolicyRunner {
	src := a.inner.All()
	out := make([]daemon.PolicyRunner, 0, len(src))
	for _, pr := range src {
		out = append(out, wrapRunner(pr))
	}
	return out
}

func (a policyManagerAdapter) StopAll()             { a.inner.StopAll() }
func (a policyManagerAdapter) LoadPersisted() error { return a.inner.LoadPersisted() }

// wrapRunner converts a coreapi.PolicyRunner to a daemon.PolicyRunner.
// The methods are structurally compatible (PolicyEventType is a type
// alias to string), but Go's named-interface typing requires an
// explicit shim.
func wrapRunner(pr coreapi.PolicyRunner) daemon.PolicyRunner {
	if pr == nil {
		return nil
	}
	return runnerAdapter{inner: pr}
}

type runnerAdapter struct{ inner coreapi.PolicyRunner }

func (r runnerAdapter) NetworkID() uint16                { return r.inner.NetworkID() }
func (r runnerAdapter) HasMember(peerNodeID uint32) bool { return r.inner.HasMember(peerNodeID) }
func (r runnerAdapter) EvaluatePortGate(eventType string, port uint16, peerNodeID uint32, payloadSize int, direction string, localTags, nodeInfoTags []string) bool {
	return r.inner.EvaluatePortGate(eventType, port, peerNodeID, payloadSize, direction, localTags, nodeInfoTags)
}
func (r runnerAdapter) EvaluateActions(eventType string, ctx map[string]any) {
	r.inner.EvaluateActions(eventType, ctx)
}
func (r runnerAdapter) Status() map[string]any             { return r.inner.Status() }
func (r runnerAdapter) PeerList() []map[string]interface{} { return r.inner.PeerList() }
func (r runnerAdapter) ForceCycle() map[string]any         { return r.inner.ForceCycle() }
func (r runnerAdapter) ReconcileNow()                      { r.inner.ReconcileNow() }
func (r runnerAdapter) PolicyJSON() ([]byte, error)        { return r.inner.PolicyJSON() }
func (r runnerAdapter) Stop()                              { r.inner.Stop() }
