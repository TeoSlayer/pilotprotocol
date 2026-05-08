// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import "time"

// managedPeer is the per-peer state the policy runner tracks for a
// single network: score (with optional per-topic breakdown), tags
// (set by tag directives), and timestamps. Mirrors the struct in
// pkg/daemon/managed.go (where the older "managed network" engine
// lives); the two are separate but share the JSON shape so the
// persisted state is interchangeable.
type managedPeer struct {
	NodeID       uint32    `json:"node_id"`
	Tags         []string  `json:"tags,omitempty"`          // policy-engine-assigned tags (addTag/removeTag)
	RegistryTags []string  `json:"registry_tags,omitempty"` // registry-sourced tags, refreshed by reconciler
	AddedAt      time.Time `json:"added_at"`
	LastSeen     time.Time `json:"last_seen"`
}

// clonePeersLocked returns a deep copy of the peer map. Caller must
// hold whatever lock guards `src`. Mirrors the same helper in
// pkg/daemon/managed.go.
func clonePeersLocked(src map[uint32]*managedPeer) map[uint32]*managedPeer {
	dst := make(map[uint32]*managedPeer, len(src))
	for k, p := range src {
		pc := *p
		if p.Tags != nil {
			pc.Tags = append([]string(nil), p.Tags...)
		}
		if p.RegistryTags != nil {
			pc.RegistryTags = append([]string(nil), p.RegistryTags...)
		}
		dst[k] = &pc
	}
	return dst
}
