// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

// Network membership bus topics (T4.3).
//
// These events are emitted by Daemon.reconcileMembership (the bus-
// inverted replacement for the old syncNetworks/networkSyncLoop). They
// decouple membership reconciliation (L7 / daemon-internal: registry
// fetch + delta computation + snapshot persistence) from per-network
// lifecycle (L11 / plugin-internal: policy runners, managed engines).
//
// Subscribers:
//   - plugins/policy.Service subscribes via coreapi.Deps.Events. On
//     network.joined with a non-empty expr_policy, it starts a runner;
//     on network.left, it stops one. tags_changed is a no-op for the
//     policy plugin today (member-tag cache is daemon-internal), but
//     reserved for future use.
//   - The daemon itself subscribes (in subscribeNetworkInternalToBus)
//     to react to network.joined / network.left for managed engines and
//     to network.tags_changed for the member-tag cache. Managed engines
//     still live in pkg/daemon (managed.go); when they move to a plugin
//     they will pick up the same subscription pattern.
//   - The webhook bridge (subscribeWebhookToBus) forwards every bus
//     event including these to the registered HTTP webhook. No extra
//     wiring needed — the bridge subscribes to "*".

const (
	// TopicNetworkJoined fires when reconciliation observes a network
	// in the registry membership list that was not present in the
	// prior tick's known set.
	//
	// Payload schema:
	//   network_id    uint16        — registry network ID (>0; 0 is the
	//                                  default/backbone and is skipped)
	//   rules         any (json)    — registrywire.NetworkRules raw form
	//                                  if the network has managed-engine
	//                                  rules; nil otherwise. Same format
	//                                  the registry returns from
	//                                  ListNetworks().
	//   expr_policy   any (json)    — compiled expr policy in the same
	//                                  format GetExprPolicy returns
	//                                  (string OR object); nil if the
	//                                  network has no expr policy.
	//   member_tags   []string      — local-node tags for this network
	//                                  at the time of join (already
	//                                  populated in d.memberTags).
	TopicNetworkJoined = "network.joined"

	// TopicNetworkLeft fires when reconciliation observes that a
	// previously-known network is no longer in the registry membership
	// list.
	//
	// Payload schema:
	//   network_id    uint16        — registry network ID
	TopicNetworkLeft = "network.left"

	// TopicNetworkTagsChanged fires when reconciliation observes a
	// non-empty change to the local node's tag list inside a network.
	// Re-emitted on each tick where the registry's authoritative tags
	// differ from the previously-cached tags.
	//
	// Payload schema:
	//   network_id    uint16        — registry network ID
	//   tags          []string      — the new authoritative tag list
	TopicNetworkTagsChanged = "network.tags_changed"
)
