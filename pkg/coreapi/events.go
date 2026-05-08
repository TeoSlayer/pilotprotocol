// SPDX-License-Identifier: AGPL-3.0-or-later

package coreapi

import "time"

// Event is one item published to the EventBus. Topics are
// dot-namespaced (e.g., "tunnel.established", "security.nonce_replay").
// Payload keys/values are plugin-defined; subscribers parse them.
type Event struct {
	Topic   string
	NodeID  uint32
	Time    time.Time
	Payload map[string]any
}

// EventBus is the publish/subscribe channel that replaces inline
// webhook.Emit calls inside core layers. Core (L2-L7) publishes;
// the webhook plugin (and any other observability plugin) subscribes.
//
// Publish is non-blocking. If the bus is over capacity, the event is
// dropped (and a metric counter is incremented inside the daemon
// implementation). This keeps L2 readLoop / L6 decrypt latency bounded.
//
// Subscribe returns a buffered channel and an unsubscribe func. Pattern
// is a glob: "tunnel.*" matches "tunnel.established" but not
// "security.nonce_replay".
type EventBus interface {
	Publish(topic string, payload map[string]any)
	Subscribe(pattern string) (<-chan Event, func())
}
