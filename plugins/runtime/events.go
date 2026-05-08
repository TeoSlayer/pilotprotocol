// SPDX-License-Identifier: AGPL-3.0-or-later

package runtime

import (
	"github.com/TeoSlayer/pilotprotocol/pkg/coreapi"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
)

// daemonEventBus adapts daemon's in-process bus to coreapi.EventBus
// for plugin Deps. Publish forwards through Daemon.PublishEvent;
// Subscribe wraps the bus channel with type conversion daemon.Event
// → coreapi.Event.

type daemonEventBus struct{ d *daemon.Daemon }

func (b daemonEventBus) Publish(topic string, payload map[string]any) {
	if b.d == nil {
		return
	}
	b.d.PublishEvent(topic, payload)
}

func (b daemonEventBus) Subscribe(pattern string) (<-chan coreapi.Event, func()) {
	if b.d == nil || b.d.Bus() == nil {
		ch := make(chan coreapi.Event)
		close(ch)
		return ch, func() {}
	}
	src, cancel := b.d.Bus().Subscribe(pattern)
	out := make(chan coreapi.Event, cap(src))
	go func() {
		defer close(out)
		for ev := range src {
			out <- coreapi.Event{
				Topic:   ev.Topic,
				NodeID:  ev.NodeID,
				Time:    ev.Time,
				Payload: ev.Payload,
			}
		}
	}()
	return out, cancel
}

var _ coreapi.EventBus = daemonEventBus{}
