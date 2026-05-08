// SPDX-License-Identifier: AGPL-3.0-or-later

package events

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// recvWithin returns the next event from ch or fails the test if none
// arrives within d.
func recvWithin(t *testing.T, ch <-chan Event, d time.Duration) Event {
	t.Helper()
	select {
	case ev, ok := <-ch:
		if !ok {
			t.Fatalf("channel closed while expecting an event")
		}
		return ev
	case <-time.After(d):
		t.Fatalf("timed out after %s waiting for event", d)
	}
	return Event{}
}

// expectNoEvent asserts no event is available on ch within d.
func expectNoEvent(t *testing.T, ch <-chan Event, d time.Duration) {
	t.Helper()
	select {
	case ev, ok := <-ch:
		if !ok {
			return // channel closed is fine here
		}
		t.Fatalf("unexpected event delivered: %+v", ev)
	case <-time.After(d):
	}
}

// TestPublishNoSubscribers verifies that publishing to a bus with no
// subscribers is a no-op and does not block or panic.
func TestPublishNoSubscribers(t *testing.T) {
	t.Parallel()
	b := NewInProcessBus(8)
	// Should not block, panic, or otherwise misbehave.
	b.Publish(Event{Source: "directory", Type: "node.deleted"})
	b.Publish(Event{Source: "membership", Type: "membership.changed"})
}

// TestSubscribeWildcardReceivesAll verifies that a wildcard "*"
// subscriber receives every published event regardless of Type.
func TestSubscribeWildcardReceivesAll(t *testing.T) {
	t.Parallel()
	b := NewInProcessBus(16)
	ch, unsub := b.Subscribe("*")
	defer unsub()

	want := []Event{
		{Source: "directory", Type: "node.deleted", Payload: map[string]any{"id": uint32(7)}},
		{Source: "membership", Type: "membership.changed", Payload: map[string]any{"net": uint16(1)}},
		{Source: "identity", Type: "key.rotated"},
	}
	for _, ev := range want {
		b.Publish(ev)
	}
	for i, w := range want {
		got := recvWithin(t, ch, time.Second)
		if got.Source != w.Source || got.Type != w.Type {
			t.Fatalf("event %d: got %+v, want %+v", i, got, w)
		}
	}
}

// TestSubscribeExactType verifies that an exact-Type subscription
// receives only events with that exact Type.
func TestSubscribeExactType(t *testing.T) {
	t.Parallel()
	b := NewInProcessBus(8)
	ch, unsub := b.Subscribe("foo.bar")
	defer unsub()

	b.Publish(Event{Type: "foo.bar"})
	b.Publish(Event{Type: "foo.baz"})
	b.Publish(Event{Type: "foo.bar.qux"})
	b.Publish(Event{Type: "foo.bar"})

	got := recvWithin(t, ch, time.Second)
	if got.Type != "foo.bar" {
		t.Fatalf("first event: got Type=%q, want %q", got.Type, "foo.bar")
	}
	got = recvWithin(t, ch, time.Second)
	if got.Type != "foo.bar" {
		t.Fatalf("second event: got Type=%q, want %q", got.Type, "foo.bar")
	}
	expectNoEvent(t, ch, 50*time.Millisecond)
}

// TestSubscribePrefixWildcard verifies that "prefix.*" matches any Type
// beginning with "prefix." but not "prefix" alone or unrelated types.
func TestSubscribePrefixWildcard(t *testing.T) {
	t.Parallel()
	b := NewInProcessBus(16)
	ch, unsub := b.Subscribe("foo.*")
	defer unsub()

	b.Publish(Event{Type: "foo.bar"})
	b.Publish(Event{Type: "foo.baz"})
	b.Publish(Event{Type: "foo"})        // no dot suffix — should NOT match
	b.Publish(Event{Type: "fooz.bar"})   // wrong prefix — should NOT match
	b.Publish(Event{Type: "foo.bar.qux"})

	wantTypes := []string{"foo.bar", "foo.baz", "foo.bar.qux"}
	for i, want := range wantTypes {
		got := recvWithin(t, ch, time.Second)
		if got.Type != want {
			t.Fatalf("event %d: got Type=%q, want %q", i, got.Type, want)
		}
	}
	expectNoEvent(t, ch, 50*time.Millisecond)
}

// TestUnsubscribeStopsAndClosesChannel verifies that unsubscribe stops
// further deliveries and closes the channel exactly once.
func TestUnsubscribeStopsAndClosesChannel(t *testing.T) {
	t.Parallel()
	b := NewInProcessBus(8)
	ch, unsub := b.Subscribe("*")

	b.Publish(Event{Type: "first"})
	got := recvWithin(t, ch, time.Second)
	if got.Type != "first" {
		t.Fatalf("got Type=%q, want %q", got.Type, "first")
	}

	unsub()

	// Channel must be closed.
	select {
	case _, ok := <-ch:
		if ok {
			// Drain any leftover, then assert close on the next recv.
			select {
			case _, ok := <-ch:
				if ok {
					t.Fatalf("expected channel closed after unsubscribe")
				}
			case <-time.After(time.Second):
				t.Fatalf("expected channel close after drain")
			}
		}
	case <-time.After(time.Second):
		t.Fatalf("expected channel closed after unsubscribe (recv timed out)")
	}

	// Further publishes must not deliver to this subscription. The
	// publisher must not block or panic.
	b.Publish(Event{Type: "after-unsub"})

	// Calling unsubscribe a second time is a no-op.
	unsub()
}

// TestSlowSubscriberDoesNotBlockOthers verifies two properties of the
// per-subscriber drop policy:
//
//  1. Publish never blocks, even when a subscriber's channel is full.
//  2. A subscriber that drains its channel keeps receiving events
//     while a stalled peer's channel saturates at its buffer size.
//
// Exact delivery counts depend on scheduler timing, so we assert
// bounds rather than equality.
func TestSlowSubscriberDoesNotBlockOthers(t *testing.T) {
	t.Parallel()
	const buf = 4
	b := NewInProcessBus(buf)

	// Slow subscriber: never reads from its channel.
	slowCh, unsubSlow := b.Subscribe("*")
	defer unsubSlow()

	// Fast subscriber: a goroutine drains everything we send.
	fastCh, unsubFast := b.Subscribe("*")
	defer unsubFast()

	var fastReceived atomic.Int64
	stop := make(chan struct{})
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for {
			select {
			case <-fastCh:
				fastReceived.Add(1)
			case <-stop:
				// Drain any remaining buffered events before exit.
				for {
					select {
					case <-fastCh:
						fastReceived.Add(1)
					default:
						return
					}
				}
			}
		}
	}()

	// Publish must not block even though slowCh fills up after `buf`
	// events. Pace the publisher just slightly so the fast drainer can
	// keep up under the race detector.
	const total = 200
	publishStart := time.Now()
	for i := 0; i < total; i++ {
		b.Publish(Event{Type: "x"})
		if i%20 == 0 {
			// Yield to let the fast drainer make progress, mimicking
			// realistic publish rates.
			time.Sleep(time.Millisecond)
		}
	}
	publishElapsed := time.Since(publishStart)
	if publishElapsed > 5*time.Second {
		t.Fatalf("Publish took %s; expected non-blocking behaviour", publishElapsed)
	}

	// Give the drainer a moment to clear the tail.
	time.Sleep(50 * time.Millisecond)
	close(stop)
	<-drained

	// Slow subscriber buffered at most `buf` events; the rest were
	// dropped at the publisher. The fast subscriber, in contrast, made
	// real progress.
	bufferedSlow := len(slowCh)
	if bufferedSlow > buf {
		t.Fatalf("slow subscriber buffered %d events; want <= %d", bufferedSlow, buf)
	}
	got := fastReceived.Load()
	if got <= int64(buf) {
		t.Fatalf("fast subscriber received %d events; expected to outpace slow's %d-buffer cap", got, buf)
	}
	if got > int64(total) {
		t.Fatalf("fast subscriber received %d events; want <= %d", got, total)
	}
}

// TestConcurrentPublishSubscribeUnsubscribe stresses the bus with
// concurrent publishers, subscribers, and unsubscribes. Designed to
// surface races under `-race`.
func TestConcurrentPublishSubscribeUnsubscribe(t *testing.T) {
	t.Parallel()
	b := NewInProcessBus(64)

	const (
		publishers  = 8
		subscribers = 8
		perPub      = 200
	)

	// Long-lived wildcard subscriber to ensure traffic flows.
	stableCh, stableUnsub := b.Subscribe("*")
	defer stableUnsub()

	var stableReceived atomic.Int64
	stableDone := make(chan struct{})
	go func() {
		defer close(stableDone)
		for {
			select {
			case _, ok := <-stableCh:
				if !ok {
					return
				}
				stableReceived.Add(1)
			case <-time.After(2 * time.Second):
				return
			}
		}
	}()

	var wg sync.WaitGroup

	// Churning subscribers: subscribe, drain a few, unsubscribe.
	for i := 0; i < subscribers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ch, unsub := b.Subscribe("foo.*")
			drained := 0
			for drained < 16 {
				select {
				case _, ok := <-ch:
					if !ok {
						return
					}
					drained++
				case <-time.After(50 * time.Millisecond):
					unsub()
					return
				}
			}
			unsub()
		}()
	}

	// Concurrent publishers.
	for p := 0; p < publishers; p++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			for i := 0; i < perPub; i++ {
				b.Publish(Event{
					Source: "directory",
					Type:   "foo.bar",
					Payload: map[string]any{
						"pub": p,
						"i":   i,
					},
				})
			}
		}(p)
	}

	wg.Wait()

	// Give the stable drainer a moment to consume any backlog.
	deadline := time.Now().Add(time.Second)
	for stableReceived.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if stableReceived.Load() == 0 {
		t.Fatalf("stable subscriber received zero events; expected traffic")
	}
}

// TestMatchPattern unit-tests the pattern helper directly. Useful as
// a sanity check independent of the bus mechanics.
func TestMatchPattern(t *testing.T) {
	t.Parallel()
	cases := []struct {
		pattern, eventType string
		want               bool
	}{
		{"*", "anything", true},
		{"", "anything", true},
		{"foo.bar", "foo.bar", true},
		{"foo.bar", "foo.baz", false},
		{"foo.*", "foo.bar", true},
		{"foo.*", "foo.bar.qux", true},
		{"foo.*", "foo", false},
		{"foo.*", "fooz.bar", false},
		{"membership.*", "membership.changed", true},
		{"membership.*", "membership", false},
	}
	for _, c := range cases {
		if got := matchPattern(c.pattern, c.eventType); got != c.want {
			t.Errorf("matchPattern(%q, %q) = %v, want %v", c.pattern, c.eventType, got, c.want)
		}
	}
}

// TestNewInProcessBusBufSizeFallback verifies that bufSize <= 0 falls
// back to the package default rather than producing a zero-buffer bus.
func TestNewInProcessBusBufSizeFallback(t *testing.T) {
	t.Parallel()
	for _, sz := range []int{0, -1, -100} {
		b := NewInProcessBus(sz)
		ipb, ok := b.(*inProcessBus)
		if !ok {
			t.Fatalf("NewInProcessBus returned %T, want *inProcessBus", b)
		}
		if ipb.bufSize != defaultBufSize {
			t.Errorf("bufSize=%d: got bufSize=%d, want %d", sz, ipb.bufSize, defaultBufSize)
		}
	}
}
