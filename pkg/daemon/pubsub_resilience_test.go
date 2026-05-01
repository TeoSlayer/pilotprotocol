// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/eventstream"
)

// failingWriter is a programmable eventWriter that fails the first
// errorCount calls per subscriber, then succeeds. Tracks call counts.
func failingWriter(failures int) (eventWriter, *atomic.Int64) {
	var calls atomic.Int64
	return func(conn *connAdapter, evt *eventstream.Event) error {
		c := calls.Add(1)
		if int(c) <= failures {
			return errors.New("simulated transient write failure")
		}
		return nil
	}, &calls
}

// alwaysFailWriter never succeeds.
func alwaysFailWriter() (eventWriter, *atomic.Int64) {
	var calls atomic.Int64
	return func(conn *connAdapter, evt *eventstream.Event) error {
		calls.Add(1)
		return errors.New("permanent failure")
	}, &calls
}

// alwaysOKWriter always succeeds.
func alwaysOKWriter() (eventWriter, *atomic.Int64) {
	var calls atomic.Int64
	return func(conn *connAdapter, evt *eventstream.Event) error {
		calls.Add(1)
		return nil
	}, &calls
}

// stubAdapter returns a minimal connAdapter usable for broker tests where
// only the failure-tracking matters (no real tunnel behind it). Uses a
// minimal Connection so slog calls that touch RemoteAddr/LocalAddr work.
func stubAdapter() *connAdapter {
	return &connAdapter{conn: &Connection{}}
}

// TestPubsubRetryAbsorbsSingleTransientFailure: write fails once, then
// the retry succeeds — subscriber stays alive, counter never increments.
func TestPubsubRetryAbsorbsSingleTransientFailure(t *testing.T) {
	b := &eventBroker{
		subs:   make(map[string][]*connAdapter),
		daemon: New(Config{}),
	}
	sub := stubAdapter()
	b.addSub("topic-a", sub)

	write, calls := failingWriter(1) // fail #1, succeed #2
	evt := &eventstream.Event{Topic: "topic-a", Payload: []byte("p1")}
	b.publishWith(evt, stubAdapter(), write)

	if got := sub.publishFailures.Load(); got != 0 {
		t.Fatalf("publishFailures = %d, want 0 (retry success should reset)", got)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("write was called %d times, want 2 (1 initial + 1 retry)", got)
	}
	// Subscriber must still be present.
	b.mu.RLock()
	defer b.mu.RUnlock()
	if len(b.subs["topic-a"]) != 1 {
		t.Fatalf("subscriber removed after one transient failure; subs = %v", b.subs)
	}
}

// TestPubsubKeepsSubscriberBelowFailureThreshold: every publish fails
// (both initial + retry). Subscriber stays subscribed until we've hit
// maxConsecutivePublishFailures across publishes.
func TestPubsubKeepsSubscriberBelowFailureThreshold(t *testing.T) {
	b := &eventBroker{
		subs:   make(map[string][]*connAdapter),
		daemon: New(Config{}),
	}
	sub := stubAdapter()
	b.addSub("topic-fail", sub)

	write, _ := alwaysFailWriter()
	evt := &eventstream.Event{Topic: "topic-fail", Payload: []byte("x")}

	// First N-1 publishes leave the sub in place (counter accumulates).
	for i := 1; i < maxConsecutivePublishFailures; i++ {
		b.publishWith(evt, stubAdapter(), write)
		got := sub.publishFailures.Load()
		if int(got) != i {
			t.Fatalf("after %d publishes, publishFailures = %d, want %d", i, got, i)
		}
		b.mu.RLock()
		alive := len(b.subs["topic-fail"]) == 1
		b.mu.RUnlock()
		if !alive {
			t.Fatalf("subscriber removed at failure count %d (threshold is %d)", got, maxConsecutivePublishFailures)
		}
	}

	// The N-th publish trips the threshold and removes the sub.
	b.publishWith(evt, stubAdapter(), write)
	b.mu.RLock()
	defer b.mu.RUnlock()
	if len(b.subs["topic-fail"]) != 0 {
		t.Fatalf("subscriber NOT removed after %d consecutive failures (threshold)", maxConsecutivePublishFailures)
	}
}

// TestPubsubFailureCounterResetsOnSuccess: 2 failures bring counter to 2,
// then a success resets it. The next 2 failures should NOT remove (since
// counter restarted from 0, threshold is 3).
func TestPubsubFailureCounterResetsOnSuccess(t *testing.T) {
	b := &eventBroker{
		subs:   make(map[string][]*connAdapter),
		daemon: New(Config{}),
	}
	sub := stubAdapter()
	b.addSub("topic-mix", sub)

	failOnce, _ := failingWriter(2) // 2 fails (×retry: 4 calls), then success
	evt := &eventstream.Event{Topic: "topic-mix", Payload: []byte("y")}

	// Publish 1: fails twice (initial + retry both fail) → counter=1
	b.publishWith(evt, stubAdapter(), func(conn *connAdapter, e *eventstream.Event) error {
		return errors.New("fail")
	})
	if got := sub.publishFailures.Load(); got != 1 {
		t.Fatalf("after publish 1: counter = %d, want 1", got)
	}

	// Publish 2: succeeds → counter resets to 0
	b.publishWith(evt, stubAdapter(), func(conn *connAdapter, e *eventstream.Event) error {
		return nil
	})
	if got := sub.publishFailures.Load(); got != 0 {
		t.Fatalf("after success: counter = %d, want 0", got)
	}

	// Publish 3+4: fail → counter rises to 2; sub still alive (threshold=3)
	for i := 0; i < 2; i++ {
		b.publishWith(evt, stubAdapter(), func(conn *connAdapter, e *eventstream.Event) error {
			return errors.New("fail again")
		})
	}
	if got := sub.publishFailures.Load(); got != 2 {
		t.Fatalf("counter = %d, want 2 (still under threshold %d)", got, maxConsecutivePublishFailures)
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if len(b.subs["topic-mix"]) != 1 {
		t.Fatalf("subscriber removed prematurely; counter reset path broken")
	}

	// silence unused
	_ = failOnce
}

// TestPubsubOneSubscribersFailureDoesNotKillOthers: a flaky subscriber
// (writes fail) sits alongside a healthy one (writes succeed). The
// healthy sub continues to receive every event regardless of how many
// the flaky sub drops.
func TestPubsubOneSubscribersFailureDoesNotKillOthers(t *testing.T) {
	b := &eventBroker{
		subs:   make(map[string][]*connAdapter),
		daemon: New(Config{}),
	}
	healthy := stubAdapter()
	flaky := stubAdapter()
	b.addSub("shared", healthy)
	b.addSub("shared", flaky)

	var (
		writeMu     sync.Mutex
		healthyHits int
		flakyHits   int
	)
	write := func(conn *connAdapter, evt *eventstream.Event) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		if conn == healthy {
			healthyHits++
			return nil
		}
		flakyHits++
		return errors.New("flaky failure")
	}

	const N = 10
	evt := &eventstream.Event{Topic: "shared", Payload: []byte("evt")}
	for i := 0; i < N; i++ {
		b.publishWith(evt, stubAdapter(), write)
	}

	// Healthy sub got every event (initial call only — no retry needed
	// when its write succeeds first try).
	if healthyHits != N {
		t.Fatalf("healthy sub got %d hits across %d publishes, want %d", healthyHits, N, N)
	}
	// Flaky sub eventually removed once its counter ≥ threshold (initial
	// + retry fail per publish, so each publish increments counter by 1).
	// After threshold publishes, sub is removed; remaining publishes
	// don't even reach it (so flakyHits caps at 2*threshold — initial+retry per publish).
	if flakyHits > 2*maxConsecutivePublishFailures {
		t.Fatalf("flaky sub got %d hits — expected ≤ %d (cap = 2*threshold)", flakyHits, 2*maxConsecutivePublishFailures)
	}
}
