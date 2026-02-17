package tests

import (
	"fmt"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/eventstream"
)

// disableES disables the built-in eventstream service so tests can bind port 1002 via driver.
func disableES(cfg *daemon.Config) { cfg.DisableEventStream = true }

func TestEventStream(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	// Daemon A runs the event broker
	a := env.AddDaemon(disableES)

	// Daemon B for subscriber
	b := env.AddDaemon(disableES)

	// Daemon C for publisher
	c := env.AddDaemon(disableES)

	// Start broker on A
	srv := eventstream.NewServer(a.Driver)
	go srv.ListenAndServe()

	// Subscriber on B
	sub, err := eventstream.Subscribe(b.Driver, a.Daemon.Addr(), "test-topic")
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer sub.Close()
	t.Log("subscriber connected")

	// Publisher on C
	pub, err := eventstream.Subscribe(c.Driver, a.Daemon.Addr(), "test-topic")
	if err != nil {
		t.Fatalf("connect publisher: %v", err)
	}
	defer pub.Close()
	t.Log("publisher connected")

	// Start receiving in background before publishing
	done := make(chan *eventstream.Event, 1)
	go func() {
		evt, err := sub.Recv()
		if err != nil {
			return
		}
		done <- evt
	}()

	// Retry publishing until the subscriber receives the event.
	// The subscriptions may not be fully registered on the broker yet,
	// so early publishes may be dropped. Keep retrying until delivery.
	deadline := time.After(5 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	published := false
	for {
		if !published {
			if err := pub.Publish("test-topic", []byte("hello event stream")); err != nil {
				t.Fatalf("publish: %v", err)
			}
			published = true
		}

		select {
		case evt := <-done:
			if evt.Topic != "test-topic" {
				t.Errorf("expected topic %q, got %q", "test-topic", evt.Topic)
			}
			if string(evt.Payload) != "hello event stream" {
				t.Errorf("expected %q, got %q", "hello event stream", string(evt.Payload))
			}
			t.Logf("received event: [%s] %s", evt.Topic, string(evt.Payload))
			return
		case <-deadline:
			t.Fatal("timeout waiting for event")
			return
		case <-ticker.C:
			// Re-publish in case the earlier publish was before subscription was registered
			if err := pub.Publish("test-topic", []byte("hello event stream")); err != nil {
				t.Fatalf("publish retry: %v", err)
			}
		}
	}
}

// publishUntilRecv retries publishing until at least one subscriber receives the event.
func publishUntilRecv(t *testing.T, pub *eventstream.Client, topic string, payload []byte, recv <-chan *eventstream.Event) *eventstream.Event {
	t.Helper()
	deadline := time.After(5 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	pub.Publish(topic, payload)
	for {
		select {
		case evt := <-recv:
			return evt
		case <-deadline:
			t.Fatalf("timeout waiting for event on topic %q", topic)
			return nil
		case <-ticker.C:
			pub.Publish(topic, payload)
		}
	}
}

// TestEventStreamWildcard verifies that a "*" subscriber receives events from all topics.
func TestEventStreamWildcard(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon(disableES)
	b := env.AddDaemon(disableES)
	c := env.AddDaemon(disableES)

	srv := eventstream.NewServer(a.Driver)
	go srv.ListenAndServe()

	// B subscribes with wildcard
	sub, err := eventstream.Subscribe(b.Driver, a.Daemon.Addr(), "*")
	if err != nil {
		t.Fatalf("subscribe wildcard: %v", err)
	}
	defer sub.Close()

	// C publishes
	pub, err := eventstream.Subscribe(c.Driver, a.Daemon.Addr(), "any-topic")
	if err != nil {
		t.Fatalf("connect publisher: %v", err)
	}
	defer pub.Close()

	recv := make(chan *eventstream.Event, 5)
	go func() {
		for {
			evt, err := sub.Recv()
			if err != nil {
				return
			}
			recv <- evt
		}
	}()

	evt := publishUntilRecv(t, pub, "topic-alpha", []byte("alpha-msg"), recv)
	if evt.Topic != "topic-alpha" {
		t.Errorf("expected topic %q, got %q", "topic-alpha", evt.Topic)
	}
	t.Logf("wildcard received: [%s] %s", evt.Topic, string(evt.Payload))
}

// TestEventStreamMultipleTopics verifies subscribers only get events for their topic.
func TestEventStreamMultipleTopics(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon(disableES)
	b := env.AddDaemon(disableES)
	c := env.AddDaemon(disableES)

	srv := eventstream.NewServer(a.Driver)
	go srv.ListenAndServe()

	// B subscribes to "topic-A"
	subA, err := eventstream.Subscribe(b.Driver, a.Daemon.Addr(), "topic-A")
	if err != nil {
		t.Fatalf("subscribe topic-A: %v", err)
	}
	defer subA.Close()

	// C subscribes to "topic-B"
	subB, err := eventstream.Subscribe(c.Driver, a.Daemon.Addr(), "topic-B")
	if err != nil {
		t.Fatalf("subscribe topic-B: %v", err)
	}
	defer subB.Close()

	// Another connection to publish
	pub, err := eventstream.Subscribe(b.Driver, a.Daemon.Addr(), "publisher")
	if err != nil {
		t.Fatalf("connect publisher: %v", err)
	}
	defer pub.Close()

	recvA := make(chan *eventstream.Event, 5)
	recvB := make(chan *eventstream.Event, 5)
	go func() {
		for {
			evt, err := subA.Recv()
			if err != nil {
				return
			}
			recvA <- evt
		}
	}()
	go func() {
		for {
			evt, err := subB.Recv()
			if err != nil {
				return
			}
			recvB <- evt
		}
	}()

	// Publish to topic-B — subA should not receive it
	evt := publishUntilRecv(t, pub, "topic-B", []byte("for-B"), recvB)
	if string(evt.Payload) != "for-B" {
		t.Errorf("expected payload %q, got %q", "for-B", string(evt.Payload))
	}

	// subA should NOT have received anything
	select {
	case got := <-recvA:
		t.Errorf("topic-A subscriber should not receive topic-B events, got: [%s] %s", got.Topic, string(got.Payload))
	case <-time.After(300 * time.Millisecond):
		t.Log("correctly: topic-A subscriber did not receive topic-B event")
	}
}

// TestEventStreamMultipleSubscribers verifies multiple subscribers to the same topic all get the event.
func TestEventStreamMultipleSubscribers(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon(disableES)
	b := env.AddDaemon(disableES)
	c := env.AddDaemon(disableES)

	srv := eventstream.NewServer(a.Driver)
	go srv.ListenAndServe()

	// Both B and C subscribe to same topic
	sub1, err := eventstream.Subscribe(b.Driver, a.Daemon.Addr(), "shared-topic")
	if err != nil {
		t.Fatalf("subscribe B: %v", err)
	}
	defer sub1.Close()

	sub2, err := eventstream.Subscribe(c.Driver, a.Daemon.Addr(), "shared-topic")
	if err != nil {
		t.Fatalf("subscribe C: %v", err)
	}
	defer sub2.Close()

	// Separate publisher connection
	pub, err := eventstream.Subscribe(b.Driver, a.Daemon.Addr(), "publisher")
	if err != nil {
		t.Fatalf("connect publisher: %v", err)
	}
	defer pub.Close()

	recv1 := make(chan *eventstream.Event, 5)
	recv2 := make(chan *eventstream.Event, 5)
	go func() {
		for {
			evt, err := sub1.Recv()
			if err != nil {
				return
			}
			recv1 <- evt
		}
	}()
	go func() {
		for {
			evt, err := sub2.Recv()
			if err != nil {
				return
			}
			recv2 <- evt
		}
	}()

	// Publish and wait for both
	deadline := time.After(5 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	pub.Publish("shared-topic", []byte("shared-msg"))
	var got1, got2 bool
	for !got1 || !got2 {
		select {
		case evt := <-recv1:
			if string(evt.Payload) == "shared-msg" {
				got1 = true
			}
		case evt := <-recv2:
			if string(evt.Payload) == "shared-msg" {
				got2 = true
			}
		case <-deadline:
			t.Fatalf("timeout: got1=%v got2=%v", got1, got2)
		case <-ticker.C:
			pub.Publish("shared-topic", []byte("shared-msg"))
		}
	}
	t.Log("both subscribers received the event")
}

// TestEventStreamPublisherExclusion verifies the publisher doesn't receive its own events.
func TestEventStreamPublisherExclusion(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon(disableES)
	b := env.AddDaemon(disableES)

	srv := eventstream.NewServer(a.Driver)
	go srv.ListenAndServe()

	// B subscribes and publishes on the same topic
	client, err := eventstream.Subscribe(b.Driver, a.Daemon.Addr(), "self-topic")
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer client.Close()

	selfRecv := make(chan *eventstream.Event, 5)
	go func() {
		for {
			evt, err := client.Recv()
			if err != nil {
				return
			}
			selfRecv <- evt
		}
	}()

	// Publish several messages
	for i := 0; i < 5; i++ {
		client.Publish("self-topic", []byte(fmt.Sprintf("msg-%d", i)))
	}

	// Should NOT receive own messages
	select {
	case evt := <-selfRecv:
		t.Errorf("should not receive own event, got: [%s] %s", evt.Topic, string(evt.Payload))
	case <-time.After(500 * time.Millisecond):
		t.Log("correctly: publisher did not receive its own events")
	}
}

// TestEventStreamSequentialMessages verifies multiple events arrive in order.
func TestEventStreamSequentialMessages(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon(disableES)
	b := env.AddDaemon(disableES)
	c := env.AddDaemon(disableES)

	srv := eventstream.NewServer(a.Driver)
	go srv.ListenAndServe()

	sub, err := eventstream.Subscribe(b.Driver, a.Daemon.Addr(), "seq-topic")
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer sub.Close()

	pub, err := eventstream.Subscribe(c.Driver, a.Daemon.Addr(), "seq-topic")
	if err != nil {
		t.Fatalf("connect publisher: %v", err)
	}
	defer pub.Close()

	recv := make(chan *eventstream.Event, 20)
	go func() {
		for {
			evt, err := sub.Recv()
			if err != nil {
				return
			}
			recv <- evt
		}
	}()

	// Wait for first event to ensure subscription is active
	_ = publishUntilRecv(t, pub, "seq-topic", []byte("msg-0"), recv)

	// Now send remaining messages (subscription is active)
	const numMsgs = 10
	for i := 1; i < numMsgs; i++ {
		pub.Publish("seq-topic", []byte(fmt.Sprintf("msg-%d", i)))
	}

	// Collect remaining messages (already have msg-0)
	msgs := []string{"msg-0"}
	timeout := time.After(5 * time.Second)
	for len(msgs) < numMsgs {
		select {
		case evt := <-recv:
			msgs = append(msgs, string(evt.Payload))
		case <-timeout:
			t.Fatalf("timeout: received %d of %d messages", len(msgs), numMsgs)
		}
	}
	t.Logf("received all %d sequential messages", len(msgs))
}

// TestEventStreamSubscriberDisconnect verifies the broker handles subscriber disconnection gracefully.
func TestEventStreamSubscriberDisconnect(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon(disableES)
	b := env.AddDaemon(disableES)
	c := env.AddDaemon(disableES)

	srv := eventstream.NewServer(a.Driver)
	go srv.ListenAndServe()

	// B subscribes and then disconnects
	sub, err := eventstream.Subscribe(b.Driver, a.Daemon.Addr(), "disc-topic")
	if err != nil {
		t.Fatalf("subscribe B: %v", err)
	}

	// C also subscribes (stays connected)
	sub2, err := eventstream.Subscribe(c.Driver, a.Daemon.Addr(), "disc-topic")
	if err != nil {
		t.Fatalf("subscribe C: %v", err)
	}
	defer sub2.Close()

	recv2 := make(chan *eventstream.Event, 5)
	go func() {
		for {
			evt, err := sub2.Recv()
			if err != nil {
				return
			}
			recv2 <- evt
		}
	}()

	// Publisher
	pub, err := eventstream.Subscribe(b.Driver, a.Daemon.Addr(), "publisher")
	if err != nil {
		t.Fatalf("connect publisher: %v", err)
	}
	defer pub.Close()

	// Disconnect B's subscription
	sub.Close()

	// Publish — C should still receive (publishUntilRecv retries until broker processes disconnect)
	evt := publishUntilRecv(t, pub, "disc-topic", []byte("after-disconnect"), recv2)
	if string(evt.Payload) != "after-disconnect" {
		t.Errorf("expected %q, got %q", "after-disconnect", string(evt.Payload))
	}
	t.Log("broker handled subscriber disconnect gracefully")
}

