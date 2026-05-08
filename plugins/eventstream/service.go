// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !no_eventstream
// +build !no_eventstream

package eventstream

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	internales "github.com/TeoSlayer/pilotprotocol/internal/eventstream"
	"github.com/TeoSlayer/pilotprotocol/pkg/coreapi"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// Publish rate-limit constants. Issue #196: previously any single publisher
// could fan out to every subscriber as fast as it could write, potentially
// OOMing slow subscribers or saturating routeLoop. The cap is generous
// (100 events/sec per publisher) but bounds worst-case abuse.
const (
	publishRatePerSecond = 100
	publishBurstBudget   = 200
)

// Pubsub resilience constants. Previously a single transient WriteEvent
// failure (e.g., a momentary tunnel blip) immediately removed the
// subscriber, dropping every subsequent event. We now:
//   - retry the failed WriteEvent once after a brief backoff (handles ms-
//     scale glitches like a queue that just hadn't drained yet);
//   - track consecutive failures per subscriber and only remove after
//     maxConsecutivePublishFailures in a row.
const (
	publishRetryBackoff           = 20 * time.Millisecond
	maxConsecutivePublishFailures = 3
)

// Service is the L11 plugin adapter. cmd/daemon/main.go (L12) and
// cmd/pilotctl _daemon-run construct it via NewService and register
// via daemon.RegisterPlugin.
type Service struct {
	listener coreapi.Listener
	deps     coreapi.Deps
	cancel   context.CancelFunc
	done     chan struct{}
	broker   *broker
}

// NewService returns a Service ready for daemon.RegisterPlugin.
func NewService() *Service {
	return &Service{}
}

func (s *Service) Name() string { return "eventstream" }

// Order: 120 — after the trust subsystem (50) and other application
// services that may want to publish before the broker is up.
func (s *Service) Order() int { return 120 }

func (s *Service) Start(ctx context.Context, deps coreapi.Deps) error {
	s.deps = deps
	ln, err := deps.Streams.Listen(protocol.PortEventStream)
	if err != nil {
		return fmt.Errorf("eventstream: listen on port %d: %w", protocol.PortEventStream, err)
	}
	s.listener = ln
	s.broker = newBroker(deps.Events)

	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.done = make(chan struct{})
	go s.acceptLoop(runCtx)
	slog.Info("eventstream service listening", "port", protocol.PortEventStream)
	return nil
}

func (s *Service) Stop(ctx context.Context) error {
	if s.cancel != nil {
		s.cancel()
	}
	if s.listener != nil {
		_ = s.listener.Close()
	}
	if s.done == nil {
		return nil
	}
	select {
	case <-s.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

func (s *Service) acceptLoop(ctx context.Context) {
	defer close(s.done)
	// L11 panic boundary: a panic in Accept (or in the goroutine
	// dispatch line) must not kill the eventstream plugin's listener.
	// TODO(03-INVARIANTS.md §8): per-plugin supervisor would restart
	// the listener; for now we just survive + log.
	defer coreapi.RecoverPlugin("eventstream", "acceptLoop", s.deps.Events, nil)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		sub := newSubscriber(conn)
		go s.broker.handleConnWithRecover(sub, s.deps.Events)
	}
}

// subscriber wraps a coreapi.Stream with the per-subscriber state the
// broker needs (consecutive failure counter for the resilience
// contract). Created when handleConn first sees a connection.
type subscriber struct {
	conn            coreapi.Stream
	publishFailures atomic.Uint32
}

func newSubscriber(conn coreapi.Stream) *subscriber {
	return &subscriber{conn: conn}
}

func (s *subscriber) Close() error { return s.conn.Close() }

func (s *subscriber) remote() string {
	if s.conn == nil {
		return "<nil>"
	}
	addr := s.conn.RemoteAddr()
	return fmt.Sprintf("%s:%d", addr.String(), s.conn.RemotePort())
}

// broker is the in-process pub/sub for port 1002. Owned by the
// Service; one instance per daemon. Tracks subscribers by topic plus
// per-publisher rate buckets.
type broker struct {
	mu     sync.RWMutex
	subs   map[string][]*subscriber
	rateMu sync.Mutex
	rate   map[*subscriber]*publishBucket
	events coreapi.EventBus // for pubsub.* observability events
}

func newBroker(events coreapi.EventBus) *broker {
	return &broker{
		subs:   make(map[string][]*subscriber),
		events: events,
	}
}

type publishBucket struct {
	tokens     float64
	lastRefill time.Time
}

func (b *broker) takeToken(s *subscriber) bool {
	b.rateMu.Lock()
	defer b.rateMu.Unlock()
	if b.rate == nil {
		b.rate = make(map[*subscriber]*publishBucket)
	}
	now := time.Now()
	bucket, ok := b.rate[s]
	if !ok {
		bucket = &publishBucket{tokens: publishBurstBudget, lastRefill: now}
		b.rate[s] = bucket
	}
	elapsed := now.Sub(bucket.lastRefill).Seconds()
	if elapsed > 0 {
		bucket.tokens += elapsed * publishRatePerSecond
		if bucket.tokens > publishBurstBudget {
			bucket.tokens = publishBurstBudget
		}
		bucket.lastRefill = now
	}
	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	return true
}

func (b *broker) forgetPublisher(s *subscriber) {
	b.rateMu.Lock()
	delete(b.rate, s)
	b.rateMu.Unlock()
}

// handleConnWithRecover wraps handleConn with the L11 panic boundary.
// Tear down THIS subscriber only on panic — the broker and other
// subscribers stay alive.
func (b *broker) handleConnWithRecover(sub *subscriber, events coreapi.EventBus) {
	defer coreapi.RecoverPlugin("eventstream", "handleConn", events, func(_ any) {
		// Cleanup on panic — mirrors the normal teardown.
		b.removeSub(sub)
		b.forgetPublisher(sub)
		_ = sub.Close()
	})
	b.handleConn(sub)
}

func (b *broker) handleConn(sub *subscriber) {
	var topic string
	defer func() {
		b.removeSub(sub)
		b.forgetPublisher(sub)
		sub.Close()
		if topic != "" && b.events != nil {
			b.events.Publish("pubsub.unsubscribed", map[string]any{
				"topic": topic, "remote": sub.remote(),
			})
		}
	}()

	slog.Info("eventstream broker: handleConn started", "remote", sub.remote())
	subEvt, err := internales.ReadEvent(sub.conn)
	if err != nil {
		slog.Warn("eventstream broker: subscribe read failed", "remote", sub.remote(), "err", err)
		return
	}
	slog.Info("eventstream broker: subscribe received", "remote", sub.remote(), "topic", subEvt.Topic)
	topic = subEvt.Topic
	b.addSub(topic, sub)
	if b.events != nil {
		b.events.Publish("pubsub.subscribed", map[string]any{
			"topic": topic, "remote": sub.remote(),
		})
	}

	for {
		evt, err := internales.ReadEvent(sub.conn)
		if err != nil {
			slog.Info("eventstream broker: publish read done", "remote", sub.remote(), "err", err)
			return
		}
		slog.Info("eventstream broker: publish received", "remote", sub.remote(), "topic", evt.Topic, "bytes", len(evt.Payload))
		if !b.takeToken(sub) {
			slog.Warn("pubsub publish dropped: rate limit",
				"remote", sub.remote(),
				"topic", evt.Topic,
				"limit_per_sec", publishRatePerSecond)
			if b.events != nil {
				b.events.Publish("pubsub.rate_limited", map[string]any{
					"topic": evt.Topic, "from": sub.remote(),
				})
			}
			continue
		}
		b.publish(evt, sub)
	}
}

func (b *broker) addSub(topic string, sub *subscriber) {
	b.mu.Lock()
	b.subs[topic] = append(b.subs[topic], sub)
	b.mu.Unlock()
}

func (b *broker) removeSub(sub *subscriber) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for topic, subs := range b.subs {
		for i, s := range subs {
			if s == sub {
				b.subs[topic] = append(subs[:i], subs[i+1:]...)
				break
			}
		}
		if len(b.subs[topic]) == 0 {
			delete(b.subs, topic)
		}
	}
}

// eventWriter abstracts the per-subscriber WriteEvent — production
// uses pkg.WriteEvent; tests inject a fake to exercise retry +
// failure-counter behavior without real tunnels.
type eventWriter func(s *subscriber, evt *internales.Event) error

func defaultEventWriter(s *subscriber, evt *internales.Event) error {
	return internales.WriteEvent(s.conn, evt)
}

func (b *broker) publish(evt *internales.Event, sender *subscriber) {
	b.publishWith(evt, sender, defaultEventWriter)
}

// publishWith delivers evt to subscribers of evt.Topic + "*", skipping
// the sender. Resilience contract:
//   - first WriteEvent error → retry once after publishRetryBackoff
//   - subscriber only removed after maxConsecutivePublishFailures
//     in a row; first success resets the counter.
//   - snapshot subscriber list under lock then I/O outside the lock
//     (P2-003 — slow subscriber must not block other publishers).
func (b *broker) publishWith(evt *internales.Event, sender *subscriber, write eventWriter) {
	b.mu.RLock()
	targets := make([]*subscriber, 0, len(b.subs[evt.Topic])+len(b.subs["*"]))
	for _, s := range b.subs[evt.Topic] {
		if s != sender {
			targets = append(targets, s)
		}
	}
	if evt.Topic != "*" {
		for _, s := range b.subs["*"] {
			if s != sender {
				targets = append(targets, s)
			}
		}
	}
	b.mu.RUnlock()

	var dead []*subscriber
	for _, s := range targets {
		err := write(s, evt)
		if err != nil {
			time.Sleep(publishRetryBackoff)
			err = write(s, evt)
		}
		if err == nil {
			s.publishFailures.Store(0)
			continue
		}
		failureCount := s.publishFailures.Add(1)
		if failureCount >= maxConsecutivePublishFailures {
			slog.Debug("eventstream subscriber removed after consecutive failures",
				"remote", s.remote(),
				"consecutive_failures", failureCount,
				"last_error", err)
			dead = append(dead, s)
		} else {
			slog.Debug("eventstream write failed, retaining subscriber",
				"remote", s.remote(),
				"consecutive_failures", failureCount,
				"error", err)
		}
	}
	for _, s := range dead {
		b.removeSub(s)
	}
	slog.Info("eventstream published", "topic", evt.Topic, "bytes", len(evt.Payload), "from", sender.remote(), "targets", len(targets))
	if b.events != nil {
		b.events.Publish("pubsub.published", map[string]any{
			"topic": evt.Topic, "size": len(evt.Payload), "from": sender.remote(),
		})
	}
}
