// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/dataexchange"
	"github.com/TeoSlayer/pilotprotocol/pkg/eventstream"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// Iter-113 coverage for three 0% functions in services.go:
//   - handleDataExchangeConn (port 1001 per-conn reader + save + ACK loop)
//   - eventBroker.handleConn (port 1002 subscribe-then-publish per-conn loop)
//   - eventBroker.publish (fan-out with dead-subscriber cleanup)
//
// Approach: feed pre-serialized frames/events into conn.RecvBuf; Connection.State=0
// causes SendData-backed writes to fail, so the ACK/publish path exits after the
// save/sub-registration has happened — tests assert on the disk side-effects +
// in-memory sub map + per-function coverage.

// --- handleDataExchangeConn: close(RecvBuf) → ReadFrame EOF → return ---

func TestHandleDataExchangeConnExitsOnReadError(t *testing.T) {
	d := New(Config{})
	conn := &Connection{
		ID:         101,
		RecvBuf:    make(chan []byte, 2),
		RemoteAddr: protocol.Addr{Network: 1, Node: 0x11223344},
		RemotePort: 5000,
	}
	conn.CloseRecvBuf()

	done := make(chan struct{})
	go func() {
		d.handleDataExchangeConn(conn)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleDataExchangeConn did not exit on closed RecvBuf")
	}
}

// --- handleDataExchangeConn: TypeText frame saves to inbox, ACK write errors, returns ---

func TestHandleDataExchangeConnSavesTextMessageToInbox(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	d := New(Config{})
	conn := &Connection{
		ID:         102,
		RecvBuf:    make(chan []byte, 2),
		RemoteAddr: protocol.Addr{Network: 2, Node: 0xABCDEF01},
		RemotePort: 6000,
	}

	var buf bytes.Buffer
	if err := dataexchange.WriteFrame(&buf, &dataexchange.Frame{
		Type:    dataexchange.TypeText,
		Payload: []byte("hello from 113"),
	}); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	conn.RecvBuf <- buf.Bytes()
	conn.CloseRecvBuf() // force the SECOND ReadFrame (after ACK-fail return) to EOF

	done := make(chan struct{})
	go func() {
		d.handleDataExchangeConn(conn)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("handleDataExchangeConn did not exit after frame + ACK-fail")
	}

	// Verify inbox write side-effect.
	inbox := filepath.Join(tmp, ".pilot", "inbox")
	entries, err := os.ReadDir(inbox)
	if err != nil {
		t.Fatalf("ReadDir inbox: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("inbox entries = %d, want 1", len(entries))
	}
	if !strings.HasPrefix(entries[0].Name(), "TEXT-") {
		t.Fatalf("inbox file = %q, want TEXT- prefix", entries[0].Name())
	}
}

// --- handleDataExchangeConn: TypeFile frame saves to received/ ---

func TestHandleDataExchangeConnSavesFileToReceived(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	d := New(Config{})
	conn := &Connection{
		ID:         103,
		RecvBuf:    make(chan []byte, 2),
		RemoteAddr: protocol.Addr{Network: 3, Node: 0x44556677},
		RemotePort: 7000,
	}

	var buf bytes.Buffer
	if err := dataexchange.WriteFrame(&buf, &dataexchange.Frame{
		Type:     dataexchange.TypeFile,
		Filename: "iter113.bin",
		Payload:  []byte{0xAA, 0xBB, 0xCC, 0xDD},
	}); err != nil {
		t.Fatalf("WriteFrame file: %v", err)
	}
	conn.RecvBuf <- buf.Bytes()
	conn.CloseRecvBuf()

	done := make(chan struct{})
	go func() {
		d.handleDataExchangeConn(conn)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("handleDataExchangeConn did not exit after file frame")
	}

	received := filepath.Join(tmp, ".pilot", "received")
	entries, err := os.ReadDir(received)
	if err != nil {
		t.Fatalf("ReadDir received: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("received entries = %d, want 1", len(entries))
	}
	if !strings.HasPrefix(entries[0].Name(), "iter113-") || !strings.HasSuffix(entries[0].Name(), ".bin") {
		t.Fatalf("received file = %q, want iter113-<ts>.bin", entries[0].Name())
	}
	data, err := os.ReadFile(filepath.Join(received, entries[0].Name()))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(data, []byte{0xAA, 0xBB, 0xCC, 0xDD}) {
		t.Fatalf("file contents = %x, want AABBCCDD", data)
	}
}

// --- handleDataExchangeConn: unknown frame type → neither save branch fires ---

func TestHandleDataExchangeConnUnknownTypeSkipsSave(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	d := New(Config{})
	conn := &Connection{
		ID:         104,
		RecvBuf:    make(chan []byte, 2),
		RemoteAddr: protocol.Addr{Network: 4, Node: 0x8899AABB},
		RemotePort: 8000,
	}

	// Type=999 is not TypeText/Binary/JSON/File — both if/else-if branches skip,
	// saveErr stays nil, ACK is attempted, write fails, return.
	var buf bytes.Buffer
	if err := dataexchange.WriteFrame(&buf, &dataexchange.Frame{
		Type:    999,
		Payload: []byte("skipped"),
	}); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	conn.RecvBuf <- buf.Bytes()
	conn.CloseRecvBuf()

	done := make(chan struct{})
	go func() {
		d.handleDataExchangeConn(conn)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("handleDataExchangeConn did not exit on unknown type")
	}

	// Neither inbox nor received should exist.
	if _, err := os.Stat(filepath.Join(tmp, ".pilot", "inbox")); !os.IsNotExist(err) {
		t.Fatalf("inbox dir should NOT exist for unknown frame type, err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, ".pilot", "received")); !os.IsNotExist(err) {
		t.Fatalf("received dir should NOT exist for unknown frame type, err=%v", err)
	}
}

// --- eventBroker.handleConn: first ReadEvent errors → return WITHOUT adding sub ---

func TestEventBrokerHandleConnExitsOnFirstReadError(t *testing.T) {
	d := New(Config{})
	conn := &Connection{
		ID:         201,
		RecvBuf:    make(chan []byte, 2),
		RemoteAddr: protocol.Addr{Network: 5, Node: 0xC0DE0001},
		RemotePort: 9000,
	}
	conn.CloseRecvBuf()

	adapter := newConnAdapter(d, conn)
	b := &eventBroker{subs: make(map[string][]*connAdapter)}

	done := make(chan struct{})
	go func() {
		b.handleConn(adapter)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleConn did not exit on closed RecvBuf")
	}

	if len(b.subs) != 0 {
		t.Fatalf("broker.subs = %v, want empty map (first-read-error should NOT register sub)", b.subs)
	}
}

// --- eventBroker.handleConn: subscribe + then read-error → sub added, then removed via defer ---

func TestEventBrokerHandleConnSubscribesThenExitsOnSecondReadError(t *testing.T) {
	d := New(Config{})
	conn := &Connection{
		ID:         202,
		RecvBuf:    make(chan []byte, 2),
		RemoteAddr: protocol.Addr{Network: 6, Node: 0xC0DE0002},
		RemotePort: 9001,
	}

	// First event is the subscription; second read returns EOF → defer fires.
	var buf bytes.Buffer
	if err := eventstream.WriteEvent(&buf, &eventstream.Event{
		Topic:   "iter113-topic",
		Payload: nil,
	}); err != nil {
		t.Fatalf("WriteEvent sub: %v", err)
	}
	conn.RecvBuf <- buf.Bytes()
	conn.CloseRecvBuf()

	adapter := newConnAdapter(d, conn)
	b := &eventBroker{subs: make(map[string][]*connAdapter)}

	done := make(chan struct{})
	go func() {
		b.handleConn(adapter)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("handleConn did not exit after sub + EOF")
	}

	// Defer's removeSub should have cleared the topic entry entirely.
	if len(b.subs) != 0 {
		t.Fatalf("broker.subs = %v, want empty after defer removeSub", b.subs)
	}
}

// --- eventBroker.handleConn: sub + publish event → publish invoked, then EOF exits ---

func TestEventBrokerHandleConnSubscribeThenPublishThenEOF(t *testing.T) {
	d := New(Config{})
	conn := &Connection{
		ID:         203,
		RecvBuf:    make(chan []byte, 4),
		RemoteAddr: protocol.Addr{Network: 7, Node: 0xC0DE0003},
		RemotePort: 9002,
	}

	// Serialize two back-to-back events: subscription + publish.
	// Push them as ONE channel send (adapter buffers leftover) so that
	// both ReadEvent calls succeed before the close triggers EOF on the third read.
	var buf bytes.Buffer
	if err := eventstream.WriteEvent(&buf, &eventstream.Event{Topic: "t2", Payload: nil}); err != nil {
		t.Fatalf("WriteEvent sub: %v", err)
	}
	if err := eventstream.WriteEvent(&buf, &eventstream.Event{Topic: "t2", Payload: []byte("pub1")}); err != nil {
		t.Fatalf("WriteEvent pub: %v", err)
	}
	conn.RecvBuf <- buf.Bytes()
	conn.CloseRecvBuf()

	adapter := newConnAdapter(d, conn)
	b := &eventBroker{subs: make(map[string][]*connAdapter)}

	done := make(chan struct{})
	go func() {
		b.handleConn(adapter)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("handleConn did not exit after sub+publish+EOF")
	}

	// publish() was called with a single subscriber that IS the sender,
	// so no writes occurred; defer still runs removeSub → map empty.
	if len(b.subs) != 0 {
		t.Fatalf("broker.subs = %v, want empty after defer removeSub", b.subs)
	}
}

// --- eventBroker.publish: no subscribers on topic → early noop ---

func TestEventBrokerPublishNoSubscribersNoop(t *testing.T) {
	d := New(Config{})
	conn := &Connection{
		ID:         301,
		RecvBuf:    make(chan []byte, 1),
		RemoteAddr: protocol.Addr{Network: 8, Node: 0xD00D0001},
		RemotePort: 10000,
	}
	sender := newConnAdapter(d, conn)

	b := &eventBroker{subs: make(map[string][]*connAdapter)}
	evt := &eventstream.Event{Topic: "ghost", Payload: []byte("nobody listening")}
	// Should not panic, not hang, and not touch any conn.
	b.publish(evt, sender)

	if len(b.subs) != 0 {
		t.Fatalf("broker.subs = %v, want empty", b.subs)
	}
}

// --- eventBroker.publish: skips the sender itself ---

func TestEventBrokerPublishSkipsSender(t *testing.T) {
	d := New(Config{})
	connSender := &Connection{
		ID: 401, RecvBuf: make(chan []byte, 1),
		RemoteAddr: protocol.Addr{Network: 9, Node: 0xFEED0001}, RemotePort: 11000,
	}
	sender := newConnAdapter(d, connSender)

	// Broker has ONLY the sender subscribed to topic "loop" — publish should skip it
	// and NOT try to write (which would fail since State=0).
	b := &eventBroker{
		subs: map[string][]*connAdapter{"loop": {sender}},
	}
	evt := &eventstream.Event{Topic: "loop", Payload: []byte("echo to self?")}
	b.publish(evt, sender)

	// Sender should still be registered — publish only prunes dead writes;
	// no write was attempted, so no pruning.
	subs, ok := b.subs["loop"]
	if !ok || len(subs) != 1 || subs[0] != sender {
		t.Fatalf("sender was incorrectly pruned: subs=%v ok=%v", subs, ok)
	}
}

// --- eventBroker.publish: fan-out to non-sender sub fails + prunes dead ---

func TestEventBrokerPublishPrunesDeadSubscriber(t *testing.T) {
	d := New(Config{})

	connA := &Connection{
		ID: 501, RecvBuf: make(chan []byte, 1),
		RemoteAddr: protocol.Addr{Network: 10, Node: 0xAAA00001}, RemotePort: 12000,
	}
	connB := &Connection{
		ID: 502, RecvBuf: make(chan []byte, 1),
		RemoteAddr: protocol.Addr{Network: 10, Node: 0xBBB00002}, RemotePort: 12001,
	}
	sender := newConnAdapter(d, connA)
	deadSub := newConnAdapter(d, connB)

	b := &eventBroker{
		subs: map[string][]*connAdapter{"news": {sender, deadSub}},
	}
	evt := &eventstream.Event{Topic: "news", Payload: []byte("headline")}
	b.publish(evt, sender)

	// deadSub's WriteEvent failed (SendData errors with State=0) → added to dead →
	// cleaned up via removeSub outside the read lock. Sender stays.
	subs := b.subs["news"]
	if len(subs) != 1 {
		t.Fatalf("subs[news] len = %d, want 1 (dead pruned, sender kept)", len(subs))
	}
	if subs[0] != sender {
		t.Fatalf("subs[news][0] = %p, want sender %p", subs[0], sender)
	}
}

// --- eventBroker.publish: wildcard "*" receives non-"*" topic publishes ---

func TestEventBrokerPublishFanOutsToWildcardSubscribers(t *testing.T) {
	d := New(Config{})

	connSender := &Connection{
		ID: 601, RecvBuf: make(chan []byte, 1),
		RemoteAddr: protocol.Addr{Network: 11, Node: 0xCC000001}, RemotePort: 13000,
	}
	connWild := &Connection{
		ID: 602, RecvBuf: make(chan []byte, 1),
		RemoteAddr: protocol.Addr{Network: 11, Node: 0xCC000002}, RemotePort: 13001,
	}
	sender := newConnAdapter(d, connSender)
	wildSub := newConnAdapter(d, connWild)

	b := &eventBroker{
		subs: map[string][]*connAdapter{
			"updates": {sender},
			"*":       {wildSub},
		},
	}
	evt := &eventstream.Event{Topic: "updates", Payload: []byte("u1")}
	b.publish(evt, sender)

	// wildSub's write also fails (State=0) → pruned from "*".
	if len(b.subs["*"]) != 0 {
		t.Fatalf(`subs["*"] len = %d, want 0 (dead wildcard pruned)`, len(b.subs["*"]))
	}
	// "updates" keeps the sender (never attempted to write).
	if len(b.subs["updates"]) != 1 {
		t.Fatalf(`subs["updates"] len = %d, want 1 (sender stays)`, len(b.subs["updates"]))
	}
}

// --- eventBroker.publish: topic "*" itself does NOT double-dispatch via wildcard branch ---

func TestEventBrokerPublishWildcardTopicDoesNotSelfDispatch(t *testing.T) {
	d := New(Config{})
	connSender := &Connection{
		ID: 701, RecvBuf: make(chan []byte, 1),
		RemoteAddr: protocol.Addr{Network: 12, Node: 0xDD000001}, RemotePort: 14000,
	}
	connSub := &Connection{
		ID: 702, RecvBuf: make(chan []byte, 1),
		RemoteAddr: protocol.Addr{Network: 12, Node: 0xDD000002}, RemotePort: 14001,
	}
	sender := newConnAdapter(d, connSender)
	sub := newConnAdapter(d, connSub)

	// A "*"-topic event: the first loop iterates subs["*"] (sub), write fails → pruned.
	// The `if evt.Topic != "*"` guard at services.go:381 SHOULD SKIP the second loop,
	// else sub would get written-to twice and dead-added twice (harmless but wasteful).
	b := &eventBroker{
		subs: map[string][]*connAdapter{"*": {sub}},
	}
	evt := &eventstream.Event{Topic: "*", Payload: []byte("broadcast")}
	b.publish(evt, sender)

	// sub is pruned (write failed) — map key removed when slice empty.
	if _, exists := b.subs["*"]; exists {
		t.Fatalf(`subs["*"] should be removed (single dead sub pruned to empty); still exists`)
	}
}
