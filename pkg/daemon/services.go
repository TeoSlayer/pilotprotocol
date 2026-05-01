// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/dataexchange"
	"github.com/TeoSlayer/pilotprotocol/pkg/eventstream"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
	"github.com/TeoSlayer/pilotprotocol/pkg/tasksubmit"
)

// connAdapter wraps a daemon *Connection as a net.Conn so that existing
// service packages (dataexchange, eventstream) that use io.Reader/io.Writer
// can work directly on top of the daemon's port infrastructure.
type connAdapter struct {
	conn   *Connection
	daemon *Daemon
	buf    []byte // leftover from previous RecvBuf read

	// publishFailures counts consecutive WriteEvent failures observed by
	// the eventBroker for THIS subscriber. A subscriber is only removed
	// from broker.subs after maxConsecutivePublishFailures in a row, so a
	// single transient tunnel blip doesn't kill the subscription. Reset
	// to 0 on the first successful WriteEvent. Atomic because publish()
	// runs concurrently across publishers without holding a write lock.
	publishFailures atomic.Uint32
}

func newConnAdapter(d *Daemon, conn *Connection) *connAdapter {
	return &connAdapter{conn: conn, daemon: d}
}

func (a *connAdapter) Read(p []byte) (int, error) {
	// Drain leftover buffer first
	if len(a.buf) > 0 {
		n := copy(p, a.buf)
		a.buf = a.buf[n:]
		return n, nil
	}
	data, ok := <-a.conn.RecvBuf
	if !ok {
		return 0, io.EOF
	}
	n := copy(p, data)
	if n < len(data) {
		a.buf = data[n:]
	}
	return n, nil
}

func (a *connAdapter) Write(p []byte) (int, error) {
	if err := a.daemon.SendData(a.conn, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (a *connAdapter) Close() error {
	a.daemon.CloseConnection(a.conn)
	return nil
}

func (a *connAdapter) LocalAddr() net.Addr {
	return pilotAddr{addr: a.conn.LocalAddr, port: a.conn.LocalPort}
}

func (a *connAdapter) RemoteAddr() net.Addr {
	return pilotAddr{addr: a.conn.RemoteAddr, port: a.conn.RemotePort}
}

// pilotAddr implements net.Addr for Pilot Protocol endpoints.
type pilotAddr struct {
	addr protocol.Addr
	port uint16
}

func (p pilotAddr) Network() string { return "pilot" }
func (p pilotAddr) String() string {
	return fmt.Sprintf("%s:%d", p.addr.String(), p.port)
}

func (a *connAdapter) SetDeadline(t time.Time) error      { return nil }
func (a *connAdapter) SetReadDeadline(t time.Time) error  { return nil }
func (a *connAdapter) SetWriteDeadline(t time.Time) error { return nil }

// inboxSeq produces a monotonically increasing suffix for inbox/received
// filenames. ms-precision timestamps collide under burst load (multiple
// messages arriving in the same millisecond), causing os.WriteFile to
// overwrite and silently drop earlier messages.
var inboxSeq uint64

// startBuiltinServices starts all enabled built-in port services.
func (d *Daemon) startBuiltinServices() {
	if !d.config.DisableEcho {
		if err := d.startEchoService(); err != nil {
			slog.Warn("echo service failed to start", "error", err)
		}
	}
	if !d.config.DisableDataExchange {
		if err := d.startDataExchangeService(); err != nil {
			slog.Warn("dataexchange service failed to start", "error", err)
		}
	}
	if !d.config.DisableEventStream {
		if err := d.startEventStreamService(); err != nil {
			slog.Warn("eventstream service failed to start", "error", err)
		}
	}
	if !d.config.DisableTaskSubmit {
		if err := d.startTaskSubmitService(); err != nil {
			slog.Warn("tasksubmit service failed to start", "error", err)
		}
	}
}

// startEchoService binds port 7 and echoes back all received data.
func (d *Daemon) startEchoService() error {
	ln, err := d.ports.Bind(protocol.PortEcho)
	if err != nil {
		return err
	}
	go func() {
		for {
			select {
			case conn, ok := <-ln.AcceptCh:
				if !ok {
					return
				}
				go d.handleEchoConn(conn)
			case <-d.stopCh:
				return
			}
		}
	}()
	slog.Info("echo service listening", "port", protocol.PortEcho)
	return nil
}

func (d *Daemon) handleEchoConn(conn *Connection) {
	for {
		data, ok := <-conn.RecvBuf
		if !ok {
			return
		}
		if err := d.SendData(conn, data); err != nil {
			return
		}
	}
}

// startDataExchangeService binds port 1001 and handles data exchange frames.
func (d *Daemon) startDataExchangeService() error {
	ln, err := d.ports.Bind(protocol.PortDataExchange)
	if err != nil {
		return err
	}
	go func() {
		for {
			select {
			case conn, ok := <-ln.AcceptCh:
				if !ok {
					return
				}
				go d.handleDataExchangeConn(conn)
			case <-d.stopCh:
				return
			}
		}
	}()
	slog.Info("dataexchange service listening", "port", protocol.PortDataExchange)
	return nil
}

func (d *Daemon) handleDataExchangeConn(conn *Connection) {
	adapter := newConnAdapter(d, conn)
	defer adapter.Close()
	for {
		frame, err := dataexchange.ReadFrame(adapter)
		if err != nil {
			return
		}
		slog.Debug("dataexchange frame received",
			"type", dataexchange.TypeName(frame.Type),
			"bytes", len(frame.Payload),
			"remote", conn.RemoteAddr,
		)

		var saveErr error
		if frame.Type == dataexchange.TypeFile && frame.Filename != "" {
			// Save received files to disk
			saveErr = d.saveReceivedFile(frame)
		} else if frame.Type == dataexchange.TypeText || frame.Type == dataexchange.TypeJSON || frame.Type == dataexchange.TypeBinary {
			// Save messages to inbox
			saveErr = d.saveInboxMessage(frame, conn.RemoteAddr)
		}

		// ACK: echo back a text frame confirming receipt
		ackMsg := fmt.Sprintf("ACK %s %d bytes", dataexchange.TypeName(frame.Type), len(frame.Payload))
		if saveErr != nil {
			ackMsg = fmt.Sprintf("ERR %s save failed: %v", dataexchange.TypeName(frame.Type), saveErr)
		}
		ack := &dataexchange.Frame{
			Type:    dataexchange.TypeText,
			Payload: []byte(ackMsg),
		}
		if err := dataexchange.WriteFrame(adapter, ack); err != nil {
			return
		}
	}
}

// saveReceivedFile saves a received file frame to ~/.pilot/received/.
func (d *Daemon) saveReceivedFile(frame *dataexchange.Frame) error {
	home, err := os.UserHomeDir()
	if err != nil {
		slog.Warn("save received file: cannot determine home dir", "err", err)
		return fmt.Errorf("home dir: %w", err)
	}
	dir := filepath.Join(home, ".pilot", "received")
	if err := os.MkdirAll(dir, 0700); err != nil {
		slog.Warn("save received file: mkdir failed", "err", err)
		return fmt.Errorf("mkdir: %w", err)
	}

	// Sanitize filename; add ms timestamp + monotonic seq so bursts in the
	// same millisecond don't collide and overwrite each other.
	safeName := filepath.Base(frame.Filename)
	ts := time.Now().Format("20060102-150405.000")
	seq := atomic.AddUint64(&inboxSeq, 1)
	ext := filepath.Ext(safeName)
	base := safeName[:len(safeName)-len(ext)]
	destName := fmt.Sprintf("%s-%s-%06d%s", base, ts, seq, ext)
	destPath := filepath.Join(dir, destName)

	if err := os.WriteFile(destPath, frame.Payload, 0600); err != nil {
		// Clean up any partial file os.WriteFile may have left on disk
		// (ENOSPC truncates rather than rolling back).
		_ = os.Remove(destPath)
		slog.Warn("save received file: write failed", "path", destPath, "err", err)
		return fmt.Errorf("write: %w", err)
	}
	slog.Info("file saved", "path", destPath, "bytes", len(frame.Payload))
	d.webhook.Emit("file.received", map[string]interface{}{
		"filename": safeName, "size": len(frame.Payload), "path": destPath,
	})
	return nil
}

// saveInboxMessage saves a received text/JSON/binary message to ~/.pilot/inbox/.
func (d *Daemon) saveInboxMessage(frame *dataexchange.Frame, from protocol.Addr) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("home dir: %w", err)
	}
	dir := filepath.Join(home, ".pilot", "inbox")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	ts := time.Now()
	msg := map[string]interface{}{
		"type":        dataexchange.TypeName(frame.Type),
		"from":        from.String(),
		"data":        string(frame.Payload),
		"bytes":       len(frame.Payload),
		"received_at": ts.Format(time.RFC3339Nano),
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	seq := atomic.AddUint64(&inboxSeq, 1)
	filename := fmt.Sprintf("%s-%s-%06d.json", dataexchange.TypeName(frame.Type), ts.Format("20060102-150405.000"), seq)
	destPath := filepath.Join(dir, filename)

	if err := os.WriteFile(destPath, data, 0600); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	slog.Info("inbox message saved", "path", destPath, "type", dataexchange.TypeName(frame.Type), "bytes", len(frame.Payload))
	d.webhook.Emit("message.received", map[string]interface{}{
		"type": dataexchange.TypeName(frame.Type), "from": from.String(),
		"size": len(frame.Payload),
	})
	return nil
}

// startEventStreamService binds port 1002 and runs a pub/sub broker.
func (d *Daemon) startEventStreamService() error {
	ln, err := d.ports.Bind(protocol.PortEventStream)
	if err != nil {
		return err
	}
	broker := &eventBroker{
		subs:   make(map[string][]*connAdapter),
		daemon: d,
	}
	go func() {
		for {
			select {
			case conn, ok := <-ln.AcceptCh:
				if !ok {
					return
				}
				adapter := newConnAdapter(d, conn)
				go broker.handleConn(adapter)
			case <-d.stopCh:
				return
			}
		}
	}()
	slog.Info("eventstream service listening", "port", protocol.PortEventStream)
	return nil
}

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
// subscriber, dropping every subsequent event. The integration suite
// documented `test_pubsub_multi_publisher` flakiness directly because of
// this. We now:
//   - retry the failed WriteEvent once after a brief backoff (handles ms-
//     scale glitches like a queue that just hadn't drained yet);
//   - track consecutive failures per subscriber and only remove after
//     maxConsecutivePublishFailures in a row.
const (
	publishRetryBackoff           = 20 * time.Millisecond
	maxConsecutivePublishFailures = 3
)

// eventBroker is an in-process pub/sub broker for the event stream service.
type eventBroker struct {
	mu     sync.RWMutex
	subs   map[string][]*connAdapter // topic → subscribers
	daemon *Daemon                   // hot-swap-safe webhook via d.webhook
	rateMu sync.Mutex
	// rate tracks publish tokens per publisher adapter. Token-bucket
	// refill rate is publishRatePerSecond, capped at publishBurstBudget.
	rate map[*connAdapter]*publishBucket
}

// webhook returns the current daemon webhook client — SetWebhookURL
// hot-swaps d.webhook, so the broker must read through on each Emit
// instead of caching the pointer at startup (otherwise emits routed
// via the initial nil/empty webhook silently drop).
func (b *eventBroker) webhook() *WebhookClient {
	if b.daemon == nil {
		return nil
	}
	return b.daemon.webhook
}

type publishBucket struct {
	tokens     float64
	lastRefill time.Time
}

// takeToken returns true if a publish token is available and deducts one.
func (b *eventBroker) takeToken(adapter *connAdapter) bool {
	b.rateMu.Lock()
	defer b.rateMu.Unlock()
	if b.rate == nil {
		b.rate = make(map[*connAdapter]*publishBucket)
	}
	now := time.Now()
	bucket, ok := b.rate[adapter]
	if !ok {
		bucket = &publishBucket{tokens: publishBurstBudget, lastRefill: now}
		b.rate[adapter] = bucket
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

// forgetPublisher drops a publisher's token bucket when they disconnect.
func (b *eventBroker) forgetPublisher(adapter *connAdapter) {
	b.rateMu.Lock()
	delete(b.rate, adapter)
	b.rateMu.Unlock()
}

func (b *eventBroker) handleConn(adapter *connAdapter) {
	var topic string
	defer func() {
		b.removeSub(adapter)
		b.forgetPublisher(adapter)
		adapter.Close()
		if topic != "" {
			b.webhook().Emit("pubsub.unsubscribed", map[string]interface{}{
				"topic": topic, "remote": adapter.RemoteAddr().String(),
			})
		}
	}()

	slog.Info("eventstream broker: handleConn started", "remote", adapter.RemoteAddr().String())
	// First event = subscription
	subEvt, err := eventstream.ReadEvent(adapter)
	if err != nil {
		slog.Warn("eventstream broker: subscribe read failed", "remote", adapter.RemoteAddr().String(), "err", err)
		return
	}
	slog.Info("eventstream broker: subscribe received", "remote", adapter.RemoteAddr().String(), "topic", subEvt.Topic)
	topic = subEvt.Topic
	b.addSub(topic, adapter)
	slog.Debug("eventstream subscription", "remote", adapter.RemoteAddr(), "topic", topic)
	b.webhook().Emit("pubsub.subscribed", map[string]interface{}{
		"topic": topic, "remote": adapter.RemoteAddr().String(),
	})

	// Remaining events = publish
	for {
		evt, err := eventstream.ReadEvent(adapter)
		if err != nil {
			slog.Info("eventstream broker: publish read done", "remote", adapter.RemoteAddr().String(), "err", err)
			return
		}
		slog.Info("eventstream broker: publish received", "remote", adapter.RemoteAddr().String(), "topic", evt.Topic, "bytes", len(evt.Payload))
		// Issue #196: rate-limit per publisher so a misbehaving client
		// can't saturate routeLoop or overwhelm every subscriber.
		if !b.takeToken(adapter) {
			slog.Warn("pubsub publish dropped: rate limit",
				"remote", adapter.RemoteAddr(),
				"topic", evt.Topic,
				"limit_per_sec", publishRatePerSecond)
			b.webhook().Emit("pubsub.rate_limited", map[string]interface{}{
				"topic": evt.Topic, "from": adapter.RemoteAddr().String(),
			})
			continue
		}
		b.publish(evt, adapter)
	}
}

func (b *eventBroker) addSub(topic string, adapter *connAdapter) {
	b.mu.Lock()
	b.subs[topic] = append(b.subs[topic], adapter)
	b.mu.Unlock()
}

func (b *eventBroker) removeSub(adapter *connAdapter) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for topic, conns := range b.subs {
		for i, c := range conns {
			if c == adapter {
				b.subs[topic] = append(conns[:i], conns[i+1:]...)
				break
			}
		}
		if len(b.subs[topic]) == 0 {
			delete(b.subs, topic)
		}
	}
}

// eventWriter abstracts the act of delivering an event to a subscriber.
// Production uses eventstream.WriteEvent; tests inject a fake to exercise
// retry / failure-counter behavior without spinning up real tunnels.
type eventWriter func(conn *connAdapter, evt *eventstream.Event) error

func defaultEventWriter(conn *connAdapter, evt *eventstream.Event) error {
	return eventstream.WriteEvent(conn, evt)
}

func (b *eventBroker) publish(evt *eventstream.Event, sender *connAdapter) {
	b.publishWith(evt, sender, defaultEventWriter)
}

// publishWith delivers evt to all subscribers of evt.Topic plus the wildcard
// "*" topic, skipping the sender. write is the per-subscriber delivery
// function — production uses eventstream.WriteEvent; tests can inject a
// fake to exercise retry + failure-counter behavior.
//
// Resilience contract:
//   - First WriteEvent error → retry once after publishRetryBackoff.
//     Handles ms-scale tunnel hiccups that resolve on their own.
//   - Each retry failure increments conn.publishFailures.
//   - Subscriber is only removed once publishFailures reaches
//     maxConsecutivePublishFailures (default 3).
//   - First success resets the counter to 0.
//
// Before this change, a single transient failure permanently removed the
// subscriber; downstream events were silently dropped, which was the root
// cause of `test_pubsub_multi_publisher` flakiness.
func (b *eventBroker) publishWith(evt *eventstream.Event, sender *connAdapter, write eventWriter) {
	// P2-003: snapshot the subscriber list under the lock, then do the
	// WriteEvent I/O after release. Holding RLock across network writes
	// lets one slow subscriber block every concurrent publisher.
	b.mu.RLock()
	targets := make([]*connAdapter, 0, len(b.subs[evt.Topic])+len(b.subs["*"]))
	for _, conn := range b.subs[evt.Topic] {
		if conn != sender {
			targets = append(targets, conn)
		}
	}
	if evt.Topic != "*" {
		for _, conn := range b.subs["*"] {
			if conn != sender {
				targets = append(targets, conn)
			}
		}
	}
	b.mu.RUnlock()

	var dead []*connAdapter
	for _, conn := range targets {
		err := write(conn, evt)
		if err != nil {
			// Retry once with a short backoff to absorb transient
			// network/tunnel hiccups. The backoff is small enough that
			// the publisher's wall-clock impact is negligible even when
			// most writes succeed first try.
			time.Sleep(publishRetryBackoff)
			err = write(conn, evt)
		}

		if err == nil {
			conn.publishFailures.Store(0)
			continue
		}

		failureCount := conn.publishFailures.Add(1)
		if failureCount >= maxConsecutivePublishFailures {
			slog.Debug("eventstream subscriber removed after consecutive failures",
				"remote", conn.RemoteAddr(),
				"consecutive_failures", failureCount,
				"last_error", err)
			dead = append(dead, conn)
		} else {
			slog.Debug("eventstream write failed, retaining subscriber",
				"remote", conn.RemoteAddr(),
				"consecutive_failures", failureCount,
				"error", err)
		}
	}

	// Clean up dead subscribers outside the read lock
	for _, conn := range dead {
		b.removeSub(conn)
	}
	slog.Info("eventstream published", "topic", evt.Topic, "bytes", len(evt.Payload), "from", sender.RemoteAddr(), "targets", len(targets))
	b.webhook().Emit("pubsub.published", map[string]interface{}{
		"topic": evt.Topic, "size": len(evt.Payload), "from": sender.RemoteAddr().String(),
	})
}

// ===================== TASK SUBMISSION SERVICE =====================

// TaskQueue manages pending task submissions using a FIFO queue.
type TaskQueue struct {
	mu           sync.Mutex
	taskIDs      []string          // FIFO queue of task IDs (only accepted tasks)
	headStagedAt map[string]string // Track when each task became head of queue (RFC3339)
}

// NewTaskQueue creates a new task queue.
func NewTaskQueue() *TaskQueue {
	return &TaskQueue{
		taskIDs:      make([]string, 0),
		headStagedAt: make(map[string]string),
	}
}

// Add adds a task ID to the queue. If this is the first task, mark it as head.
func (q *TaskQueue) Add(taskID string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	wasEmpty := len(q.taskIDs) == 0
	q.taskIDs = append(q.taskIDs, taskID)
	if wasEmpty {
		// First task becomes head immediately
		q.headStagedAt[taskID] = time.Now().UTC().Format(time.RFC3339)
	}
}

// Pop removes and returns the next task ID from the queue, or empty string if empty.
// Also updates the head timestamp for the new head if one exists.
func (q *TaskQueue) Pop() string {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.taskIDs) == 0 {
		return ""
	}
	taskID := q.taskIDs[0]
	delete(q.headStagedAt, taskID) // Remove old head's timestamp
	q.taskIDs = q.taskIDs[1:]
	// Mark new head with staged timestamp
	if len(q.taskIDs) > 0 {
		newHead := q.taskIDs[0]
		if _, exists := q.headStagedAt[newHead]; !exists {
			q.headStagedAt[newHead] = time.Now().UTC().Format(time.RFC3339)
		}
	}
	return taskID
}

// Remove removes a specific task ID from the queue (used for expiry/cancellation).
func (q *TaskQueue) Remove(taskID string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	for i, id := range q.taskIDs {
		if id == taskID {
			wasHead := i == 0
			delete(q.headStagedAt, taskID)
			q.taskIDs = append(q.taskIDs[:i], q.taskIDs[i+1:]...)
			// If we removed the head, mark new head with staged timestamp
			if wasHead && len(q.taskIDs) > 0 {
				newHead := q.taskIDs[0]
				if _, exists := q.headStagedAt[newHead]; !exists {
					q.headStagedAt[newHead] = time.Now().UTC().Format(time.RFC3339)
				}
			}
			return true
		}
	}
	return false
}

// Peek returns the first task ID without removing it, or empty string if empty.
func (q *TaskQueue) Peek() string {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.taskIDs) == 0 {
		return ""
	}
	return q.taskIDs[0]
}

// GetHeadStagedAt returns when the head task became head of queue (RFC3339 timestamp).
func (q *TaskQueue) GetHeadStagedAt() string {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.taskIDs) == 0 {
		return ""
	}
	return q.headStagedAt[q.taskIDs[0]]
}

// GetStagedAt returns when a specific task became head of queue.
func (q *TaskQueue) GetStagedAt(taskID string) string {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.headStagedAt[taskID]
}

// Len returns the number of tasks in the queue.
func (q *TaskQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.taskIDs)
}

// List returns all task IDs in the queue.
func (q *TaskQueue) List() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	result := make([]string, len(q.taskIDs))
	copy(result, q.taskIDs)
	return result
}

// Global queue instance for pilotctl to use
var globalTaskQueue = NewTaskQueue()

// RemoveFromQueue is a package-level function to remove a task from the global queue.
// This is used by pilotctl commands.
func RemoveFromQueue(taskID string) bool {
	return globalTaskQueue.Remove(taskID)
}

// GetQueueStagedAt returns when a task became head of the global queue.
func GetQueueStagedAt(taskID string) string {
	return globalTaskQueue.GetStagedAt(taskID)
}

// getTasksDir returns the path to ~/.pilot/tasks directory.
func getTasksDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".pilot", "tasks"), nil
}

// ensureTaskDirs creates the tasks/submitted and tasks/received directories.
func ensureTaskDirs() error {
	tasksDir, err := getTasksDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(tasksDir, "submitted"), 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(tasksDir, "received"), 0700); err != nil {
		return err
	}
	return nil
}

// SaveTaskFile saves a task file to the appropriate directory.
func SaveTaskFile(tf *tasksubmit.TaskFile, isSubmitter bool) error {
	if err := ensureTaskDirs(); err != nil {
		return err
	}
	tasksDir, err := getTasksDir()
	if err != nil {
		return err
	}

	subdir := "received"
	if isSubmitter {
		subdir = "submitted"
	}

	data, err := tasksubmit.MarshalTaskFile(tf)
	if err != nil {
		return err
	}

	filename := filepath.Join(tasksDir, subdir, tf.TaskID+".json")
	return os.WriteFile(filename, data, 0600)
}

// LoadTaskFile loads a task file from the received directory.
func LoadTaskFile(taskID string) (*tasksubmit.TaskFile, error) {
	tasksDir, err := getTasksDir()
	if err != nil {
		return nil, err
	}

	filename := filepath.Join(tasksDir, "received", taskID+".json")
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return tasksubmit.UnmarshalTaskFile(data)
}

// LoadSubmittedTaskFile loads a task file from the submitted directory.
func LoadSubmittedTaskFile(taskID string) (*tasksubmit.TaskFile, error) {
	tasksDir, err := getTasksDir()
	if err != nil {
		return nil, err
	}

	filename := filepath.Join(tasksDir, "submitted", taskID+".json")
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return tasksubmit.UnmarshalTaskFile(data)
}

// UpdateTaskStatus updates the status of a task file.
func UpdateTaskStatus(taskID, status, justification string, isSubmitter bool) error {
	tasksDir, err := getTasksDir()
	if err != nil {
		return err
	}

	subdir := "received"
	if isSubmitter {
		subdir = "submitted"
	}

	filename := filepath.Join(tasksDir, subdir, taskID+".json")
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	tf, err := tasksubmit.UnmarshalTaskFile(data)
	if err != nil {
		return err
	}

	tf.Status = status
	tf.StatusJustification = justification

	newData, err := tasksubmit.MarshalTaskFile(tf)
	if err != nil {
		return err
	}

	return os.WriteFile(filename, newData, 0600)
}

// UpdateTaskFileWithTimes updates a task file with time metadata calculations.
// action can be: "accept", "decline", "execute", "complete", "cancel", "expire"
func UpdateTaskFileWithTimes(taskID, status, justification, action string, isSubmitter bool, stagedAt string) error {
	tasksDir, err := getTasksDir()
	if err != nil {
		return err
	}

	subdir := "received"
	if isSubmitter {
		subdir = "submitted"
	}

	filename := filepath.Join(tasksDir, subdir, taskID+".json")
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	tf, err := tasksubmit.UnmarshalTaskFile(data)
	if err != nil {
		return err
	}

	tf.Status = status
	tf.StatusJustification = justification

	switch action {
	case "accept", "decline", "cancel":
		// Calculate time_idle (from creation to now)
		tf.CalculateTimeIdle()
	case "execute":
		// Set staged time and calculate time_staged
		if stagedAt != "" {
			tf.StagedAt = stagedAt
		}
		tf.CalculateTimeStaged()
	case "complete":
		// Calculate time_cpu (from execute start to now)
		tf.CalculateTimeCpu()
	case "expire":
		// Set staged time if provided
		if stagedAt != "" {
			tf.StagedAt = stagedAt
		}
		// Calculate time_staged (from staged to now)
		tf.CalculateTimeStaged()
	}

	newData, err := tasksubmit.MarshalTaskFile(tf)
	if err != nil {
		return err
	}

	return os.WriteFile(filename, newData, 0600)
}

// CancelTaskBothSides cancels a task on both the submitter and receiver sides.
func CancelTaskBothSides(taskID string) error {
	errReceiver := UpdateTaskFileWithTimes(taskID, tasksubmit.TaskStatusCancelled,
		"Task cancelled: no response within 1 minute", "cancel", false, "")
	errSubmitter := UpdateTaskFileWithTimes(taskID, tasksubmit.TaskStatusCancelled,
		"Task cancelled: no response within 1 minute", "cancel", true, "")

	if errReceiver != nil && errSubmitter != nil {
		return fmt.Errorf("receiver: %v, submitter: %v", errReceiver, errSubmitter)
	}
	if errReceiver != nil {
		return errReceiver
	}
	return errSubmitter
}

// ExpireTaskBothSides expires a task on both sides and decrements receiver's polo score.
func ExpireTaskBothSides(taskID, stagedAt string, regConn *registry.Client, receiverNodeID uint32) error {
	// Update receiver's task file to EXPIRED
	errReceiver := UpdateTaskFileWithTimes(taskID, tasksubmit.TaskStatusExpired,
		"Task expired: at head of queue for over 1 hour", "expire", false, stagedAt)

	// Update submitter's task file to EXPIRED
	errSubmitter := UpdateTaskFileWithTimes(taskID, tasksubmit.TaskStatusExpired,
		"Task expired: receiver did not execute within 1 hour", "expire", true, stagedAt)

	// Decrement receiver's polo score by 1
	if regConn != nil {
		if _, err := regConn.UpdatePoloScore(receiverNodeID, -1); err != nil {
			slog.Warn("failed to decrement polo score on task expiry", "node_id", receiverNodeID, "error", err)
		}
	}

	if errReceiver != nil {
		return errReceiver
	}
	return errSubmitter
}

// startTaskSubmitService binds port 1003 and handles task submissions.
func (d *Daemon) startTaskSubmitService() error {
	ln, err := d.ports.Bind(protocol.PortTaskSubmit)
	if err != nil {
		return err
	}
	go func() {
		for {
			select {
			case conn, ok := <-ln.AcceptCh:
				if !ok {
					return
				}
				go d.handleTaskSubmitConn(conn)
			case <-d.stopCh:
				return
			}
		}
	}()

	// Start task monitoring goroutines
	go d.monitorNewTasksForCancellation()
	go d.monitorQueueHeadForExpiry()

	slog.Info("tasksubmit service listening", "port", protocol.PortTaskSubmit)
	return nil
}

// monitorNewTasksForCancellation checks for NEW tasks that haven't been accepted/declined within 1 minute.
func (d *Daemon) monitorNewTasksForCancellation() {
	ticker := time.NewTicker(10 * time.Second) // Check every 10 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			d.checkAndCancelExpiredNewTasks()
		case <-d.stopCh:
			return
		}
	}
}

// checkAndCancelExpiredNewTasks scans received and submitted tasks for NEW
// tasks past the accept timeout. Both sides must scan independently — the
// remote peer's auto-cancel only updates its own local files, so each
// daemon is responsible for expiring its own NEW-state copies.
func (d *Daemon) checkAndCancelExpiredNewTasks() {
	tasksDir, err := getTasksDir()
	if err != nil {
		return
	}

	for _, sub := range []string{"received", "submitted"} {
		dir := filepath.Join(tasksDir, sub)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				continue
			}
			tf, err := tasksubmit.UnmarshalTaskFile(data)
			if err != nil {
				continue
			}

			if tf.IsExpiredForAccept() {
				slog.Info("tasksubmit: cancelling task due to accept timeout",
					"task_id", tf.TaskID,
					"side", sub,
					"created_at", tf.CreatedAt,
				)
				d.taskQueue.Remove(tf.TaskID)
				if err := CancelTaskBothSides(tf.TaskID); err != nil {
					slog.Warn("tasksubmit: failed to cancel task", "task_id", tf.TaskID, "error", err)
				}
			}

			// Submitter-side stall detection: if the receiver accepted but
			// then went silent (e.g., crashed before send-results), the
			// submitter must mark the task EXPIRED so callers don't see
			// it stuck in ACCEPTED forever.
			if sub == "submitted" && tf.IsAcceptedStalled() {
				slog.Info("tasksubmit: expiring submitter task — receiver silent past stall timeout",
					"task_id", tf.TaskID,
					"accepted_at", tf.AcceptedAt,
				)
				_ = UpdateTaskStatus(tf.TaskID, tasksubmit.TaskStatusExpired,
					"receiver did not return results within stall window", true)
			}
		}
	}
}

// monitorQueueHeadForExpiry checks if the head of queue has been there for over 1 hour.
func (d *Daemon) monitorQueueHeadForExpiry() {
	ticker := time.NewTicker(30 * time.Second) // Check every 30 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			d.checkAndExpireQueueHead()
		case <-d.stopCh:
			return
		}
	}
}

// checkAndExpireQueueHead checks if the head task has been staged for over 1 hour.
func (d *Daemon) checkAndExpireQueueHead() {
	headTaskID := d.taskQueue.Peek()
	if headTaskID == "" {
		return
	}

	stagedAt := d.taskQueue.GetStagedAt(headTaskID)
	if stagedAt == "" {
		return
	}

	stagedTime, err := tasksubmit.ParseTime(stagedAt)
	if err != nil {
		return
	}

	if time.Since(stagedTime) > tasksubmit.TaskQueueHeadTimeout {
		slog.Info("tasksubmit: expiring task due to queue head timeout",
			"task_id", headTaskID,
			"staged_at", stagedAt,
		)
		// Remove from queue
		d.taskQueue.Remove(headTaskID)
		// Expire on both sides and decrement receiver's polo score
		if err := ExpireTaskBothSides(headTaskID, stagedAt, d.regConn, d.nodeID); err != nil {
			slog.Warn("tasksubmit: failed to expire task", "task_id", headTaskID, "error", err)
		}
	}
}

func (d *Daemon) handleTaskSubmitConn(conn *Connection) {
	adapter := newConnAdapter(d, conn)
	defer adapter.Close()

	// Read frame
	frame, err := tasksubmit.ReadFrame(adapter)
	if err != nil {
		slog.Warn("tasksubmit: failed to read frame", "error", err)
		return
	}

	switch frame.Type {
	case tasksubmit.TypeSubmit:
		d.handleTaskSubmitRequest(adapter, conn, frame)
	case tasksubmit.TypeStatusUpdate:
		d.handleTaskStatusUpdate(adapter, conn, frame)
	case tasksubmit.TypeSendResults:
		d.handleTaskResults(adapter, conn, frame)
	default:
		slog.Warn("tasksubmit: unexpected frame type", "type", frame.Type)
	}
}

func (d *Daemon) handleTaskSubmitRequest(adapter *connAdapter, conn *Connection, frame *tasksubmit.Frame) {
	req, err := tasksubmit.UnmarshalSubmitRequest(frame)
	if err != nil {
		slog.Warn("tasksubmit: failed to unmarshal request", "error", err)
		return
	}

	// Issue #198: reject oversized task_description before we allocate,
	// persist, or chain the polo-score lookup. Bounded allocation is a
	// prerequisite for any remote-controlled submit path.
	if err := tasksubmit.ValidateSubmitRequest(req); err != nil {
		slog.Warn("tasksubmit: rejecting oversized submit", "task_id", req.TaskID, "error", err)
		resp := &tasksubmit.SubmitResponse{
			TaskID:  req.TaskID,
			Status:  tasksubmit.StatusRejected,
			Message: err.Error(),
		}
		if respFrame, merr := tasksubmit.MarshalSubmitResponse(resp); merr == nil {
			_ = tasksubmit.WriteFrame(adapter, respFrame)
		}
		return
	}

	slog.Debug("tasksubmit: received task submission",
		"task_id", req.TaskID,
		"description", req.TaskDescription,
		"from", req.FromAddr,
		"remote_node", conn.RemoteAddr.Node,
	)

	// Polo gate: receiver asks the registry whether the submitter is
	// authorized. Polo is private — daemons cannot read other nodes'
	// scores. The registry compares internally (or against an optional
	// per-receiver guarantee floor) and returns only allow/deny.
	var accepted bool
	var message string

	if d.regConn != nil {
		minPolo := d.config.PoloGateMin
		ok, reason, err := d.regConn.AuthorizeTaskSubmit(d.nodeID, conn.RemoteAddr.Node, d.nodeID, minPolo)
		if err != nil {
			slog.Warn("tasksubmit: registry authorize failed", "error", err)
			accepted = false
			message = "Failed to authorize task"
		} else if !ok {
			accepted = false
			message = "Task rejected by polo gate: " + reason
		} else {
			accepted = true
			message = "Task received with status NEW"
		}
	} else {
		// No registry connection — fail closed (cannot evaluate gate)
		accepted = false
		message = "Registry unavailable, cannot verify polo gate"
	}

	var resp *tasksubmit.SubmitResponse
	if accepted {
		// Create task file for receiver (received/)
		localAddrStr := ""
		if info := d.Info(); info != nil {
			localAddrStr = info.Address
		}

		tf := tasksubmit.NewTaskFile(req.TaskID, req.TaskDescription, req.FromAddr, localAddrStr)
		if err := SaveTaskFile(tf, false); err != nil {
			slog.Warn("tasksubmit: failed to save task file", "error", err)
		}

		// Add task to the execution queue
		d.taskQueue.Add(req.TaskID)

		resp = &tasksubmit.SubmitResponse{
			TaskID:  req.TaskID,
			Status:  tasksubmit.StatusAccepted,
			Message: message,
		}

		slog.Info("tasksubmit: task received",
			"task_id", req.TaskID,
			"description", req.TaskDescription,
			"submitter_node", conn.RemoteAddr.Node,
		)
		d.webhook.Emit("task.submitted", map[string]interface{}{
			"task_id":        req.TaskID,
			"description":    req.TaskDescription,
			"from":           req.FromAddr,
			"submitter_node": conn.RemoteAddr.Node,
		})
	} else {
		resp = &tasksubmit.SubmitResponse{
			TaskID:  req.TaskID,
			Status:  tasksubmit.StatusRejected,
			Message: message,
		}
	}

	// Send response
	respFrame, err := tasksubmit.MarshalSubmitResponse(resp)
	if err != nil {
		slog.Warn("tasksubmit: failed to marshal response", "error", err)
		return
	}

	if err := tasksubmit.WriteFrame(adapter, respFrame); err != nil {
		slog.Warn("tasksubmit: failed to write response", "error", err)
		return
	}
}

func (d *Daemon) handleTaskStatusUpdate(adapter *connAdapter, conn *Connection, frame *tasksubmit.Frame) {
	update, err := tasksubmit.UnmarshalTaskStatusUpdate(frame)
	if err != nil {
		slog.Warn("tasksubmit: failed to unmarshal status update", "error", err)
		return
	}

	slog.Debug("tasksubmit: received status update",
		"task_id", update.TaskID,
		"status", update.Status,
		"justification", update.Justification,
	)

	// Update local task file (in submitted/ directory since this is sent to the submitter)
	if err := UpdateTaskStatus(update.TaskID, update.Status, update.Justification, true); err != nil {
		slog.Warn("tasksubmit: failed to update task status", "task_id", update.TaskID, "error", err)
	}

	// Stamp AcceptedAt on the submitter's copy so the stall-detector
	// (IsAcceptedStalled) has a reliable clock reference. Receiver-side
	// AcceptedAt isn't transmitted with the status update.
	if update.Status == tasksubmit.TaskStatusAccepted {
		tasksDir, err := getTasksDir()
		if err == nil {
			taskPath := filepath.Join(tasksDir, "submitted", update.TaskID+".json")
			if data, rerr := os.ReadFile(taskPath); rerr == nil {
				if tf, perr := tasksubmit.UnmarshalTaskFile(data); perr == nil {
					if tf.AcceptedAt == "" {
						tf.AcceptedAt = time.Now().UTC().Format(time.RFC3339)
						if newData, merr := tasksubmit.MarshalTaskFile(tf); merr == nil {
							_ = os.WriteFile(taskPath, newData, 0600)
						}
					}
				}
			}
		}
	}

	slog.Info("tasksubmit: task status updated",
		"task_id", update.TaskID,
		"status", update.Status,
	)
}

func (d *Daemon) handleTaskResults(adapter *connAdapter, conn *Connection, frame *tasksubmit.Frame) {
	msg, err := tasksubmit.UnmarshalTaskResultMessage(frame)
	if err != nil {
		slog.Warn("tasksubmit: failed to unmarshal results", "error", err)
		return
	}

	// Issue #198: reject oversized result payloads before touching the
	// filesystem. Caller gets a decline so its task moves out of ACCEPTED.
	if err := tasksubmit.ValidateTaskResultMessage(msg); err != nil {
		slog.Warn("tasksubmit: rejecting oversized result", "task_id", msg.TaskID, "error", err)
		return
	}

	slog.Debug("tasksubmit: received task results",
		"task_id", msg.TaskID,
		"result_type", msg.ResultType,
	)

	// Save results
	tasksDir, err := getTasksDir()
	if err != nil {
		slog.Warn("tasksubmit: failed to get tasks dir", "error", err)
		return
	}

	resultsDir := filepath.Join(tasksDir, "results")
	if err := os.MkdirAll(resultsDir, 0700); err != nil {
		slog.Warn("tasksubmit: failed to create results dir", "error", err)
		return
	}

	if msg.ResultType == "file" && len(msg.FileData) > 0 {
		// Save file
		filename := filepath.Join(resultsDir, msg.TaskID+"_"+msg.Filename)
		if err := os.WriteFile(filename, msg.FileData, 0600); err != nil {
			slog.Warn("tasksubmit: failed to save result file", "error", err)
			return
		}
		slog.Info("tasksubmit: result file saved", "task_id", msg.TaskID, "filename", filename)
	} else {
		// Save text results
		filename := filepath.Join(resultsDir, msg.TaskID+"_result.txt")
		if err := os.WriteFile(filename, []byte(msg.ResultText), 0600); err != nil {
			slog.Warn("tasksubmit: failed to save result text", "error", err)
			return
		}
		slog.Info("tasksubmit: result text saved", "task_id", msg.TaskID, "filename", filename)
	}

	// Receipt of a result message is the success terminal — go straight to
	// SUCCEEDED so callers don't see an intermediate COMPLETED state that
	// then races with the explicit SendStatusUpdate from the receiver.
	if err := UpdateTaskStatus(msg.TaskID, tasksubmit.TaskStatusSucceeded, "Task completed with results", true); err != nil {
		slog.Warn("tasksubmit: failed to update task status", "task_id", msg.TaskID, "error", err)
	} else {
		// Read the just-updated task file, attach result fields, write back.
		taskPath := filepath.Join(tasksDir, "submitted", msg.TaskID+".json")
		if data, rerr := os.ReadFile(taskPath); rerr == nil {
			if tf, perr := tasksubmit.UnmarshalTaskFile(data); perr == nil {
				tf.ResultType = msg.ResultType
				if msg.ResultType == "file" {
					tf.Results = msg.Filename
				} else {
					tf.Results = msg.ResultText
				}
				if newData, merr := tasksubmit.MarshalTaskFile(tf); merr == nil {
					_ = os.WriteFile(taskPath, newData, 0600)
				}
			}
		}
	}
	d.webhook.Emit("task.completed", map[string]interface{}{
		"task_id":     msg.TaskID,
		"result_type": msg.ResultType,
	})

	// Update polo scores using weighted calculation
	if d.regConn != nil {
		// Load task to get addresses
		tf, err := LoadSubmittedTaskFile(msg.TaskID)
		if err != nil {
			slog.Warn("tasksubmit: failed to load task for polo update", "error", err)
			return
		}

		// Update task file with time metadata from the result message
		tf.TimeIdleMs = msg.TimeIdleMs
		tf.TimeStagedMs = msg.TimeStagedMs
		tf.TimeCpuMs = msg.TimeCpuMs

		// Calculate the weighted polo score reward
		reward := tf.PoloScoreReward()
		breakdown := tf.PoloScoreRewardDetailed()

		slog.Info("tasksubmit: polo score calculation",
			"task_id", msg.TaskID,
			"time_idle_ms", msg.TimeIdleMs,
			"time_staged_ms", msg.TimeStagedMs,
			"time_cpu_ms", msg.TimeCpuMs,
			"cpu_minutes", breakdown.CpuMinutes,
			"base", breakdown.Base,
			"cpu_bonus", breakdown.CpuBonus,
			"idle_factor", breakdown.IdleFactor,
			"staged_factor", breakdown.StagedFactor,
			"efficiency", breakdown.EfficiencyMultiplier,
			"reward", reward,
		)

		// Parse addresses to get node IDs
		fromAddr, err := protocol.ParseAddr(tf.From)
		if err == nil {
			// Submitter (fromAddr) loses 1 polo score
			if _, err := d.regConn.UpdatePoloScore(fromAddr.Node, -1); err != nil {
				slog.Warn("tasksubmit: failed to update submitter polo score", "error", err)
			}
		}

		toAddr, err := protocol.ParseAddr(tf.To)
		if err == nil {
			// Receiver (toAddr) gains weighted polo score
			if reward > 0 {
				if _, err := d.regConn.UpdatePoloScore(toAddr.Node, reward); err != nil {
					slog.Warn("tasksubmit: failed to update receiver polo score", "error", err)
				}
			}
		}

		slog.Info("tasksubmit: polo scores updated", "task_id", msg.TaskID, "receiver_reward", reward)
		d.webhook.Emit("polo.updated", map[string]interface{}{
			"task_id":          msg.TaskID,
			"submitter_delta":  -1,
			"receiver_reward":  reward,
		})
	}
}
