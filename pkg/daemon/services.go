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

	// Sanitize filename and add timestamp (with ms precision) to avoid overwrites
	safeName := filepath.Base(frame.Filename)
	ts := time.Now().Format("20060102-150405.000")
	ext := filepath.Ext(safeName)
	base := safeName[:len(safeName)-len(ext)]
	destName := fmt.Sprintf("%s-%s%s", base, ts, ext)
	destPath := filepath.Join(dir, destName)

	if err := os.WriteFile(destPath, frame.Payload, 0600); err != nil {
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
		"received_at": ts.Format(time.RFC3339),
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	filename := fmt.Sprintf("%s-%s.json", dataexchange.TypeName(frame.Type), ts.Format("20060102-150405.000"))
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
		subs:    make(map[string][]*connAdapter),
		webhook: d.webhook,
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

// eventBroker is an in-process pub/sub broker for the event stream service.
type eventBroker struct {
	mu      sync.RWMutex
	subs    map[string][]*connAdapter // topic → subscribers
	webhook *WebhookClient
}

func (b *eventBroker) handleConn(adapter *connAdapter) {
	var topic string
	defer func() {
		b.removeSub(adapter)
		adapter.Close()
		if topic != "" {
			b.webhook.Emit("pubsub.unsubscribed", map[string]interface{}{
				"topic": topic, "remote": adapter.RemoteAddr().String(),
			})
		}
	}()

	// First event = subscription
	subEvt, err := eventstream.ReadEvent(adapter)
	if err != nil {
		return
	}
	topic = subEvt.Topic
	b.addSub(topic, adapter)
	slog.Debug("eventstream subscription", "remote", adapter.RemoteAddr(), "topic", topic)
	b.webhook.Emit("pubsub.subscribed", map[string]interface{}{
		"topic": topic, "remote": adapter.RemoteAddr().String(),
	})

	// Remaining events = publish
	for {
		evt, err := eventstream.ReadEvent(adapter)
		if err != nil {
			return
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

func (b *eventBroker) publish(evt *eventstream.Event, sender *connAdapter) {
	b.mu.RLock()
	var dead []*connAdapter
	for _, conn := range b.subs[evt.Topic] {
		if conn != sender {
			if err := eventstream.WriteEvent(conn, evt); err != nil {
				slog.Debug("eventstream write failed, removing subscriber", "remote", conn.RemoteAddr(), "error", err)
				dead = append(dead, conn)
			}
		}
	}
	if evt.Topic != "*" {
		for _, conn := range b.subs["*"] {
			if conn != sender {
				if err := eventstream.WriteEvent(conn, evt); err != nil {
					slog.Debug("eventstream write failed, removing subscriber", "remote", conn.RemoteAddr(), "error", err)
					dead = append(dead, conn)
				}
			}
		}
	}
	b.mu.RUnlock()

	// Clean up dead subscribers outside the read lock
	for _, conn := range dead {
		b.removeSub(conn)
	}
	slog.Debug("eventstream published", "topic", evt.Topic, "bytes", len(evt.Payload), "from", sender.RemoteAddr())
	b.webhook.Emit("pubsub.published", map[string]interface{}{
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

// checkAndCancelExpiredNewTasks scans received tasks for NEW tasks past the accept timeout.
func (d *Daemon) checkAndCancelExpiredNewTasks() {
	tasksDir, err := getTasksDir()
	if err != nil {
		return
	}

	receivedDir := filepath.Join(tasksDir, "received")
	entries, err := os.ReadDir(receivedDir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(receivedDir, entry.Name()))
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
				"created_at", tf.CreatedAt,
			)
			// Remove from queue if present
			d.taskQueue.Remove(tf.TaskID)
			// Cancel on both sides
			if err := CancelTaskBothSides(tf.TaskID); err != nil {
				slog.Warn("tasksubmit: failed to cancel task", "task_id", tf.TaskID, "error", err)
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

	slog.Debug("tasksubmit: received task submission",
		"task_id", req.TaskID,
		"description", req.TaskDescription,
		"from", req.FromAddr,
		"remote_node", conn.RemoteAddr.Node,
	)

	// Check polo scores: submitter's score must be >= receiver's score
	var accepted bool
	var message string

	if d.regConn != nil {
		submitterScore, err := d.regConn.GetPoloScore(conn.RemoteAddr.Node)
		if err != nil {
			slog.Warn("tasksubmit: failed to get submitter polo score", "error", err)
			accepted = false
			message = "Failed to verify polo score"
		} else {
			receiverScore, err := d.regConn.GetPoloScore(d.nodeID)
			if err != nil {
				slog.Warn("tasksubmit: failed to get receiver polo score", "error", err)
				accepted = false
				message = "Failed to verify polo score"
			} else {
				if submitterScore >= receiverScore {
					accepted = true
					message = "Task received with status NEW"
				} else {
					accepted = false
					message = fmt.Sprintf("Polo score too low: submitter=%d, receiver=%d", submitterScore, receiverScore)
				}
			}
		}
	} else {
		// No registry connection, accept by default
		accepted = true
		message = "Task received with status NEW"
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

	// Update task status to COMPLETED
	if err := UpdateTaskStatus(msg.TaskID, tasksubmit.TaskStatusCompleted, "Task completed with results", true); err != nil {
		slog.Warn("tasksubmit: failed to update task status", "task_id", msg.TaskID, "error", err)
	}

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
	}
}

// updatePoloScores updates polo scores for task processing.
func (d *Daemon) updatePoloScores(receiverNode, submitterNode uint32) {
	if d.regConn == nil {
		slog.Warn("tasksubmit: cannot update polo score, no registry connection")
		return
	}

	// Receiver gets +1 polo score
	if _, err := d.regConn.UpdatePoloScore(receiverNode, 1); err != nil {
		slog.Warn("tasksubmit: failed to update receiver polo score",
			"node_id", receiverNode,
			"error", err,
		)
	} else {
		slog.Info("tasksubmit: polo score updated",
			"node_id", receiverNode,
			"delta", 1,
		)
	}

	// Submitter gets -1 polo score
	if _, err := d.regConn.UpdatePoloScore(submitterNode, -1); err != nil {
		slog.Warn("tasksubmit: failed to update submitter polo score",
			"node_id", submitterNode,
			"error", err,
		)
	} else {
		slog.Info("tasksubmit: polo score updated",
			"node_id", submitterNode,
			"delta", -1,
		)
	}
}
