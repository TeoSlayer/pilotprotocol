package daemon

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"web4/pkg/dataexchange"
	"web4/pkg/eventstream"
	"web4/pkg/protocol"
	"web4/pkg/tasksubmit"
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

// TaskQueue manages pending task submissions.
type TaskQueue struct {
	mu    sync.Mutex
	tasks []QueuedTask
}

// QueuedTask represents a task in the queue.
type QueuedTask struct {
	Description string
	SubmitterID uint32
	SubmittedAt time.Time
}

// NewTaskQueue creates a new task queue.
func NewTaskQueue() *TaskQueue {
	return &TaskQueue{
		tasks: make([]QueuedTask, 0),
	}
}

// Add adds a task to the queue.
func (q *TaskQueue) Add(description string, submitterID uint32) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.tasks = append(q.tasks, QueuedTask{
		Description: description,
		SubmitterID: submitterID,
		SubmittedAt: time.Now(),
	})
}

// Pop removes and returns the next task from the queue, or nil if empty.
func (q *TaskQueue) Pop() *QueuedTask {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.tasks) == 0 {
		return nil
	}
	task := q.tasks[0]
	q.tasks = q.tasks[1:]
	return &task
}

// Len returns the number of tasks in the queue.
func (q *TaskQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.tasks)
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
	slog.Info("tasksubmit service listening", "port", protocol.PortTaskSubmit)
	return nil
}

func (d *Daemon) handleTaskSubmitConn(conn *Connection) {
	adapter := newConnAdapter(d, conn)
	defer adapter.Close()

	// Read task submission request
	frame, err := tasksubmit.ReadFrame(adapter)
	if err != nil {
		slog.Warn("tasksubmit: failed to read frame", "error", err)
		return
	}

	if frame.Type != tasksubmit.TypeSubmit {
		slog.Warn("tasksubmit: unexpected frame type", "type", frame.Type)
		return
	}

	req, err := tasksubmit.UnmarshalSubmitRequest(frame)
	if err != nil {
		slog.Warn("tasksubmit: failed to unmarshal request", "error", err)
		return
	}

	slog.Debug("tasksubmit: received task",
		"description", req.TaskDescription,
		"remote", conn.RemoteAddr,
		"remote_node", conn.RemoteAddr.Node,
	)

	// For now, auto-accept all tasks (can be extended with policy later)
	accepted := true

	var resp *tasksubmit.SubmitResponse
	if accepted {
		// Add to queue
		d.taskQueue.Add(req.TaskDescription, conn.RemoteAddr.Node)

		resp = &tasksubmit.SubmitResponse{
			Status:  tasksubmit.StatusAccepted,
			Message: "Task accepted and queued",
		}

		slog.Info("tasksubmit: task accepted",
			"description", req.TaskDescription,
			"submitter_node", conn.RemoteAddr.Node,
			"queue_length", d.taskQueue.Len(),
		)

		// Process task asynchronously
		go d.processNextTask()
	} else {
		resp = &tasksubmit.SubmitResponse{
			Status:  tasksubmit.StatusRejected,
			Message: "Task rejected",
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

	slog.Info("tasksubmit: response sent",
		"status", resp.Status,
		"accepted", accepted,
		"remote_node", conn.RemoteAddr.Node,
	)
}

// processNextTask processes the next task in the queue.
func (d *Daemon) processNextTask() {
	task := d.taskQueue.Pop()
	if task == nil {
		return
	}

	slog.Info("tasksubmit: processing task",
		"description", task.Description,
		"submitter_node", task.SubmitterID,
	)

	// Update karma scores: receiver +1, submitter -1
	d.updateKarmaScores(d.nodeID, task.SubmitterID)

	// Simulate task execution (mock for now)
	result := &tasksubmit.TaskResult{
		TaskDescription: task.Description,
		Status:          "success",
		Result:          "Mock task completed successfully",
		Timestamp:       time.Now().Format(time.RFC3339),
	}

	// Send result back to submitter via data exchange
	d.sendTaskResult(task.SubmitterID, result)

	slog.Info("tasksubmit: task completed",
		"description", task.Description,
		"submitter_node", task.SubmitterID,
	)
}

// updateKarmaScores updates karma scores for task processing.
func (d *Daemon) updateKarmaScores(receiverNode, submitterNode uint32) {
	if d.regConn == nil {
		slog.Warn("tasksubmit: cannot update karma, no registry connection")
		return
	}

	// Receiver gets +1 karma
	if _, err := d.regConn.UpdateKarma(receiverNode, 1); err != nil {
		slog.Warn("tasksubmit: failed to update receiver karma",
			"node_id", receiverNode,
			"error", err,
		)
	} else {
		slog.Info("tasksubmit: karma updated",
			"node_id", receiverNode,
			"delta", 1,
		)
	}

	// Submitter gets -1 karma
	if _, err := d.regConn.UpdateKarma(submitterNode, -1); err != nil {
		slog.Warn("tasksubmit: failed to update submitter karma",
			"node_id", submitterNode,
			"error", err,
		)
	} else {
		slog.Info("tasksubmit: karma updated",
			"node_id", submitterNode,
			"delta", -1,
		)
	}
}

// sendTaskResult sends the task result back to the submitter via data exchange.
func (d *Daemon) sendTaskResult(submitterNode uint32, result *tasksubmit.TaskResult) {
	// Convert node ID to address
	addr := protocol.Addr{
		Network: 0, // backbone
		Node:    submitterNode,
	}

	// Marshal result to JSON
	resultJSON, err := json.Marshal(result)
	if err != nil {
		slog.Warn("tasksubmit: failed to marshal result", "error", err)
		return
	}

	// Connect to submitter's data exchange port
	conn, err := d.DialConnection(addr, protocol.PortDataExchange)
	if err != nil {
		slog.Warn("tasksubmit: failed to connect to submitter for result delivery",
			"submitter_node", submitterNode,
			"error", err,
		)
		return
	}
	defer d.CloseConnection(conn)

	// Create adapter
	adapter := newConnAdapter(d, conn)
	defer adapter.Close()

	// Send as JSON message
	frame := &dataexchange.Frame{
		Type:    dataexchange.TypeJSON,
		Payload: resultJSON,
	}

	if err := dataexchange.WriteFrame(adapter, frame); err != nil {
		slog.Warn("tasksubmit: failed to send result",
			"submitter_node", submitterNode,
			"error", err,
		)
		return
	}

	// Read ACK
	ackFrame, err := dataexchange.ReadFrame(adapter)
	if err != nil {
		slog.Warn("tasksubmit: failed to read ACK", "error", err)
		return
	}

	slog.Info("tasksubmit: result sent",
		"submitter_node", submitterNode,
		"ack", string(ackFrame.Payload),
	)
}
