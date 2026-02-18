package tasksubmit

import (
	"github.com/TeoSlayer/pilotprotocol/pkg/driver"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// Client connects to a remote task submission service on port 1003.
type Client struct {
	conn      *driver.Conn
	localAddr string
}

// Dial connects to a remote agent's task submission port.
func Dial(d *driver.Driver, addr protocol.Addr) (*Client, error) {
	conn, err := d.DialAddr(addr, protocol.PortTaskSubmit)
	if err != nil {
		return nil, err
	}
	// Get local address from driver
	info, _ := d.Info()
	localAddr := ""
	if addrStr, ok := info["address"].(string); ok {
		localAddr = addrStr
	}
	return &Client{conn: conn, localAddr: localAddr}, nil
}

// SubmitTask sends a task submission request and waits for a response.
// Returns the task_id assigned to this task.
func (c *Client) SubmitTask(taskDescription string, targetAddr string) (*SubmitResponse, error) {
	taskID := GenerateTaskID()
	req := &SubmitRequest{
		TaskID:          taskID,
		TaskDescription: taskDescription,
		FromAddr:        c.localAddr,
		ToAddr:          targetAddr,
	}
	frame, err := MarshalSubmitRequest(req)
	if err != nil {
		return nil, err
	}
	if err := WriteFrame(c.conn, frame); err != nil {
		return nil, err
	}

	// Wait for response
	respFrame, err := ReadFrame(c.conn)
	if err != nil {
		return nil, err
	}

	return UnmarshalSubmitResponse(respFrame)
}

// SendStatusUpdate sends a task status update to the remote agent.
func (c *Client) SendStatusUpdate(taskID, status, justification string) error {
	update := &TaskStatusUpdate{
		TaskID:        taskID,
		Status:        status,
		Justification: justification,
	}
	frame, err := MarshalTaskStatusUpdate(update)
	if err != nil {
		return err
	}
	return WriteFrame(c.conn, frame)
}

// SendResults sends task results to the remote agent.
func (c *Client) SendResults(msg *TaskResultMessage) error {
	frame, err := MarshalTaskResultMessage(msg)
	if err != nil {
		return err
	}
	return WriteFrame(c.conn, frame)
}

// RecvResult reads a task result from the connection.
func (c *Client) RecvResult() (*TaskResult, error) {
	frame, err := ReadFrame(c.conn)
	if err != nil {
		return nil, err
	}
	return UnmarshalTaskResult(frame)
}

// Close closes the connection.
func (c *Client) Close() error {
	return c.conn.Close()
}
