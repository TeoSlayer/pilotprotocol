package tasksubmit

import (
	"web4/pkg/driver"
	"web4/pkg/protocol"
)

// Client connects to a remote task submission service on port 1003.
type Client struct {
	conn *driver.Conn
}

// Dial connects to a remote agent's task submission port.
func Dial(d *driver.Driver, addr protocol.Addr) (*Client, error) {
	conn, err := d.DialAddr(addr, protocol.PortTaskSubmit)
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn}, nil
}

// SubmitTask sends a task submission request and waits for a response.
func (c *Client) SubmitTask(taskDescription string) (*SubmitResponse, error) {
	req := &SubmitRequest{
		TaskDescription: taskDescription,
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
