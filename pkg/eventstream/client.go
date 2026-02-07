package eventstream

import (
	"web4/pkg/driver"
	"web4/pkg/protocol"
)

// Client connects to a remote event stream broker on port 1002.
type Client struct {
	conn  *driver.Conn
	topic string
}

// Subscribe connects to the event stream and subscribes to a topic.
// Use "*" to subscribe to all events.
func Subscribe(d *driver.Driver, addr protocol.Addr, topic string) (*Client, error) {
	conn, err := d.DialAddr(addr, protocol.PortEventStream)
	if err != nil {
		return nil, err
	}

	// Send subscription event
	if err := WriteEvent(conn, &Event{Topic: topic}); err != nil {
		conn.Close()
		return nil, err
	}

	return &Client{conn: conn, topic: topic}, nil
}

// Publish sends an event to the broker for distribution.
func (c *Client) Publish(topic string, payload []byte) error {
	return WriteEvent(c.conn, &Event{Topic: topic, Payload: payload})
}

// Recv waits for the next event from the broker.
func (c *Client) Recv() (*Event, error) {
	return ReadEvent(c.conn)
}

// Close closes the connection.
func (c *Client) Close() error {
	return c.conn.Close()
}
