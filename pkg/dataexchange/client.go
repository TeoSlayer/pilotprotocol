package dataexchange

import (
	"github.com/TeoSlayer/pilotprotocol/pkg/driver"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// Client connects to a remote data exchange service on port 1001.
type Client struct {
	conn *driver.Conn
}

// Dial connects to a remote agent's data exchange port.
func Dial(d *driver.Driver, addr protocol.Addr) (*Client, error) {
	conn, err := d.DialAddr(addr, protocol.PortDataExchange)
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn}, nil
}

// SendText sends a text frame.
func (c *Client) SendText(text string) error {
	return WriteFrame(c.conn, &Frame{Type: TypeText, Payload: []byte(text)})
}

// SendJSON sends a JSON frame.
func (c *Client) SendJSON(data []byte) error {
	return WriteFrame(c.conn, &Frame{Type: TypeJSON, Payload: data})
}

// SendBinary sends a binary frame.
func (c *Client) SendBinary(data []byte) error {
	return WriteFrame(c.conn, &Frame{Type: TypeBinary, Payload: data})
}

// SendFile sends a file frame with a filename and data.
func (c *Client) SendFile(name string, data []byte) error {
	return WriteFrame(c.conn, &Frame{Type: TypeFile, Filename: name, Payload: data})
}

// Recv reads the next frame from the connection.
func (c *Client) Recv() (*Frame, error) {
	return ReadFrame(c.conn)
}

// Close closes the connection.
func (c *Client) Close() error {
	return c.conn.Close()
}
