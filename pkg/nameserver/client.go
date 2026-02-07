package nameserver

import (
	"fmt"

	"web4/pkg/driver"
	"web4/pkg/protocol"
)

// Client queries a Pilot Protocol nameserver over the overlay.
type Client struct {
	driver     *driver.Driver
	serverAddr protocol.Addr
}

// NewClient creates a nameserver client that will query the given nameserver address.
func NewClient(d *driver.Driver, nsAddr protocol.Addr) *Client {
	return &Client{driver: d, serverAddr: nsAddr}
}

// LookupA resolves a name to a virtual address.
func (c *Client) LookupA(name string) (protocol.Addr, error) {
	resp, err := c.send(FormatRequest(Request{Command: "QUERY", RecordType: "A", Name: name}))
	if err != nil {
		return protocol.AddrZero, err
	}
	parsed, err := ParseResponse(resp)
	if err != nil {
		return protocol.AddrZero, err
	}
	if parsed.Type == "ERR" {
		return protocol.AddrZero, fmt.Errorf("nameserver: %s", parsed.Error)
	}
	return protocol.ParseAddr(parsed.Address)
}

// LookupN resolves a network name to a network ID.
func (c *Client) LookupN(name string) (uint16, error) {
	resp, err := c.send(FormatRequest(Request{Command: "QUERY", RecordType: "N", Name: name}))
	if err != nil {
		return 0, err
	}
	parsed, err := ParseResponse(resp)
	if err != nil {
		return 0, err
	}
	if parsed.Type == "ERR" {
		return 0, fmt.Errorf("nameserver: %s", parsed.Error)
	}
	return parsed.NetID, nil
}

// LookupS finds services on a network+port.
func (c *Client) LookupS(networkID, port uint16) ([]ServiceEntry, error) {
	resp, err := c.send(FormatRequest(Request{Command: "QUERY", RecordType: "S", NetID: networkID, Port: port}))
	if err != nil {
		return nil, err
	}
	parsed, err := ParseResponse(resp)
	if err != nil {
		return nil, err
	}
	if parsed.Type == "ERR" {
		return nil, fmt.Errorf("nameserver: %s", parsed.Error)
	}
	return parsed.Services, nil
}

// RegisterA registers a name → address mapping.
func (c *Client) RegisterA(name string, addr protocol.Addr) error {
	resp, err := c.send(FormatRequest(Request{Command: "REGISTER", RecordType: "A", Name: name, Address: addr.String()}))
	if err != nil {
		return err
	}
	parsed, err := ParseResponse(resp)
	if err != nil {
		return err
	}
	if parsed.Type == "ERR" {
		return fmt.Errorf("nameserver: %s", parsed.Error)
	}
	return nil
}

// RegisterN registers a network name → network ID mapping.
func (c *Client) RegisterN(name string, netID uint16) error {
	resp, err := c.send(FormatRequest(Request{Command: "REGISTER", RecordType: "N", Name: name, NetID: netID}))
	if err != nil {
		return err
	}
	parsed, err := ParseResponse(resp)
	if err != nil {
		return err
	}
	if parsed.Type == "ERR" {
		return fmt.Errorf("nameserver: %s", parsed.Error)
	}
	return nil
}

// RegisterS registers a service.
func (c *Client) RegisterS(name string, addr protocol.Addr, networkID, port uint16) error {
	resp, err := c.send(FormatRequest(Request{Command: "REGISTER", RecordType: "S", Name: name, Address: addr.String(), NetID: networkID, Port: port}))
	if err != nil {
		return err
	}
	parsed, err := ParseResponse(resp)
	if err != nil {
		return err
	}
	if parsed.Type == "ERR" {
		return fmt.Errorf("nameserver: %s", parsed.Error)
	}
	return nil
}

func (c *Client) send(msg string) (string, error) {
	conn, err := c.driver.DialAddr(c.serverAddr, protocol.PortNameserver)
	if err != nil {
		return "", fmt.Errorf("dial nameserver: %w", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte(msg)); err != nil {
		return "", fmt.Errorf("write: %w", err)
	}

	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return "", fmt.Errorf("read: %w", err)
	}

	return string(buf[:n]), nil
}
