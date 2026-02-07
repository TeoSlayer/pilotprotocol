package driver

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	"web4/pkg/protocol"
)

const DefaultSocketPath = "/tmp/pilot.sock"

// Driver is the main entry point for the Pilot Protocol SDK.
type Driver struct {
	ipc        *ipcClient
	socketPath string
}

// Connect creates a new driver connected to the local daemon.
func Connect(socketPath string) (*Driver, error) {
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}

	ipc, err := newIPCClient(socketPath)
	if err != nil {
		return nil, err
	}

	return &Driver{ipc: ipc, socketPath: socketPath}, nil
}

// Dial opens a stream connection to a remote address:port.
// addr format: "N:XXXX.YYYY.YYYY:PORT"
func (d *Driver) Dial(addr string) (*Conn, error) {
	sa, err := protocol.ParseSocketAddr(addr)
	if err != nil {
		return nil, fmt.Errorf("parse address: %w", err)
	}

	return d.DialAddr(sa.Addr, sa.Port)
}

// DialAddr opens a stream connection to a remote Addr + port.
func (d *Driver) DialAddr(dst protocol.Addr, port uint16) (*Conn, error) {
	msg := make([]byte, 1+protocol.AddrSize+2)
	msg[0] = cmdDial
	dst.MarshalTo(msg, 1)
	binary.BigEndian.PutUint16(msg[1+protocol.AddrSize:], port)

	resp, err := d.ipc.sendAndWait(msg, cmdDialOK)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	if len(resp) < 4 {
		return nil, fmt.Errorf("invalid dial response")
	}

	connID := binary.BigEndian.Uint32(resp[0:4])
	recvCh := d.ipc.registerRecvCh(connID)

	return &Conn{
		id:         connID,
		remoteAddr: protocol.SocketAddr{Addr: dst, Port: port},
		ipc:        d.ipc,
		recvCh:     recvCh,
		deadlineCh: make(chan struct{}),
	}, nil
}

// Listen binds a port and returns a Listener that accepts connections.
func (d *Driver) Listen(port uint16) (*Listener, error) {
	msg := make([]byte, 3)
	msg[0] = cmdBind
	binary.BigEndian.PutUint16(msg[1:3], port)

	resp, err := d.ipc.sendAndWait(msg, cmdBindOK)
	if err != nil {
		return nil, fmt.Errorf("bind: %w", err)
	}

	boundPort := binary.BigEndian.Uint16(resp[0:2])

	// H12 fix: register per-port accept channel
	acceptCh := d.ipc.registerAcceptCh(boundPort)

	return &Listener{
		port:     boundPort,
		ipc:      d.ipc,
		acceptCh: acceptCh,
		done:     make(chan struct{}),
	}, nil
}

// SendTo sends an unreliable datagram to the given address:port.
// Use with broadcast addresses (Node=0xFFFFFFFF) to send to all network members.
func (d *Driver) SendTo(dst protocol.Addr, port uint16, data []byte) error {
	msg := make([]byte, 1+protocol.AddrSize+2+len(data))
	msg[0] = cmdSendTo
	dst.MarshalTo(msg, 1)
	binary.BigEndian.PutUint16(msg[1+protocol.AddrSize:], port)
	copy(msg[1+protocol.AddrSize+2:], data)
	return d.ipc.send(msg)
}

// RecvFrom receives the next incoming datagram.
func (d *Driver) RecvFrom() (*Datagram, error) {
	dg, ok := <-d.ipc.dgCh
	if !ok {
		return nil, fmt.Errorf("driver closed")
	}
	return dg, nil
}

// Info returns the daemon's status information.
func (d *Driver) Info() (map[string]interface{}, error) {
	msg := []byte{cmdInfo}
	resp, err := d.ipc.sendAndWait(msg, cmdInfoOK)
	if err != nil {
		return nil, fmt.Errorf("info: %w", err)
	}
	var info map[string]interface{}
	if err := json.Unmarshal(resp, &info); err != nil {
		return nil, fmt.Errorf("info unmarshal: %w", err)
	}
	return info, nil
}

// Handshake sends a trust handshake request to a remote node.
func (d *Driver) Handshake(nodeID uint32, justification string) (map[string]interface{}, error) {
	payload := make([]byte, 1+4+len(justification))
	payload[0] = 0x01 // SendRequest sub-command
	binary.BigEndian.PutUint32(payload[1:5], nodeID)
	copy(payload[5:], justification)

	msg := make([]byte, 1+len(payload))
	msg[0] = cmdHandshake
	copy(msg[1:], payload)

	resp, err := d.ipc.sendAndWait(msg, cmdHandshakeOK)
	if err != nil {
		return nil, fmt.Errorf("handshake: %w", err)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("handshake unmarshal: %w", err)
	}
	return result, nil
}

// ApproveHandshake approves a pending trust handshake request.
func (d *Driver) ApproveHandshake(nodeID uint32) (map[string]interface{}, error) {
	msg := make([]byte, 1+1+4)
	msg[0] = cmdHandshake
	msg[1] = 0x02 // Approve sub-command
	binary.BigEndian.PutUint32(msg[2:6], nodeID)

	resp, err := d.ipc.sendAndWait(msg, cmdHandshakeOK)
	if err != nil {
		return nil, fmt.Errorf("approve: %w", err)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("approve unmarshal: %w", err)
	}
	return result, nil
}

// RejectHandshake rejects a pending trust handshake request.
func (d *Driver) RejectHandshake(nodeID uint32, reason string) (map[string]interface{}, error) {
	payload := make([]byte, 1+4+len(reason))
	payload[0] = 0x03 // Reject sub-command
	binary.BigEndian.PutUint32(payload[1:5], nodeID)
	copy(payload[5:], reason)

	msg := make([]byte, 1+len(payload))
	msg[0] = cmdHandshake
	copy(msg[1:], payload)

	resp, err := d.ipc.sendAndWait(msg, cmdHandshakeOK)
	if err != nil {
		return nil, fmt.Errorf("reject: %w", err)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("reject unmarshal: %w", err)
	}
	return result, nil
}

// PendingHandshakes returns pending trust handshake requests.
func (d *Driver) PendingHandshakes() (map[string]interface{}, error) {
	msg := []byte{cmdHandshake, 0x04}

	resp, err := d.ipc.sendAndWait(msg, cmdHandshakeOK)
	if err != nil {
		return nil, fmt.Errorf("pending: %w", err)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("pending unmarshal: %w", err)
	}
	return result, nil
}

// TrustedPeers returns all trusted peers from the handshake protocol.
func (d *Driver) TrustedPeers() (map[string]interface{}, error) {
	msg := []byte{cmdHandshake, 0x05}

	resp, err := d.ipc.sendAndWait(msg, cmdHandshakeOK)
	if err != nil {
		return nil, fmt.Errorf("trusted: %w", err)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("trusted unmarshal: %w", err)
	}
	return result, nil
}

// RevokeTrust removes a peer from the trusted set and notifies the registry.
func (d *Driver) RevokeTrust(nodeID uint32) (map[string]interface{}, error) {
	msg := make([]byte, 6)
	msg[0] = cmdHandshake
	msg[1] = 0x06 // SubHandshakeRevoke
	binary.BigEndian.PutUint32(msg[2:6], nodeID)

	resp, err := d.ipc.sendAndWait(msg, cmdHandshakeOK)
	if err != nil {
		return nil, fmt.Errorf("revoke: %w", err)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("revoke unmarshal: %w", err)
	}
	return result, nil
}

// ResolveHostname resolves a hostname to node info via the daemon.
func (d *Driver) ResolveHostname(hostname string) (map[string]interface{}, error) {
	msg := make([]byte, 1+len(hostname))
	msg[0] = cmdResolveHostname
	copy(msg[1:], hostname)

	resp, err := d.ipc.sendAndWait(msg, cmdResolveHostnameOK)
	if err != nil {
		return nil, fmt.Errorf("resolve_hostname: %w", err)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("resolve_hostname unmarshal: %w", err)
	}
	return result, nil
}

// SetHostname sets or clears the daemon's hostname via the registry.
func (d *Driver) SetHostname(hostname string) (map[string]interface{}, error) {
	msg := make([]byte, 1+len(hostname))
	msg[0] = cmdSetHostname
	copy(msg[1:], hostname)

	resp, err := d.ipc.sendAndWait(msg, cmdSetHostnameOK)
	if err != nil {
		return nil, fmt.Errorf("set_hostname: %w", err)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("set_hostname unmarshal: %w", err)
	}
	return result, nil
}

// SetVisibility sets the daemon's visibility on the registry.
func (d *Driver) SetVisibility(public bool) (map[string]interface{}, error) {
	msg := make([]byte, 2)
	msg[0] = cmdSetVisibility
	if public {
		msg[1] = 1
	}

	resp, err := d.ipc.sendAndWait(msg, cmdSetVisibilityOK)
	if err != nil {
		return nil, fmt.Errorf("set_visibility: %w", err)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("set_visibility unmarshal: %w", err)
	}
	return result, nil
}

// Deregister removes the daemon from the registry.
func (d *Driver) Deregister() (map[string]interface{}, error) {
	msg := []byte{cmdDeregister}

	resp, err := d.ipc.sendAndWait(msg, cmdDeregisterOK)
	if err != nil {
		return nil, fmt.Errorf("deregister: %w", err)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("deregister unmarshal: %w", err)
	}
	return result, nil
}

// Disconnect closes a connection by ID. Used by administrative tools.
func (d *Driver) Disconnect(connID uint32) error {
	msg := make([]byte, 5)
	msg[0] = cmdClose
	binary.BigEndian.PutUint32(msg[1:5], connID)
	_, err := d.ipc.sendAndWait(msg, cmdCloseOK)
	return err
}

// Close disconnects from the daemon.
func (d *Driver) Close() error {
	return d.ipc.close()
}
