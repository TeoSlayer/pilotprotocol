package driver

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

const DefaultSocketPath = "/tmp/pilot.sock"

// Handshake sub-commands (must match daemon SubHandshake* constants)
const (
	subHandshakeSend    byte = 0x01
	subHandshakeApprove byte = 0x02
	subHandshakeReject  byte = 0x03
	subHandshakePending byte = 0x04
	subHandshakeTrusted byte = 0x05
	subHandshakeRevoke  byte = 0x06
)

// jsonRPC sends an IPC message, waits for the expected response, and
// unmarshals the JSON payload. Most driver methods follow this pattern.
func (d *Driver) jsonRPC(msg []byte, expectCmd byte, label string) (map[string]interface{}, error) {
	resp, err := d.ipc.sendAndWait(msg, expectCmd)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("%s unmarshal: %w", label, err)
	}
	return result, nil
}

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
	return d.jsonRPC([]byte{cmdInfo}, cmdInfoOK, "info")
}

// Handshake sends a trust handshake request to a remote node.
func (d *Driver) Handshake(nodeID uint32, justification string) (map[string]interface{}, error) {
	msg := make([]byte, 1+1+4+len(justification))
	msg[0] = cmdHandshake
	msg[1] = subHandshakeSend
	binary.BigEndian.PutUint32(msg[2:6], nodeID)
	copy(msg[6:], justification)
	return d.jsonRPC(msg, cmdHandshakeOK, "handshake")
}

// ApproveHandshake approves a pending trust handshake request.
func (d *Driver) ApproveHandshake(nodeID uint32) (map[string]interface{}, error) {
	msg := make([]byte, 6)
	msg[0] = cmdHandshake
	msg[1] = subHandshakeApprove
	binary.BigEndian.PutUint32(msg[2:6], nodeID)
	return d.jsonRPC(msg, cmdHandshakeOK, "approve")
}

// RejectHandshake rejects a pending trust handshake request.
func (d *Driver) RejectHandshake(nodeID uint32, reason string) (map[string]interface{}, error) {
	msg := make([]byte, 1+1+4+len(reason))
	msg[0] = cmdHandshake
	msg[1] = subHandshakeReject
	binary.BigEndian.PutUint32(msg[2:6], nodeID)
	copy(msg[6:], reason)
	return d.jsonRPC(msg, cmdHandshakeOK, "reject")
}

// PendingHandshakes returns pending trust handshake requests.
func (d *Driver) PendingHandshakes() (map[string]interface{}, error) {
	return d.jsonRPC([]byte{cmdHandshake, subHandshakePending}, cmdHandshakeOK, "pending")
}

// TrustedPeers returns all trusted peers from the handshake protocol.
func (d *Driver) TrustedPeers() (map[string]interface{}, error) {
	return d.jsonRPC([]byte{cmdHandshake, subHandshakeTrusted}, cmdHandshakeOK, "trusted")
}

// RevokeTrust removes a peer from the trusted set and notifies the registry.
func (d *Driver) RevokeTrust(nodeID uint32) (map[string]interface{}, error) {
	msg := make([]byte, 6)
	msg[0] = cmdHandshake
	msg[1] = subHandshakeRevoke
	binary.BigEndian.PutUint32(msg[2:6], nodeID)
	return d.jsonRPC(msg, cmdHandshakeOK, "revoke")
}

// ResolveHostname resolves a hostname to node info via the daemon.
func (d *Driver) ResolveHostname(hostname string) (map[string]interface{}, error) {
	msg := make([]byte, 1+len(hostname))
	msg[0] = cmdResolveHostname
	copy(msg[1:], hostname)
	return d.jsonRPC(msg, cmdResolveHostnameOK, "resolve_hostname")
}

// SetHostname sets or clears the daemon's hostname via the registry.
func (d *Driver) SetHostname(hostname string) (map[string]interface{}, error) {
	msg := make([]byte, 1+len(hostname))
	msg[0] = cmdSetHostname
	copy(msg[1:], hostname)
	return d.jsonRPC(msg, cmdSetHostnameOK, "set_hostname")
}

// SetVisibility sets the daemon's visibility on the registry.
func (d *Driver) SetVisibility(public bool) (map[string]interface{}, error) {
	msg := make([]byte, 2)
	msg[0] = cmdSetVisibility
	if public {
		msg[1] = 1
	}
	return d.jsonRPC(msg, cmdSetVisibilityOK, "set_visibility")
}

// SetTaskExec enables or disables task execution capability on the registry.
func (d *Driver) SetTaskExec(enabled bool) (map[string]interface{}, error) {
	msg := make([]byte, 2)
	msg[0] = cmdSetTaskExec
	if enabled {
		msg[1] = 1
	}
	return d.jsonRPC(msg, cmdSetTaskExecOK, "set_task_exec")
}

// Deregister removes the daemon from the registry.
func (d *Driver) Deregister() (map[string]interface{}, error) {
	return d.jsonRPC([]byte{cmdDeregister}, cmdDeregisterOK, "deregister")
}

// SetTags sets the capability tags for this daemon's node.
func (d *Driver) SetTags(tags []string) (map[string]interface{}, error) {
	data, _ := json.Marshal(tags)
	msg := make([]byte, 1+len(data))
	msg[0] = cmdSetTags
	copy(msg[1:], data)
	return d.jsonRPC(msg, cmdSetTagsOK, "set_tags")
}

// SetWebhook sets or clears the daemon's webhook URL at runtime.
// An empty URL disables the webhook.
func (d *Driver) SetWebhook(url string) (map[string]interface{}, error) {
	msg := make([]byte, 1+len(url))
	msg[0] = cmdSetWebhook
	copy(msg[1:], url)
	return d.jsonRPC(msg, cmdSetWebhookOK, "set_webhook")
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
