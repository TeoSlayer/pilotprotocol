package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// BinaryClient talks to a registry server using the binary wire protocol.
// It provides native binary encoding for hot-path operations (heartbeat, lookup,
// resolve) and JSON-over-binary passthrough for all other operations.
type BinaryClient struct {
	conn   net.Conn
	mu     sync.Mutex
	addr   string
	closed bool
}

// DialBinary connects to a registry server and negotiates the binary wire protocol.
// The server detects the magic bytes and switches to binary mode for this connection.
func DialBinary(addr string) (*BinaryClient, error) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial registry: %w", err)
	}

	// Send magic + version to negotiate binary protocol
	var handshake [5]byte
	copy(handshake[:4], wireMagic[:])
	handshake[4] = wireVersion
	if _, err := conn.Write(handshake[:]); err != nil {
		conn.Close()
		return nil, fmt.Errorf("binary handshake: %w", err)
	}

	return &BinaryClient{conn: conn, addr: addr}, nil
}

// Close shuts down the binary client connection.
func (c *BinaryClient) Close() error {
	c.mu.Lock()
	c.closed = true
	conn := c.conn
	c.mu.Unlock()
	if conn != nil {
		return conn.Close()
	}
	return nil
}

// Addr returns the registry address this client is connected to.
func (c *BinaryClient) Addr() string {
	return c.addr
}

// reconnect re-establishes the binary connection. Must be called with c.mu held.
func (c *BinaryClient) reconnect() error {
	if c.closed {
		return fmt.Errorf("client closed")
	}
	if c.conn != nil {
		c.conn.Close()
	}

	backoff := 500 * time.Millisecond
	maxBackoff := 10 * time.Second
	var lastErr error

	for attempts := 0; attempts < 5; attempts++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", c.addr)
		cancel()
		if err != nil {
			lastErr = err
			slog.Warn("binary client reconnect failed", "attempt", attempts+1, "err", err)
			time.Sleep(backoff)
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		// Re-negotiate binary protocol
		var handshake [5]byte
		copy(handshake[:4], wireMagic[:])
		handshake[4] = wireVersion
		if _, err := conn.Write(handshake[:]); err != nil {
			conn.Close()
			lastErr = err
			continue
		}

		c.conn = conn
		slog.Info("binary client reconnected", "addr", c.addr)
		return nil
	}
	return fmt.Errorf("reconnect failed after 5 attempts: %w", lastErr)
}

// Heartbeat sends a binary heartbeat and returns the server time and key expiry warning.
func (c *BinaryClient) Heartbeat(nodeID uint32, sig []byte) (unixTime int64, keyExpiryWarning bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	unixTime, keyExpiryWarning, err = c.heartbeatLocked(nodeID, sig)
	if err != nil && !c.closed {
		// Connection-level failure — reconnect and retry once
		if reconnErr := c.reconnect(); reconnErr != nil {
			return 0, false, fmt.Errorf("heartbeat failed and reconnect failed: %w", err)
		}
		unixTime, keyExpiryWarning, err = c.heartbeatLocked(nodeID, sig)
	}
	return
}

func (c *BinaryClient) heartbeatLocked(nodeID uint32, sig []byte) (int64, bool, error) {
	if err := wireWriteFrame(c.conn, wireMsgHeartbeat, encodeHeartbeatReq(nodeID, sig)); err != nil {
		return 0, false, fmt.Errorf("send heartbeat: %w", err)
	}

	msgType, payload, err := wireReadFrame(c.conn)
	if err != nil {
		return 0, false, fmt.Errorf("recv heartbeat: %w", err)
	}

	if msgType == wireMsgError {
		return 0, false, fmt.Errorf("registry: %s", decodeWireError(payload))
	}
	if msgType != wireMsgHeartbeatOK {
		return 0, false, fmt.Errorf("unexpected response type 0x%02x", msgType)
	}

	return decodeHeartbeatResp(payload)
}

// Lookup sends a binary lookup request and returns the decoded result.
func (c *BinaryClient) Lookup(nodeID uint32) (*WireLookupResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	result, err := c.lookupLocked(nodeID)
	if err != nil && !c.closed {
		if reconnErr := c.reconnect(); reconnErr != nil {
			return nil, fmt.Errorf("lookup failed and reconnect failed: %w", err)
		}
		result, err = c.lookupLocked(nodeID)
	}
	return result, err
}

func (c *BinaryClient) lookupLocked(nodeID uint32) (*WireLookupResult, error) {
	if err := wireWriteFrame(c.conn, wireMsgLookup, encodeLookupReq(nodeID)); err != nil {
		return nil, fmt.Errorf("send lookup: %w", err)
	}

	msgType, payload, err := wireReadFrame(c.conn)
	if err != nil {
		return nil, fmt.Errorf("recv lookup: %w", err)
	}

	if msgType == wireMsgError {
		return nil, fmt.Errorf("registry: %s", decodeWireError(payload))
	}
	if msgType != wireMsgLookupOK {
		return nil, fmt.Errorf("unexpected response type 0x%02x", msgType)
	}

	result, err := decodeLookupResp(payload)
	if err != nil {
		return nil, fmt.Errorf("decode lookup response: %w", err)
	}
	return &result, nil
}

// Resolve sends a binary resolve request and returns the decoded result.
func (c *BinaryClient) Resolve(nodeID, requesterID uint32, sig []byte) (*WireResolveResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	result, err := c.resolveLocked(nodeID, requesterID, sig)
	if err != nil && !c.closed {
		if reconnErr := c.reconnect(); reconnErr != nil {
			return nil, fmt.Errorf("resolve failed and reconnect failed: %w", err)
		}
		result, err = c.resolveLocked(nodeID, requesterID, sig)
	}
	return result, err
}

func (c *BinaryClient) resolveLocked(nodeID, requesterID uint32, sig []byte) (*WireResolveResult, error) {
	if err := wireWriteFrame(c.conn, wireMsgResolve, encodeResolveReq(nodeID, requesterID, sig)); err != nil {
		return nil, fmt.Errorf("send resolve: %w", err)
	}

	msgType, payload, err := wireReadFrame(c.conn)
	if err != nil {
		return nil, fmt.Errorf("recv resolve: %w", err)
	}

	if msgType == wireMsgError {
		return nil, fmt.Errorf("registry: %s", decodeWireError(payload))
	}
	if msgType != wireMsgResolveOK {
		return nil, fmt.Errorf("unexpected response type 0x%02x", msgType)
	}

	result, err := decodeResolveResp(payload)
	if err != nil {
		return nil, fmt.Errorf("decode resolve response: %w", err)
	}
	return &result, nil
}

// SendJSON sends a JSON message over the binary protocol using JSON passthrough.
// This allows any registry operation to be used without a native binary encoding.
func (c *BinaryClient) SendJSON(msg map[string]interface{}) (map[string]interface{}, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	resp, err := c.sendJSONLocked(msg)
	if err != nil && resp == nil && !c.closed {
		if reconnErr := c.reconnect(); reconnErr != nil {
			return nil, fmt.Errorf("send failed and reconnect failed: %w", err)
		}
		resp, err = c.sendJSONLocked(msg)
	}
	return resp, err
}

func (c *BinaryClient) sendJSONLocked(msg map[string]interface{}) (map[string]interface{}, error) {
	body, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("json encode: %w", err)
	}

	if err := wireWriteFrame(c.conn, wireMsgJSON, body); err != nil {
		return nil, fmt.Errorf("send: %w", err)
	}

	msgType, payload, readErr := wireReadFrame(c.conn)
	if readErr != nil {
		return nil, fmt.Errorf("recv: %w", readErr)
	}

	if msgType == wireMsgError {
		errMsg := decodeWireError(payload)
		return map[string]interface{}{"type": "error", "error": errMsg}, fmt.Errorf("registry: %s", errMsg)
	}
	if msgType != wireMsgJSON {
		return nil, fmt.Errorf("unexpected response type 0x%02x for JSON passthrough", msgType)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(payload, &resp); err != nil {
		return nil, fmt.Errorf("json decode response: %w", err)
	}
	if errMsg, ok := resp["error"].(string); ok {
		return resp, fmt.Errorf("registry: %s", errMsg)
	}
	return resp, nil
}
