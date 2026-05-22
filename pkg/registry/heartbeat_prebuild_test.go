// SPDX-License-Identifier: AGPL-3.0-or-later

package registry

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pilot-protocol/common/crypto"
)

// TestBuildHeartbeatOkMatchesJSONMarshal pins the wire-format contract: the
// pre-built bytes must be byte-identical to what Go's json.Marshal produces
// for the equivalent map[string]interface{}. If a future Go release changes
// encoder behavior, this test alerts immediately.
func TestBuildHeartbeatOkMatchesJSONMarshal(t *testing.T) {
	now := int64(1714500000)

	cases := []struct {
		name string
		warn bool
	}{
		{"no_warning", false},
		{"with_warning", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := map[string]interface{}{
				"type": "heartbeat_ok",
				"time": now,
			}
			if tc.warn {
				resp["key_expiry_warning"] = true
			}
			expected, err := json.Marshal(resp)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}

			got := buildHeartbeatOk(now, tc.warn)
			if string(got) != string(expected) {
				t.Fatalf("byte mismatch.\n  expected: %s\n       got: %s", string(expected), string(got))
			}

			// Round-trip parse to confirm semantic identity.
			var parsed map[string]interface{}
			if err := json.Unmarshal(got, &parsed); err != nil {
				t.Fatalf("parse pre-built bytes: %v", err)
			}
			if parsed["type"] != "heartbeat_ok" {
				t.Fatalf("type field wrong")
			}
			if int64(parsed["time"].(float64)) != now {
				t.Fatalf("time field wrong: %v", parsed["time"])
			}
			if tc.warn {
				if v, _ := parsed["key_expiry_warning"].(bool); !v {
					t.Fatalf("warning flag missing or wrong")
				}
			} else {
				if _, exists := parsed["key_expiry_warning"]; exists {
					t.Fatalf("warning flag should be absent without expiry")
				}
			}
		})
	}
}

// TestBuildHeartbeatOkVariousTimes validates timestamp encoding for edge
// cases (zero, max int64, negative).
func TestBuildHeartbeatOkVariousTimes(t *testing.T) {
	for _, ts := range []int64{0, 1, -1, 1714500000, 1<<62 - 1} {
		got := buildHeartbeatOk(ts, false)
		expected, _ := json.Marshal(map[string]interface{}{
			"type": "heartbeat_ok",
			"time": ts,
		})
		if string(got) != string(expected) {
			t.Fatalf("ts=%d: %s != %s", ts, string(got), string(expected))
		}
	}
}

// TestHandleHeartbeatUsesBypassMarshalSentinel locks down the integration:
// after a successful heartbeat, the response carries the rawResponseKey
// sentinel pointing at pre-built bytes that match the JSON shape. Tests
// the fast path actually fires on the production code path.
func TestHandleHeartbeatUsesBypassMarshalSentinel(t *testing.T) {
	s := newTestServer(t, "")
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	pkB64 := crypto.EncodePublicKey(id.PublicKey)

	const nodeID uint32 = 9001
	s.mu.Lock()
	n := &NodeInfo{
		ID:        nodeID,
		Owner:     "alice",
		PublicKey: id.PublicKey,
	}
	n.setLastSeen(time.Now())
	s.nodes[nodeID] = n
	s.pubKeyIdx[pkB64] = nodeID
	s.mu.Unlock()

	challenge := fmt.Sprintf("heartbeat:%d", nodeID)
	sig := id.Sign([]byte(challenge))

	resp, err := s.handleHeartbeat(map[string]interface{}{
		"node_id":   float64(nodeID),
		"signature": base64.StdEncoding.EncodeToString(sig),
	})
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	raw, ok := resp[rawResponseKey].([]byte)
	if !ok || len(raw) == 0 {
		t.Fatalf("expected rawResponseKey sentinel with pre-built bytes; got resp=%v", resp)
	}
	// Sanity: the bytes must parse and the payload must match.
	var parsed map[string]interface{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("pre-built bytes do not parse: %v\n%s", err, string(raw))
	}
	if parsed["type"] != "heartbeat_ok" {
		t.Fatalf("type field wrong: %v", parsed["type"])
	}
	if _, ok := parsed["time"].(float64); !ok {
		t.Fatalf("time field missing or wrong type: %T", parsed["time"])
	}
}

// TestWriteMessageBypassMarshalEmitsHeartbeatBytesVerbatim proves the
// end-to-end fast path: handler builds bytes → writeMessage emits them
// over the wire without ever calling json.Marshal on the outer map.
func TestWriteMessageBypassMarshalEmitsHeartbeatBytesVerbatim(t *testing.T) {
	preBuilt := buildHeartbeatOk(1714500000, false)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	server, err := listener.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer server.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := writeMessage(server, map[string]interface{}{
			rawResponseKey: preBuilt,
		})
		if err != nil {
			t.Errorf("writeMessage: %v", err)
		}
	}()

	// Read framed message from the client side.
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	var lenBuf [4]byte
	if _, err := readFull(client, lenBuf[:]); err != nil {
		t.Fatalf("read len: %v", err)
	}
	bodyLen := binary.BigEndian.Uint32(lenBuf[:])
	body := make([]byte, bodyLen)
	if _, err := readFull(client, body); err != nil {
		t.Fatalf("read body: %v", err)
	}

	wg.Wait()

	if string(body) != string(preBuilt) {
		t.Fatalf("wire bytes mismatch.\n  expected: %s\n       got: %s", string(preBuilt), string(body))
	}
}

// readFull is a tiny io.ReadFull substitute kept local to avoid pulling
// in the test-helper grab bag.
func readFull(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
