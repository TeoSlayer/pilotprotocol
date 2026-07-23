// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"encoding/json"
	"testing"
	"time"

	registry "github.com/pilot-protocol/common/registry/client"
)

// newSimpleHandlerDaemon wires the minimum set of fields needed to exercise
// the "simple" IPC handlers: Info/Health/ResolveHostname/SetHostname/
// SetVisibility/Deregister/SetTags/SetWebhook/SetTaskExec. All of these call
// s.daemon.Info() (which touches tunnels, ports, handshakes, config) and/or
// a single registry method.
func newSimpleHandlerDaemon(t *testing.T, client *registry.Client) (*Daemon, *IPCServer) {
	t.Helper()
	d := &Daemon{
		nodeID:        7,
		tunnels:       NewTunnelManager(),
		ports:         NewPortManager(),
		resolveCache:  make(map[uint32]*resolveEntry),
		epCache:       make(map[uint32]*endpointEntry),
		hostnameCache: make(map[string]*hostnameCacheEntry),
		netPolicies:   make(map[uint16][]uint16),
		managed:       make(map[uint16]*ManagedEngine),
		memberTags:    make(map[uint16][]string),
		startTime:     time.Now(),
	}
	d.regConn.Store(client)
	d.ipc = NewIPCServer("", d)
	return d, d.ipc
}

// --- handleInfo ------------------------------------------------------------

func TestHandleInfoRepliesWithInfoOKAndNodeID(t *testing.T) {
	t.Parallel()
	// Info() calls nodeNetworks()→regConn.Lookup, so we need a fake registry.
	client, cleanup := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		if req["type"] == "lookup" {
			return map[string]interface{}{"networks": []interface{}{float64(0), float64(3)}}
		}
		return map[string]interface{}{}
	})
	defer cleanup()

	d, s := newSimpleHandlerDaemon(t, client)
	d.config.Hostname = "the-host"
	d.config.Version = "v9.9.9-test"

	ic, client2 := newIPCTestConn(t)
	reply := runHandler(t, client2, func() { s.handleInfo(ic, 0) })

	if reply[0] != CmdInfoOK {
		t.Fatalf("opcode = 0x%02X, want CmdInfoOK (0x%02X)", reply[0], CmdInfoOK)
	}
	var info map[string]interface{}
	if err := json.Unmarshal(reply[1:], &info); err != nil {
		t.Fatalf("info json: %v (payload=%q)", err, reply[1:])
	}
	if nid, _ := info["node_id"].(float64); uint32(nid) != 7 {
		t.Errorf("node_id = %v, want 7", info["node_id"])
	}
	if host, _ := info["hostname"].(string); host != "the-host" {
		t.Errorf("hostname = %q, want the-host", host)
	}
	if ver, _ := info["version"].(string); ver != "v9.9.9-test" {
		t.Errorf("version = %q, want v9.9.9-test", ver)
	}
	if _, ok := info["peer_list"].([]interface{}); !ok {
		t.Error("peer_list missing or wrong type")
	}
	if _, ok := info["conn_list"].([]interface{}); !ok {
		t.Error("conn_list missing or wrong type")
	}
}

// --- handleHealth ----------------------------------------------------------

func TestHandleHealthRepliesWithHealthOK(t *testing.T) {
	t.Parallel()
	client, cleanup := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		if req["type"] == "lookup" {
			return map[string]interface{}{"networks": []interface{}{}}
		}
		return map[string]interface{}{}
	})
	defer cleanup()

	d, s := newSimpleHandlerDaemon(t, client)
	d.startTime = time.Now().Add(-2 * time.Second)

	ic, client2 := newIPCTestConn(t)
	reply := runHandler(t, client2, func() { s.handleHealth(ic, 0) })

	if reply[0] != CmdHealthOK {
		t.Fatalf("opcode = 0x%02X, want CmdHealthOK", reply[0])
	}
	var health map[string]interface{}
	if err := json.Unmarshal(reply[1:], &health); err != nil {
		t.Fatalf("health json: %v", err)
	}
	if health["status"] != "ok" {
		t.Errorf("status = %v, want ok", health["status"])
	}
	if upt, _ := health["uptime_seconds"].(float64); upt < 1 {
		t.Errorf("uptime_seconds = %v, want >= 1", upt)
	}
}

// --- handleResolveHostname -------------------------------------------------

func TestHandleResolveHostnameEmptyPayloadReturnsError(t *testing.T) {
	t.Parallel()
	_, s := newSimpleHandlerDaemon(t, nil)
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() { s.handleResolveHostname(ic, 0, []byte{}) })
	if reply[0] != CmdError {
		t.Fatalf("opcode = 0x%02X, want CmdError", reply[0])
	}
}

func TestHandleResolveHostnameRegistryErrorPropagates(t *testing.T) {
	t.Parallel()
	client, cleanup := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		if req["type"] == "resolve_hostname" {
			return map[string]interface{}{"error": "not found"}
		}
		return map[string]interface{}{}
	})
	defer cleanup()

	_, s := newSimpleHandlerDaemon(t, client)
	ic, client2 := newIPCTestConn(t)
	reply := runHandler(t, client2, func() { s.handleResolveHostname(ic, 0, []byte("ghost.host")) })

	if reply[0] != CmdError {
		t.Fatalf("opcode = 0x%02X, want CmdError", reply[0])
	}
	if bodyStr := string(reply[3:]); bodyStr == "" {
		t.Error("error body empty")
	}
}

func TestHandleResolveHostnameSuccess(t *testing.T) {
	t.Parallel()
	client, cleanup := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		if req["type"] == "resolve_hostname" && req["hostname"] == "good.host" {
			return map[string]interface{}{"node_id": float64(99), "addr": "0:0000.0000.0063"}
		}
		return map[string]interface{}{}
	})
	defer cleanup()

	_, s := newSimpleHandlerDaemon(t, client)
	ic, client2 := newIPCTestConn(t)
	reply := runHandler(t, client2, func() { s.handleResolveHostname(ic, 0, []byte("good.host")) })

	if reply[0] != CmdResolveHostnameOK {
		t.Fatalf("opcode = 0x%02X, want CmdResolveHostnameOK", reply[0])
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(reply[1:], &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if nid, _ := resp["node_id"].(float64); uint32(nid) != 99 {
		t.Errorf("node_id = %v, want 99", resp["node_id"])
	}
}

// --- handleSetHostname -----------------------------------------------------

func TestHandleSetHostnameUpdatesConfigAndPropagatesReply(t *testing.T) {
	t.Parallel()
	var received string
	client, cleanup := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		if req["type"] == "set_hostname" {
			received, _ = req["hostname"].(string)
			return map[string]interface{}{"ok": true, "hostname": received}
		}
		return map[string]interface{}{}
	})
	defer cleanup()

	d, s := newSimpleHandlerDaemon(t, client)
	ic, client2 := newIPCTestConn(t)
	reply := runHandler(t, client2, func() { s.handleSetHostname(ic, 0, []byte("newname")) })

	if reply[0] != CmdSetHostnameOK {
		t.Fatalf("opcode 0x%02X", reply[0])
	}
	if received != "newname" {
		t.Errorf("registry received hostname=%q, want newname", received)
	}
	d.addrMu.RLock()
	got := d.config.Hostname
	d.addrMu.RUnlock()
	if got != "newname" {
		t.Errorf("daemon config.Hostname = %q, want newname", got)
	}
}

func TestHandleSetHostnameRegistryErrorReturnsError(t *testing.T) {
	t.Parallel()
	client, cleanup := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		if req["type"] == "set_hostname" {
			return map[string]interface{}{"error": "taken"}
		}
		return map[string]interface{}{}
	})
	defer cleanup()

	d, s := newSimpleHandlerDaemon(t, client)
	d.config.Hostname = "original"

	ic, client2 := newIPCTestConn(t)
	reply := runHandler(t, client2, func() { s.handleSetHostname(ic, 0, []byte("clash")) })

	if reply[0] != CmdError {
		t.Fatalf("opcode 0x%02X, want CmdError", reply[0])
	}
	d.addrMu.RLock()
	got := d.config.Hostname
	d.addrMu.RUnlock()
	if got != "original" {
		t.Errorf("config.Hostname = %q, want original (unchanged on error)", got)
	}
}

// --- handleSetVisibility ---------------------------------------------------

func TestHandleSetVisibilityMissingPayloadReturnsError(t *testing.T) {
	t.Parallel()
	_, s := newSimpleHandlerDaemon(t, nil)
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() { s.handleSetVisibility(ic, 0, []byte{}) })
	if reply[0] != CmdError {
		t.Fatalf("opcode 0x%02X, want CmdError", reply[0])
	}
}

func TestHandleSetVisibilityTrueUpdatesConfig(t *testing.T) {
	t.Parallel()
	var received interface{}
	client, cleanup := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		if req["type"] == "set_visibility" {
			received = req["public"]
			return map[string]interface{}{"ok": true}
		}
		return map[string]interface{}{}
	})
	defer cleanup()

	d, s := newSimpleHandlerDaemon(t, client)
	d.config.Public = false

	ic, client2 := newIPCTestConn(t)
	reply := runHandler(t, client2, func() { s.handleSetVisibility(ic, 0, []byte{0x01}) })

	if reply[0] != CmdSetVisibilityOK {
		t.Fatalf("opcode 0x%02X", reply[0])
	}
	if pub, _ := received.(bool); !pub {
		t.Errorf("registry received public=%v, want true", received)
	}
	d.addrMu.RLock()
	got := d.config.Public
	d.addrMu.RUnlock()
	if !got {
		t.Errorf("config.Public = false, want true")
	}
}

func TestHandleSetVisibilityFalseUpdatesConfig(t *testing.T) {
	t.Parallel()
	client, cleanup := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		if req["type"] == "set_visibility" {
			return map[string]interface{}{"ok": true}
		}
		return map[string]interface{}{}
	})
	defer cleanup()

	d, s := newSimpleHandlerDaemon(t, client)
	d.config.Public = true

	ic, client2 := newIPCTestConn(t)
	reply := runHandler(t, client2, func() { s.handleSetVisibility(ic, 0, []byte{0x00}) })

	if reply[0] != CmdSetVisibilityOK {
		t.Fatalf("opcode 0x%02X", reply[0])
	}
	d.addrMu.RLock()
	got := d.config.Public
	d.addrMu.RUnlock()
	if got {
		t.Errorf("config.Public = true, want false")
	}
}

func TestHandleSetVisibilityRegistryError(t *testing.T) {
	t.Parallel()
	client, cleanup := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		if req["type"] == "set_visibility" {
			return map[string]interface{}{"error": "denied"}
		}
		return map[string]interface{}{}
	})
	defer cleanup()

	_, s := newSimpleHandlerDaemon(t, client)
	ic, client2 := newIPCTestConn(t)
	reply := runHandler(t, client2, func() { s.handleSetVisibility(ic, 0, []byte{0x01}) })
	if reply[0] != CmdError {
		t.Fatalf("opcode 0x%02X, want CmdError", reply[0])
	}
}

// --- handleDeregister ------------------------------------------------------

func TestHandleDeregisterSuccess(t *testing.T) {
	t.Parallel()
	var receivedID interface{}
	client, cleanup := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		if req["type"] == "deregister" {
			receivedID = req["node_id"]
			return map[string]interface{}{"ok": true}
		}
		return map[string]interface{}{}
	})
	defer cleanup()

	_, s := newSimpleHandlerDaemon(t, client)
	ic, client2 := newIPCTestConn(t)
	reply := runHandler(t, client2, func() { s.handleDeregister(ic, 0) })

	if reply[0] != CmdDeregisterOK {
		t.Fatalf("opcode 0x%02X", reply[0])
	}
	if nid, _ := receivedID.(float64); uint32(nid) != 7 {
		t.Errorf("registry received node_id=%v, want 7", receivedID)
	}
}

func TestHandleDeregisterRegistryError(t *testing.T) {
	t.Parallel()
	client, cleanup := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		if req["type"] == "deregister" {
			return map[string]interface{}{"error": "offline"}
		}
		return map[string]interface{}{}
	})
	defer cleanup()

	_, s := newSimpleHandlerDaemon(t, client)
	ic, client2 := newIPCTestConn(t)
	reply := runHandler(t, client2, func() { s.handleDeregister(ic, 0) })
	if reply[0] != CmdError {
		t.Fatalf("opcode 0x%02X, want CmdError", reply[0])
	}
}

// --- handleSetTags ---------------------------------------------------------

func TestHandleSetTagsInvalidJSONReturnsError(t *testing.T) {
	t.Parallel()
	_, s := newSimpleHandlerDaemon(t, nil)
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() { s.handleSetTags(ic, 0, []byte("not json")) })
	if reply[0] != CmdError {
		t.Fatalf("opcode 0x%02X, want CmdError", reply[0])
	}
}

func TestHandleSetTagsOverLimitReturnsError(t *testing.T) {
	t.Parallel()
	_, s := newSimpleHandlerDaemon(t, nil)
	ic, client := newIPCTestConn(t)
	payload, _ := json.Marshal([]string{"a", "b", "c", "d"}) // 4 > 3
	reply := runHandler(t, client, func() { s.handleSetTags(ic, 0, payload) })
	if reply[0] != CmdError {
		t.Fatalf("opcode 0x%02X, want CmdError on >3 tags", reply[0])
	}
}

func TestHandleSetTagsSuccess(t *testing.T) {
	t.Parallel()
	var received interface{}
	client, cleanup := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		if req["type"] == "set_tags" {
			received = req["tags"]
			return map[string]interface{}{"ok": true}
		}
		return map[string]interface{}{}
	})
	defer cleanup()

	_, s := newSimpleHandlerDaemon(t, client)
	ic, client2 := newIPCTestConn(t)
	payload, _ := json.Marshal([]string{"one", "two"})
	reply := runHandler(t, client2, func() { s.handleSetTags(ic, 0, payload) })

	if reply[0] != CmdSetTagsOK {
		t.Fatalf("opcode 0x%02X, want CmdSetTagsOK", reply[0])
	}
	tags, _ := received.([]interface{})
	if len(tags) != 2 || tags[0] != "one" || tags[1] != "two" {
		t.Errorf("registry received tags=%v", received)
	}
}

func TestHandleSetTagsRegistryError(t *testing.T) {
	t.Parallel()
	client, cleanup := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		if req["type"] == "set_tags" {
			return map[string]interface{}{"error": "nope"}
		}
		return map[string]interface{}{}
	})
	defer cleanup()

	_, s := newSimpleHandlerDaemon(t, client)
	ic, client2 := newIPCTestConn(t)
	payload, _ := json.Marshal([]string{"x"})
	reply := runHandler(t, client2, func() { s.handleSetTags(ic, 0, payload) })
	if reply[0] != CmdError {
		t.Fatalf("opcode 0x%02X, want CmdError", reply[0])
	}
}

// --- handleSetWebhook ------------------------------------------------------

func TestHandleSetWebhookEmptyPayloadClearsWebhookReturnsOK(t *testing.T) {
	t.Parallel()
	_, s := newSimpleHandlerDaemon(t, nil)
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() { s.handleSetWebhook(ic, 0, []byte{}) })

	if reply[0] != CmdSetWebhookOK {
		t.Fatalf("opcode 0x%02X, want CmdSetWebhookOK", reply[0])
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(reply[1:], &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["webhook"] != "" {
		t.Errorf("webhook = %v, want empty string", resp["webhook"])
	}
}

func TestHandleSetWebhookInvalidURLReturnsError(t *testing.T) {
	t.Parallel()
	_, s := newSimpleHandlerDaemon(t, nil)
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() { s.handleSetWebhook(ic, 0, []byte("ftp://example.com/hook")) })
	if reply[0] != CmdError {
		t.Fatalf("opcode 0x%02X, want CmdError on invalid URL", reply[0])
	}
}

func TestHandleSetWebhookValidHTTPSURLAcceptedAndEchoedBack(t *testing.T) {
	t.Parallel()
	_, s := newSimpleHandlerDaemon(t, nil)
	ic, client := newIPCTestConn(t)
	url := "https://example.com/hook"
	reply := runHandler(t, client, func() { s.handleSetWebhook(ic, 0, []byte(url)) })

	if reply[0] != CmdSetWebhookOK {
		t.Fatalf("opcode 0x%02X, want CmdSetWebhookOK", reply[0])
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(reply[1:], &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["webhook"] != url {
		t.Errorf("webhook = %v, want %q", resp["webhook"], url)
	}
}
