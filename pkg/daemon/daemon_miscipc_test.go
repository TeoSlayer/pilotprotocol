// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
)

// Misc IPC handler dispatch coverage: handleResolveHostname, handleSetHostname,
// handleSetVisibility, handleSetTaskExec, handleSetTags, handleDeregister.
// Uses a shared miscTestDaemon that wires the real test registry + a signer
// so signed operations ("signature required for authenticated node") pass.

// miscTestDaemon returns a daemon wired with registry + identity + registered
// nodeID + signer (for SetHostname/SetVisibility/SetTags/SetTaskExec/Deregister).
func miscTestDaemon(t *testing.T) (*Daemon, uint32) {
	t.Helper()
	reg, rc := startTestRegistry(t)
	t.Cleanup(func() { reg.Close() })
	t.Cleanup(func() { rc.Close() })

	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("gen identity: %v", err)
	}
	resp, err := rc.RegisterWithKey("127.0.0.1:5800", crypto.EncodePublicKey(id.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("self register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	rc.SetSigner(func(challenge string) string {
		sig := id.Sign([]byte(challenge))
		return base64.StdEncoding.EncodeToString(sig)
	})

	d := New(Config{})
	d.regConn = rc
	d.identity = id
	d.setNodeID_testhelper(nodeID)
	t.Cleanup(func() { d.handshakes.Stop() })
	return d, nodeID
}

// --- handleResolveHostname ---

func TestHandleResolveHostnameUnknownSendsError(t *testing.T) {
	d, _ := miscTestDaemon(t)
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() {
		s.handleResolveHostname(ic, []byte("nonexistent-host"))
	})
	assertErrorReply(t, reply, "resolve_hostname:")
}

func TestHandleResolveHostnameValidRepliesOK(t *testing.T) {
	d, _ := miscTestDaemon(t)
	s := d.ipc

	// Registry's resolve_hostname applies a privacy check for private nodes:
	// non-self / non-trust resolvers see "not found" even if the name exists.
	// Flip the node to public so the unauthenticated IPC resolve succeeds.
	icV, clientV := newIPCTestConn(t)
	visReply := runHandler(t, clientV, func() {
		s.handleSetVisibility(icV, []byte{0x01})
	})
	if visReply[0] != CmdSetVisibilityOK {
		t.Fatalf("set_visibility reply[0] = 0x%02X, want CmdSetVisibilityOK — body=%q", visReply[0], visReply[1:])
	}

	// Set a hostname so resolve can find it.
	ic1, client1 := newIPCTestConn(t)
	setReply := runHandler(t, client1, func() {
		s.handleSetHostname(ic1, []byte("alice"))
	})
	if setReply[0] != CmdSetHostnameOK {
		t.Fatalf("set_hostname reply[0] = 0x%02X, want CmdSetHostnameOK — body=%q", setReply[0], setReply[1:])
	}

	ic2, client2 := newIPCTestConn(t)
	reply := runHandler(t, client2, func() {
		s.handleResolveHostname(ic2, []byte("alice"))
	})
	if reply[0] != CmdResolveHostnameOK {
		t.Fatalf("reply[0] = 0x%02X, want CmdResolveHostnameOK — body=%q", reply[0], reply[1:])
	}
	var r map[string]interface{}
	if err := json.Unmarshal(reply[1:], &r); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if _, ok := r["node_id"]; !ok {
		t.Fatalf("resolve reply missing node_id: %v", r)
	}
}

// --- handleSetHostname ---

func TestHandleSetHostnameValidRepliesOK(t *testing.T) {
	d, _ := miscTestDaemon(t)
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() {
		s.handleSetHostname(ic, []byte("bob"))
	})
	if reply[0] != CmdSetHostnameOK {
		t.Fatalf("reply[0] = 0x%02X, want CmdSetHostnameOK — body=%q", reply[0], reply[1:])
	}
	// Daemon config should reflect the new hostname.
	d.addrMu.Lock()
	got := d.config.Hostname
	d.addrMu.Unlock()
	if got != "bob" {
		t.Fatalf("daemon config hostname = %q, want %q", got, "bob")
	}
}

// --- handleSetVisibility ---

func TestHandleSetVisibilityPublicRepliesOK(t *testing.T) {
	d, _ := miscTestDaemon(t)
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() {
		s.handleSetVisibility(ic, []byte{0x01}) // public=true
	})
	if reply[0] != CmdSetVisibilityOK {
		t.Fatalf("reply[0] = 0x%02X, want CmdSetVisibilityOK — body=%q", reply[0], reply[1:])
	}
	d.addrMu.Lock()
	got := d.config.Public
	d.addrMu.Unlock()
	if !got {
		t.Fatal("daemon config Public = false, want true")
	}
}

func TestHandleSetVisibilityPrivateRepliesOK(t *testing.T) {
	d, _ := miscTestDaemon(t)
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() {
		s.handleSetVisibility(ic, []byte{0x00}) // public=false
	})
	if reply[0] != CmdSetVisibilityOK {
		t.Fatalf("reply[0] = 0x%02X, want CmdSetVisibilityOK — body=%q", reply[0], reply[1:])
	}
	d.addrMu.Lock()
	got := d.config.Public
	d.addrMu.Unlock()
	if got {
		t.Fatal("daemon config Public = true, want false")
	}
}

// --- handleSetTaskExec ---

func TestHandleSetTaskExecEnabledRepliesOK(t *testing.T) {
	d, _ := miscTestDaemon(t)
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() {
		s.handleSetTaskExec(ic, []byte{0x01}) // enabled=true
	})
	if reply[0] != CmdSetTaskExecOK {
		t.Fatalf("reply[0] = 0x%02X, want CmdSetTaskExecOK — body=%q", reply[0], reply[1:])
	}
}

func TestHandleSetTaskExecDisabledRepliesOK(t *testing.T) {
	d, _ := miscTestDaemon(t)
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() {
		s.handleSetTaskExec(ic, []byte{0x00}) // enabled=false
	})
	if reply[0] != CmdSetTaskExecOK {
		t.Fatalf("reply[0] = 0x%02X, want CmdSetTaskExecOK — body=%q", reply[0], reply[1:])
	}
}

// --- handleSetTags ---

func TestHandleSetTagsValidRepliesOK(t *testing.T) {
	d, _ := miscTestDaemon(t)
	s := d.ipc
	ic, client := newIPCTestConn(t)
	body := []byte(`["gpu","cpu"]`)
	reply := runHandler(t, client, func() {
		s.handleSetTags(ic, body)
	})
	if reply[0] != CmdSetTagsOK {
		t.Fatalf("reply[0] = 0x%02X, want CmdSetTagsOK — body=%q", reply[0], reply[1:])
	}
}

func TestHandleSetTagsEmptyArrayRepliesOK(t *testing.T) {
	d, _ := miscTestDaemon(t)
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() {
		s.handleSetTags(ic, []byte(`[]`))
	})
	if reply[0] != CmdSetTagsOK {
		t.Fatalf("reply[0] = 0x%02X, want CmdSetTagsOK — body=%q", reply[0], reply[1:])
	}
}

// --- handleDeregister ---

func TestHandleDeregisterValidRepliesOK(t *testing.T) {
	d, _ := miscTestDaemon(t)
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() {
		s.handleDeregister(ic)
	})
	if reply[0] != CmdDeregisterOK {
		t.Fatalf("reply[0] = 0x%02X, want CmdDeregisterOK — body=%q", reply[0], reply[1:])
	}
}
