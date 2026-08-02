// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"net"
	"testing"
	"time"
)

func TestIPCUnbindReleasesOwnedPortForImmediateReuse(t *testing.T) {
	d, server, socketPath := newIPCTestServer(t)
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	connection, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	port := []byte{0x17, 0xD6} // 6102
	if err := writeIPCRequest(connection, CmdBind, port); err != nil {
		t.Fatal(err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	if reply, err := readIPCFrame(connection); err != nil || reply[0] != CmdBindOK {
		t.Fatalf("bind reply=%x err=%v", reply, err)
	}
	if err := writeIPCRequest(connection, CmdUnbind, port); err != nil {
		t.Fatal(err)
	}
	if reply, err := readIPCFrame(connection); err != nil || reply[0] != CmdUnbindOK {
		t.Fatalf("unbind reply=%x err=%v", reply, err)
	}
	if listener := d.ports.GetListener(6102); listener != nil {
		t.Fatal("unbound port remained allocated")
	}
	if err := writeIPCRequest(connection, CmdBind, port); err != nil {
		t.Fatal(err)
	}
	if reply, err := readIPCFrame(connection); err != nil || reply[0] != CmdBindOK {
		t.Fatalf("rebind reply=%x err=%v", reply, err)
	}
}
