package main

/*
#include <stdlib.h>
#include <stdint.h>
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"sync"
	"unsafe"

	"github.com/TeoSlayer/pilotprotocol/pkg/driver"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// ---------- Handle table ----------
// Keeps Go heap objects alive while C/Python holds a uint64 token.

var handles struct {
	sync.Mutex
	m    map[uint64]interface{}
	next uint64
}

func init() {
	handles.m = make(map[uint64]interface{})
	handles.next = 1
}

func storeHandle(v interface{}) uint64 {
	handles.Lock()
	id := handles.next
	handles.next++
	handles.m[id] = v
	handles.Unlock()
	return id
}

func loadHandle(id uint64) (interface{}, bool) {
	handles.Lock()
	v, ok := handles.m[id]
	handles.Unlock()
	return v, ok
}

func deleteHandle(id uint64) {
	handles.Lock()
	delete(handles.m, id)
	handles.Unlock()
}

// ---------- Helpers ----------

func errJSON(err error) *C.char {
	out, _ := json.Marshal(map[string]string{"error": err.Error()})
	return C.CString(string(out))
}

func okJSON(v interface{}) *C.char {
	out, _ := json.Marshal(v)
	return C.CString(string(out))
}

func driverFromHandle(h C.uint64_t) (*driver.Driver, error) {
	v, ok := loadHandle(uint64(h))
	if !ok {
		return nil, fmt.Errorf("invalid driver handle")
	}
	d, ok := v.(*driver.Driver)
	if !ok {
		return nil, fmt.Errorf("handle is not a Driver")
	}
	return d, nil
}

// ---------- Memory ----------

//export FreeString
func FreeString(s *C.char) {
	C.free(unsafe.Pointer(s))
}

// ---------- Driver lifecycle ----------

//export PilotConnect
func PilotConnect(socketPath *C.char) (C.uint64_t, *C.char) {
	path := C.GoString(socketPath)
	d, err := driver.Connect(path)
	if err != nil {
		return 0, errJSON(err)
	}
	return C.uint64_t(storeHandle(d)), nil
}

//export PilotClose
func PilotClose(h C.uint64_t) *C.char {
	v, ok := loadHandle(uint64(h))
	if !ok {
		return errJSON(fmt.Errorf("invalid handle"))
	}
	d, ok := v.(*driver.Driver)
	if !ok {
		return errJSON(fmt.Errorf("handle is not a Driver"))
	}
	deleteHandle(uint64(h))
	if err := d.Close(); err != nil {
		return errJSON(err)
	}
	return nil
}

// ---------- JSON-RPC wrappers ----------

//export PilotInfo
func PilotInfo(h C.uint64_t) *C.char {
	d, err := driverFromHandle(h)
	if err != nil {
		return errJSON(err)
	}
	r, err := d.Info()
	if err != nil {
		return errJSON(err)
	}
	return okJSON(r)
}

//export PilotHandshake
func PilotHandshake(h C.uint64_t, nodeID C.uint32_t, justification *C.char) *C.char {
	d, err := driverFromHandle(h)
	if err != nil {
		return errJSON(err)
	}
	r, err := d.Handshake(uint32(nodeID), C.GoString(justification))
	if err != nil {
		return errJSON(err)
	}
	return okJSON(r)
}

//export PilotApproveHandshake
func PilotApproveHandshake(h C.uint64_t, nodeID C.uint32_t) *C.char {
	d, err := driverFromHandle(h)
	if err != nil {
		return errJSON(err)
	}
	r, err := d.ApproveHandshake(uint32(nodeID))
	if err != nil {
		return errJSON(err)
	}
	return okJSON(r)
}

//export PilotRejectHandshake
func PilotRejectHandshake(h C.uint64_t, nodeID C.uint32_t, reason *C.char) *C.char {
	d, err := driverFromHandle(h)
	if err != nil {
		return errJSON(err)
	}
	r, err := d.RejectHandshake(uint32(nodeID), C.GoString(reason))
	if err != nil {
		return errJSON(err)
	}
	return okJSON(r)
}

//export PilotPendingHandshakes
func PilotPendingHandshakes(h C.uint64_t) *C.char {
	d, err := driverFromHandle(h)
	if err != nil {
		return errJSON(err)
	}
	r, err := d.PendingHandshakes()
	if err != nil {
		return errJSON(err)
	}
	return okJSON(r)
}

//export PilotTrustedPeers
func PilotTrustedPeers(h C.uint64_t) *C.char {
	d, err := driverFromHandle(h)
	if err != nil {
		return errJSON(err)
	}
	r, err := d.TrustedPeers()
	if err != nil {
		return errJSON(err)
	}
	return okJSON(r)
}

//export PilotRevokeTrust
func PilotRevokeTrust(h C.uint64_t, nodeID C.uint32_t) *C.char {
	d, err := driverFromHandle(h)
	if err != nil {
		return errJSON(err)
	}
	r, err := d.RevokeTrust(uint32(nodeID))
	if err != nil {
		return errJSON(err)
	}
	return okJSON(r)
}

//export PilotResolveHostname
func PilotResolveHostname(h C.uint64_t, hostname *C.char) *C.char {
	d, err := driverFromHandle(h)
	if err != nil {
		return errJSON(err)
	}
	r, err := d.ResolveHostname(C.GoString(hostname))
	if err != nil {
		return errJSON(err)
	}
	return okJSON(r)
}

//export PilotSetHostname
func PilotSetHostname(h C.uint64_t, hostname *C.char) *C.char {
	d, err := driverFromHandle(h)
	if err != nil {
		return errJSON(err)
	}
	r, err := d.SetHostname(C.GoString(hostname))
	if err != nil {
		return errJSON(err)
	}
	return okJSON(r)
}

//export PilotSetVisibility
func PilotSetVisibility(h C.uint64_t, public C.int) *C.char {
	d, err := driverFromHandle(h)
	if err != nil {
		return errJSON(err)
	}
	r, err := d.SetVisibility(public != 0)
	if err != nil {
		return errJSON(err)
	}
	return okJSON(r)
}

//export PilotSetTaskExec
func PilotSetTaskExec(h C.uint64_t, enabled C.int) *C.char {
	d, err := driverFromHandle(h)
	if err != nil {
		return errJSON(err)
	}
	r, err := d.SetTaskExec(enabled != 0)
	if err != nil {
		return errJSON(err)
	}
	return okJSON(r)
}

//export PilotDeregister
func PilotDeregister(h C.uint64_t) *C.char {
	d, err := driverFromHandle(h)
	if err != nil {
		return errJSON(err)
	}
	r, err := d.Deregister()
	if err != nil {
		return errJSON(err)
	}
	return okJSON(r)
}

//export PilotSetTags
func PilotSetTags(h C.uint64_t, tagsJSON *C.char) *C.char {
	d, err := driverFromHandle(h)
	if err != nil {
		return errJSON(err)
	}
	var tags []string
	if err := json.Unmarshal([]byte(C.GoString(tagsJSON)), &tags); err != nil {
		return errJSON(fmt.Errorf("invalid tags JSON: %w", err))
	}
	r, err := d.SetTags(tags)
	if err != nil {
		return errJSON(err)
	}
	return okJSON(r)
}

//export PilotSetWebhook
func PilotSetWebhook(h C.uint64_t, url *C.char) *C.char {
	d, err := driverFromHandle(h)
	if err != nil {
		return errJSON(err)
	}
	r, err := d.SetWebhook(C.GoString(url))
	if err != nil {
		return errJSON(err)
	}
	return okJSON(r)
}

//export PilotDisconnect
func PilotDisconnect(h C.uint64_t, connID C.uint32_t) *C.char {
	d, err := driverFromHandle(h)
	if err != nil {
		return errJSON(err)
	}
	if err := d.Disconnect(uint32(connID)); err != nil {
		return errJSON(err)
	}
	return nil
}

// ---------- Stream connections ----------

//export PilotDial
func PilotDial(h C.uint64_t, addr *C.char) (C.uint64_t, *C.char) {
	d, err := driverFromHandle(h)
	if err != nil {
		return 0, errJSON(err)
	}
	conn, err := d.Dial(C.GoString(addr))
	if err != nil {
		return 0, errJSON(err)
	}
	return C.uint64_t(storeHandle(conn)), nil
}

//export PilotListen
func PilotListen(h C.uint64_t, port C.uint16_t) (C.uint64_t, *C.char) {
	d, err := driverFromHandle(h)
	if err != nil {
		return 0, errJSON(err)
	}
	ln, err := d.Listen(uint16(port))
	if err != nil {
		return 0, errJSON(err)
	}
	return C.uint64_t(storeHandle(ln)), nil
}

//export PilotListenerAccept
func PilotListenerAccept(lh C.uint64_t) (C.uint64_t, *C.char) {
	v, ok := loadHandle(uint64(lh))
	if !ok {
		return 0, errJSON(fmt.Errorf("invalid listener handle"))
	}
	ln, ok := v.(*driver.Listener)
	if !ok {
		return 0, errJSON(fmt.Errorf("handle is not a Listener"))
	}
	conn, err := ln.Accept()
	if err != nil {
		return 0, errJSON(err)
	}
	return C.uint64_t(storeHandle(conn)), nil
}

//export PilotListenerClose
func PilotListenerClose(lh C.uint64_t) *C.char {
	v, ok := loadHandle(uint64(lh))
	if !ok {
		return errJSON(fmt.Errorf("invalid listener handle"))
	}
	ln, ok := v.(*driver.Listener)
	if !ok {
		return errJSON(fmt.Errorf("handle is not a Listener"))
	}
	deleteHandle(uint64(lh))
	if err := ln.Close(); err != nil {
		return errJSON(err)
	}
	return nil
}

//export PilotConnRead
func PilotConnRead(ch C.uint64_t, bufSize C.int) (C.int, *C.char, *C.char) {
	v, ok := loadHandle(uint64(ch))
	if !ok {
		return 0, nil, errJSON(fmt.Errorf("invalid conn handle"))
	}
	type reader interface{ Read([]byte) (int, error) }
	r, ok := v.(reader)
	if !ok {
		return 0, nil, errJSON(fmt.Errorf("handle is not a Conn"))
	}
	buf := make([]byte, int(bufSize))
	n, err := r.Read(buf)
	if err != nil {
		return 0, nil, errJSON(err)
	}
	cData := C.CBytes(buf[:n])
	return C.int(n), (*C.char)(cData), nil
}

//export PilotConnWrite
func PilotConnWrite(ch C.uint64_t, data unsafe.Pointer, dataLen C.int) (C.int, *C.char) {
	v, ok := loadHandle(uint64(ch))
	if !ok {
		return 0, errJSON(fmt.Errorf("invalid conn handle"))
	}
	type writer interface{ Write([]byte) (int, error) }
	w, ok := v.(writer)
	if !ok {
		return 0, errJSON(fmt.Errorf("handle is not a Conn"))
	}
	n, err := w.Write(C.GoBytes(data, dataLen))
	if err != nil {
		return 0, errJSON(err)
	}
	return C.int(n), nil
}

//export PilotConnClose
func PilotConnClose(ch C.uint64_t) *C.char {
	v, ok := loadHandle(uint64(ch))
	if !ok {
		return errJSON(fmt.Errorf("invalid conn handle"))
	}
	type closer interface{ Close() error }
	c, ok := v.(closer)
	if !ok {
		return errJSON(fmt.Errorf("handle is not a Conn"))
	}
	deleteHandle(uint64(ch))
	if err := c.Close(); err != nil {
		return errJSON(err)
	}
	return nil
}

// ---------- Datagrams ----------

//export PilotSendTo
func PilotSendTo(h C.uint64_t, fullAddr *C.char, data unsafe.Pointer, dataLen C.int) *C.char {
	d, err := driverFromHandle(h)
	if err != nil {
		return errJSON(err)
	}
	// fullAddr = "N:XXXX.YYYY.YYYY:PORT"
	sa, err := protocol.ParseSocketAddr(C.GoString(fullAddr))
	if err != nil {
		return errJSON(err)
	}
	if err := d.SendTo(sa.Addr, sa.Port, C.GoBytes(data, dataLen)); err != nil {
		return errJSON(err)
	}
	return nil
}

//export PilotRecvFrom
func PilotRecvFrom(h C.uint64_t) *C.char {
	d, err := driverFromHandle(h)
	if err != nil {
		return errJSON(err)
	}
	dg, err := d.RecvFrom()
	if err != nil {
		return errJSON(err)
	}
	return okJSON(map[string]interface{}{
		"src_addr": dg.SrcAddr.String(),
		"src_port": dg.SrcPort,
		"dst_port": dg.DstPort,
		"data":     dg.Data,
	})
}

// main is required for c-shared build mode.
func main() {}
