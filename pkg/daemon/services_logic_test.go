// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"io"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// --- TaskQueue ---

func TestTaskQueueAddFirstTaskMarksItAsHead(t *testing.T) {
	q := NewTaskQueue()
	q.Add("task-1")
	if got := q.Peek(); got != "task-1" {
		t.Fatalf("Peek = %q, want task-1", got)
	}
	if got := q.GetHeadStagedAt(); got == "" {
		t.Fatal("head should have staged timestamp")
	}
}

func TestTaskQueueAddSubsequentTasksOnlyFirstHasStagedTimestamp(t *testing.T) {
	q := NewTaskQueue()
	q.Add("head")
	q.Add("next")

	if got := q.GetStagedAt("head"); got == "" {
		t.Fatal("head should have staged timestamp")
	}
	if got := q.GetStagedAt("next"); got != "" {
		t.Fatalf("non-head task should not have staged timestamp, got %q", got)
	}
}

func TestTaskQueuePopEmptyReturnsEmptyString(t *testing.T) {
	q := NewTaskQueue()
	if got := q.Pop(); got != "" {
		t.Fatalf("Pop on empty = %q, want empty", got)
	}
}

func TestTaskQueuePopReturnsFirstAndPromotesNewHead(t *testing.T) {
	q := NewTaskQueue()
	q.Add("a")
	q.Add("b")
	q.Add("c")

	if got := q.Pop(); got != "a" {
		t.Fatalf("Pop = %q, want a", got)
	}
	// Old head's timestamp cleared; new head "b" gets a fresh timestamp
	if got := q.GetStagedAt("a"); got != "" {
		t.Fatalf("popped head should have no staged timestamp, got %q", got)
	}
	if got := q.GetStagedAt("b"); got == "" {
		t.Fatal("new head should have staged timestamp")
	}
	if q.Len() != 2 {
		t.Fatalf("Len = %d, want 2", q.Len())
	}
}

func TestTaskQueuePopToEmptyClearsHeadStagedAt(t *testing.T) {
	q := NewTaskQueue()
	q.Add("only")
	_ = q.Pop()
	if got := q.GetStagedAt("only"); got != "" {
		t.Fatalf("timestamp should be cleared, got %q", got)
	}
	if got := q.GetHeadStagedAt(); got != "" {
		t.Fatalf("GetHeadStagedAt on empty queue = %q, want empty", got)
	}
}

func TestTaskQueueRemoveKnownReturnsTrue(t *testing.T) {
	q := NewTaskQueue()
	q.Add("a")
	q.Add("b")
	q.Add("c")

	if !q.Remove("b") {
		t.Fatal("Remove(b) should return true")
	}
	if q.Len() != 2 {
		t.Fatalf("Len = %d, want 2", q.Len())
	}
	if list := q.List(); len(list) != 2 || list[0] != "a" || list[1] != "c" {
		t.Fatalf("List = %v, want [a c]", list)
	}
}

func TestTaskQueueRemoveUnknownReturnsFalse(t *testing.T) {
	q := NewTaskQueue()
	q.Add("a")
	if q.Remove("nonexistent") {
		t.Fatal("Remove(nonexistent) should return false")
	}
}

func TestTaskQueueRemoveHeadPromotesNextWithStagedTimestamp(t *testing.T) {
	q := NewTaskQueue()
	q.Add("a")
	q.Add("b")
	// Confirm b has no timestamp
	if q.GetStagedAt("b") != "" {
		t.Fatal("b should not have staged timestamp before a is removed")
	}

	q.Remove("a")
	if got := q.GetStagedAt("b"); got == "" {
		t.Fatal("b should have staged timestamp after a was removed")
	}
	if got := q.GetStagedAt("a"); got != "" {
		t.Fatal("a's timestamp should be cleared after Remove")
	}
}

func TestTaskQueuePeekDoesNotModify(t *testing.T) {
	q := NewTaskQueue()
	if got := q.Peek(); got != "" {
		t.Fatalf("Peek on empty = %q, want empty", got)
	}
	q.Add("a")
	if got := q.Peek(); got != "a" {
		t.Fatalf("Peek = %q, want a", got)
	}
	if q.Len() != 1 {
		t.Fatalf("Len = %d after Peek, want 1", q.Len())
	}
}

func TestTaskQueueGetStagedAtUnknownReturnsEmpty(t *testing.T) {
	q := NewTaskQueue()
	q.Add("a")
	if got := q.GetStagedAt("ghost"); got != "" {
		t.Fatalf("unknown task = %q, want empty", got)
	}
}

func TestTaskQueueListReturnsACopy(t *testing.T) {
	q := NewTaskQueue()
	q.Add("a")
	q.Add("b")
	list1 := q.List()
	list1[0] = "mutated"
	// Internal state should not be affected by mutating the returned slice.
	if q.Peek() != "a" {
		t.Fatal("List should return a copy, not a reference")
	}
}

func TestGlobalQueueRemoveFromQueueRemovesFromGlobal(t *testing.T) {
	// Track what's in the global queue before we touch it.
	globalTaskQueue.Add("iter82-task-id")
	defer globalTaskQueue.Remove("iter82-task-id") // cleanup on test failure

	if ts := GetQueueStagedAt("iter82-task-id"); ts == "" {
		t.Fatal("GetQueueStagedAt should return non-empty for head task")
	}
	if !RemoveFromQueue("iter82-task-id") {
		t.Fatal("RemoveFromQueue should return true for known task")
	}
	if RemoveFromQueue("iter82-task-id") {
		t.Fatal("RemoveFromQueue should return false for already-removed task")
	}
}

// --- pilotAddr ---

func TestPilotAddrNetworkReturnsConstant(t *testing.T) {
	a := pilotAddr{addr: protocol.Addr{Network: 7, Node: 0xBEEF}, port: 1234}
	if a.Network() != "pilot" {
		t.Fatalf("Network = %q, want 'pilot'", a.Network())
	}
}

func TestPilotAddrStringFormatsAddressAndPort(t *testing.T) {
	a := pilotAddr{addr: protocol.Addr{Network: 7, Node: 0xBEEF}, port: 1234}
	got := a.String()
	want := a.addr.String() + ":1234"
	if got != want {
		t.Fatalf("String = %q, want %q", got, want)
	}
}

// --- connAdapter ---

func TestConnAdapterSetDeadlineAllNoOps(t *testing.T) {
	a := &connAdapter{}
	if err := a.SetDeadline(time.Now()); err != nil {
		t.Fatalf("SetDeadline = %v, want nil", err)
	}
	if err := a.SetReadDeadline(time.Now()); err != nil {
		t.Fatalf("SetReadDeadline = %v, want nil", err)
	}
	if err := a.SetWriteDeadline(time.Now()); err != nil {
		t.Fatalf("SetWriteDeadline = %v, want nil", err)
	}
}

func TestConnAdapterLocalAddrAndRemoteAddrUseConnFields(t *testing.T) {
	c := &Connection{
		LocalAddr:  protocol.Addr{Network: 1, Node: 0x11},
		LocalPort:  100,
		RemoteAddr: protocol.Addr{Network: 2, Node: 0x22},
		RemotePort: 200,
	}
	a := newConnAdapter(nil, c)

	local, ok := a.LocalAddr().(pilotAddr)
	if !ok {
		t.Fatal("LocalAddr should be pilotAddr")
	}
	if local.port != 100 {
		t.Fatalf("local.port = %d, want 100", local.port)
	}
	remote, ok := a.RemoteAddr().(pilotAddr)
	if !ok {
		t.Fatal("RemoteAddr should be pilotAddr")
	}
	if remote.port != 200 {
		t.Fatalf("remote.port = %d, want 200", remote.port)
	}
}

func TestConnAdapterReadDelivRecvBufData(t *testing.T) {
	c := &Connection{RecvBuf: make(chan []byte, 2)}
	a := newConnAdapter(nil, c)
	c.RecvBuf <- []byte("hello")

	buf := make([]byte, 10)
	n, err := a.Read(buf)
	if err != nil {
		t.Fatalf("Read err = %v", err)
	}
	if n != 5 || string(buf[:n]) != "hello" {
		t.Fatalf("Read = %q (n=%d), want 'hello'", buf[:n], n)
	}
}

func TestConnAdapterReadPartialCopyBuffersRemainder(t *testing.T) {
	c := &Connection{RecvBuf: make(chan []byte, 2)}
	a := newConnAdapter(nil, c)
	c.RecvBuf <- []byte("hello-world")

	// Tiny buffer — only 5 bytes can be read
	buf := make([]byte, 5)
	n, err := a.Read(buf)
	if err != nil {
		t.Fatalf("Read err = %v", err)
	}
	if n != 5 || string(buf[:n]) != "hello" {
		t.Fatalf("first Read = %q, want 'hello'", buf[:n])
	}
	// Second Read should drain the leftover buffer WITHOUT pulling from RecvBuf
	buf2 := make([]byte, 10)
	n, err = a.Read(buf2)
	if err != nil {
		t.Fatalf("second Read err = %v", err)
	}
	if string(buf2[:n]) != "-world" {
		t.Fatalf("leftover Read = %q, want '-world'", buf2[:n])
	}
}

func TestConnAdapterReadReturnsEOFWhenRecvBufClosed(t *testing.T) {
	c := &Connection{RecvBuf: make(chan []byte, 1)}
	a := newConnAdapter(nil, c)
	close(c.RecvBuf)

	buf := make([]byte, 10)
	n, err := a.Read(buf)
	if err != io.EOF {
		t.Fatalf("Read err = %v, want io.EOF", err)
	}
	if n != 0 {
		t.Fatalf("Read n = %d, want 0", n)
	}
}
