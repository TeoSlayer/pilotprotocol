// SPDX-License-Identifier: AGPL-3.0-or-later

package routing_test

import (
	"errors"
	"testing"
	"time"

	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/routing"
)

var errFake = errors.New("synthetic send error")

func TestBlackholeAccessors_EmptyManager(t *testing.T) {
	t.Parallel()
	m := routing.New()

	if got := m.LastDirectRecv(0xCAFE); !got.IsZero() {
		t.Errorf("LastDirectRecv on empty: %v, want zero", got)
	}
	if got, ok := m.LastOutboundSend(0xCAFE); ok || !got.IsZero() {
		t.Errorf("LastOutboundSend on empty: %v, %v; want zero,false", got, ok)
	}
	if got := m.SendErrCount(0xCAFE); got != 0 {
		t.Errorf("SendErrCount on empty: %d, want 0", got)
	}

	// Clear on absent key is a safe no-op.
	m.ClearSendErrCount(0xCAFE)
	if got := m.SendErrCount(0xCAFE); got != 0 {
		t.Errorf("after Clear: %d, want 0", got)
	}
}

func TestBlackholeAccessors_RoundTrip(t *testing.T) {
	t.Parallel()
	m := routing.New()

	const peer uint32 = 0x1234
	now := time.Now()

	// RecordDirectRecv populates LastDirectRecv.
	m.RecordDirectRecv(peer, now)
	if got := m.LastDirectRecv(peer); got != now {
		t.Errorf("LastDirectRecv: got %v, want %v", got, now)
	}

	// RecordOutboundSend stamps LastOutboundSend.
	m.RecordOutboundSend(peer, now.Add(time.Second))
	got, ok := m.LastOutboundSend(peer)
	if !ok || !got.Equal(now.Add(time.Second)) {
		t.Errorf("LastOutboundSend: %v %v", got, ok)
	}

	// HandleSendError with non-ICMP-unreachable err is a no-op
	// (covers the early-return branch).
	flipped, n := m.HandleSendError(peer, errFake)
	if flipped || n != 0 {
		t.Errorf("non-ICMP-unreachable: flipped=%v count=%d, want false,0", flipped, n)
	}
	// ClearSendErrCount on a clean peer is still safe.
	m.ClearSendErrCount(peer)
	if got := m.SendErrCount(peer); got != 0 {
		t.Errorf("SendErrCount after Clear: %d, want 0", got)
	}
}
