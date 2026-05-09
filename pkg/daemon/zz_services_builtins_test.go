// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// stopDaemonOnce closes d.stopCh safely from t.Cleanup and waits briefly so
// accept-loop goroutines can observe the close before the peer/tunnel are
// torn down by the outer cleanup.
func stopDaemonOnce(t *testing.T, d *Daemon) {
	t.Helper()
	t.Cleanup(func() {
		select {
		case <-d.stopCh:
		default:
			close(d.stopCh)
		}
		time.Sleep(20 * time.Millisecond)
	})
}

// -----------------------------------------------------------------------------
// startEchoService / startDataExchangeService / startEventStreamService
// bind + dup-bind error + stopCh exit
// -----------------------------------------------------------------------------

func TestStartEchoServiceBindsPortEcho(t *testing.T) {
	t.Parallel()
	d, _ := newPacketDaemon(t, nil)
	stopDaemonOnce(t, d)

	if err := d.startEchoService(); err != nil {
		t.Fatalf("startEchoService: %v", err)
	}
	if ln := d.ports.GetListener(protocol.PortEcho); ln == nil {
		t.Error("PortEcho listener missing after start")
	}
}

func TestStartEchoServiceDuplicateBindReturnsError(t *testing.T) {
	t.Parallel()
	d, _ := newPacketDaemon(t, nil)
	stopDaemonOnce(t, d)

	if err := d.startEchoService(); err != nil {
		t.Fatalf("first start: %v", err)
	}
	if err := d.startEchoService(); err == nil {
		t.Error("expected dup-bind error on second start")
	}
}

// startDataExchangeService / startEventStreamService / handleDataExchangeConn removed: extracted to plugins (T3.2).

// -----------------------------------------------------------------------------
// startBuiltinServices branches (all disabled / selectively enabled)
// -----------------------------------------------------------------------------

func TestStartBuiltinServicesOnlyEchoEnabledBindsOnlyEcho(t *testing.T) {
	t.Parallel()
	d, _ := newPacketDaemon(t, nil)
	d.config.DisableEcho = false
	d.config.DisableDataExchange = true
	d.config.DisableEventStream = true
	stopDaemonOnce(t, d)

	d.startBuiltinServices()

	if ln := d.ports.GetListener(protocol.PortEcho); ln == nil {
		t.Error("PortEcho not bound with echo enabled")
	}
	if ln := d.ports.GetListener(protocol.PortDataExchange); ln != nil {
		t.Error("PortDataExchange unexpectedly bound")
	}
}

func TestStartBuiltinServicesEchoFailureSwallowedByWarning(t *testing.T) {
	t.Parallel()
	d, _ := newPacketDaemon(t, nil)
	d.config.DisableDataExchange = true
	d.config.DisableEventStream = true
	// Pre-bind echo port so startEchoService fails; warning is logged, no panic.
	if _, err := d.ports.Bind(protocol.PortEcho); err != nil {
		t.Fatalf("prebind: %v", err)
	}
	stopDaemonOnce(t, d)

	d.startBuiltinServices() // must not panic even though startEcho errored
}

// -----------------------------------------------------------------------------
// handleEchoConn: echo loop + RecvBuf-close exit
// -----------------------------------------------------------------------------

func TestHandleEchoConnEchoesRecvBufDataBackViaSendData(t *testing.T) {
	t.Parallel()
	d, peer, conn := setupSendDataConn(t)
	conn.NoDelay = true

	done := make(chan struct{})
	go func() {
		d.handleEchoConn(conn)
		close(done)
	}()
	t.Cleanup(func() {
		conn.CloseRecvBuf()
		<-done
	})

	conn.RecvBuf <- []byte("ping")
	frame := readOneFrame(t, peer)
	if frame == nil {
		t.Fatal("no echo frame received")
	}
	pkt, err := protocol.Unmarshal(frame[4:])
	if err != nil {
		t.Fatal(err)
	}
	if string(pkt.Payload) != "ping" {
		t.Errorf("payload=%q, want 'ping'", pkt.Payload)
	}
}

func TestHandleEchoConnExitsWhenRecvBufClosed(t *testing.T) {
	t.Parallel()
	d, _, conn := setupSendDataConn(t)

	done := make(chan struct{})
	go func() {
		d.handleEchoConn(conn)
		close(done)
	}()

	conn.CloseRecvBuf()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("handleEchoConn did not return after RecvBuf close")
	}
}
