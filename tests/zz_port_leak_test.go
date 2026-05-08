// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestEphemeralPortLeakOnSendDatagramError — §4.4 port-leak regression.
//
// Spec (architecture-notes/05-VERIFICATION.md §4.4):
//
//	Pre-fill port pool to capacity; induce 100 SendDatagram failures.
//	Verify: ephemeral pool not exhausted; subsequent dial succeeds.
//
// Setup:
//
//   - One real daemon A, plus a non-existent peer node ID. SendDatagram
//     to that node ID will fail at ensureTunnel() (registry resolve
//     miss). At the time of failure, AllocEphemeralPort has already
//     produced a port number — the test pins that the failure path
//     does not strand the port allocator.
//
//   - Architecture note: the current AllocEphemeralPort implementation
//     (pkg/daemon/ports.go) is stateless across datagram calls. It
//     advances a `nextEphPort` counter and checks `portInUse` against
//     the live `connections` map. Since SendDatagram never instantiates
//     a Connection, the allocated srcPort is never "registered" as
//     in-use anywhere — there is no state to leak. This test pins that
//     property: even after 100 induced failures, alloc still returns a
//     fresh port and a real outbound dial still completes a SYN.
//
// Assertions:
//  1. 100 SendDatagram calls to a non-existent peer all return errors.
//  2. After those 100 failures, A.SendDatagram to a real reachable peer
//     succeeds (proves the alloc counter still produces usable ports).
//  3. After those 100 failures, A.DialConnection to a real peer
//     succeeds within the standard test budget (proves the alloc path
//     used by stream connections is also unaffected).
func TestEphemeralPortLeakOnSendDatagramError(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	disableEcho := func(cfg *daemon.Config) { cfg.DisableEcho = true }
	a := env.AddDaemon(disableEcho)
	b := env.AddDaemon(disableEcho)

	// Stand up an echo listener on B so the post-failure dial has
	// somewhere to land.
	ln, err := b.Driver.Listen(protocol.PortEcho)
	if err != nil {
		t.Fatalf("listen echo on B: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 64)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					if _, err := c.Write(buf[:n]); err != nil {
						return
					}
				}
			}()
		}
	}()

	// Choose a node ID that does not exist in the registry. The
	// daemons in this env are real and have real node IDs derived
	// from their identities; 0xDEADBEEF is exceedingly unlikely to
	// collide and will fail registry resolve cleanly.
	const phantomNode uint32 = 0xDEADBEEF
	phantomAddr := protocol.Addr{Network: a.Daemon.Addr().Network, Node: phantomNode}

	const failures = 100
	failed := 0
	for i := 0; i < failures; i++ {
		if err := a.Daemon.SendDatagram(phantomAddr, 12345, []byte("phantom")); err != nil {
			failed++
		}
	}
	if failed != failures {
		t.Fatalf("expected all %d SendDatagram calls to fail (phantom peer), got %d failures", failures, failed)
	}

	// Property 1: a real datagram still goes through after the failure
	// burst — port allocator did not get stuck.
	if err := a.Daemon.SendDatagram(b.Daemon.Addr(), protocol.PortEcho, []byte("post-failure")); err != nil {
		t.Fatalf("SendDatagram to live peer after %d failures: %v", failures, err)
	}

	// Property 2: a stream dial (which also calls AllocEphemeralPort)
	// still completes after the failure burst.
	if _, err := a.Daemon.DialConnection(b.Daemon.Addr(), protocol.PortEcho); err != nil {
		t.Fatalf("DialConnection to live peer after %d failures: %v", failures, err)
	}
	// Connection cleanup is driven by daemon Stop in TestEnv.Close
	// (t.Cleanup); pkg/daemon does not expose a public Close on
	// *daemon.Connection (the driver-side Conn does, but the public
	// dial returns the lower-level type).
}
