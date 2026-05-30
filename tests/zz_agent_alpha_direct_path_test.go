// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build pilot_production_smoke

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestAgentAlphaDirectPath is the end-to-end check for the direct-path
// preservation patches landed alongside this test:
//
//   - tunnel.go:onKeyInstalled — keep the ensureTunnel-resolved direct
//     address even when the peer's PILA arrives via the beacon.
//   - tunnel.go:handleRelayDeliver — skip MarkRelayActivatedIfHadCrypto
//     when we already hold a direct address for the peer.
//   - tunnel.go:maybeRequestRekey — skip AdmitRelayFromBeacon when we
//     already hold a direct address for the peer.
//   - routing.ClearRelayOnDirect — reset blackholeMissCount on
//     relay-decrypt events so a chatty peer that only replies via the
//     beacon does not get auto-pinned to relay after 8 s.
//
// Together these keep direct-path live for dialer-initiated sessions
// against production specialists. The test boots a real pilot-daemon
// against the production registry, dials agent-alpha (a deterministic,
// always-reachable public peer), then asserts PATH=direct via
// `pilotctl peers`. The build tag `pilot_production_smoke` gates this
// out of normal CI because it hits the live network — run with:
//
//	go test -tags pilot_production_smoke -run TestAgentAlphaDirectPath \
//	    -timeout 90s ./tests/
//
// Required env vars:
//
//	PILOT_DAEMON_BIN  — path to a freshly-built pilot-daemon
//	PILOT_CTL_BIN     — path to the matching pilotctl
//
// The daemon spins up with a fresh, ephemeral identity in t.TempDir so
// stale trust state from prior runs cannot mask a regression. Auto-
// approve trust is enabled so the test can transparently handshake with
// the public agent-alpha endpoint.
func TestAgentAlphaDirectPath(t *testing.T) {
	daemonBin := os.Getenv("PILOT_DAEMON_BIN")
	ctlBin := os.Getenv("PILOT_CTL_BIN")
	if daemonBin == "" || ctlBin == "" {
		t.Skip("set PILOT_DAEMON_BIN and PILOT_CTL_BIN to run the production-smoke direct-path test")
	}
	if _, err := os.Stat(daemonBin); err != nil {
		t.Fatalf("PILOT_DAEMON_BIN %q: %v", daemonBin, err)
	}
	if _, err := os.Stat(ctlBin); err != nil {
		t.Fatalf("PILOT_CTL_BIN %q: %v", ctlBin, err)
	}

	dir := t.TempDir()
	idPath := filepath.Join(dir, "identity.json")
	sockPath := filepath.Join(dir, "pilot.sock")
	logPath := filepath.Join(dir, "daemon.log")

	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create log: %v", err)
	}
	defer logFile.Close()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	cmd := exec.CommandContext(ctx, daemonBin,
		"-identity", idPath,
		"-socket", sockPath,
		"-listen", ":0",
		"-hostname", "direct-path-smoke",
		"-log-level", "info",
		"-trust-auto-approve",
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start daemon: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})

	// Wait for the IPC socket to come up.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if _, err := os.Stat(sockPath); err != nil {
		t.Fatalf("daemon socket never appeared: %v\nlog:\n%s", err, tailFile(t, logPath, 40))
	}

	env := append(os.Environ(), "PILOT_SOCKET="+sockPath)
	runCtl := func(args ...string) (string, error) {
		c := exec.CommandContext(ctx, ctlBin, args...)
		c.Env = env
		out, err := c.CombinedOutput()
		return string(out), err
	}

	// Drive the dial via ping. The first probe absorbs the handshake +
	// crypto exchange; later probes ride the established session.
	pingOut, err := runCtl("ping", "agent-alpha")
	if err != nil {
		t.Fatalf("ping agent-alpha: %v\nout:\n%s\ndaemon-log:\n%s", err, pingOut, tailFile(t, logPath, 60))
	}
	if !strings.Contains(pingOut, "seq=0") {
		t.Fatalf("ping output unexpected:\n%s", pingOut)
	}

	// Soak: give the routing layer enough time that the historical
	// 8-second silent-direct blackhole timer would have flipped us to
	// relay if the patch were absent. 12 s is comfortably past the
	// threshold.
	time.Sleep(12 * time.Second)

	// Re-ping to keep the session warm without re-establishing it,
	// then snapshot peer state via the structured info command.
	if _, err := runCtl("ping", "agent-alpha", "--count", "2"); err != nil {
		t.Fatalf("re-ping agent-alpha: %v", err)
	}
	infoOut, err := runCtl("--json", "info")
	if err != nil {
		t.Fatalf("info json: %v\nout:\n%s", err, infoOut)
	}

	relay, found, err := peerRelayFlag(infoOut, 16392) // agent-alpha
	if err != nil {
		t.Fatalf("parse info: %v\nraw:\n%s", err, infoOut)
	}
	if !found {
		t.Fatalf("agent-alpha (node 16392) not in peer_list — handshake never completed?\nlog:\n%s",
			tailFile(t, logPath, 60))
	}
	if relay {
		t.Fatalf("agent-alpha stuck on relay path — direct-path patches regressed.\nlog:\n%s",
			tailFile(t, logPath, 80))
	}
}

func peerRelayFlag(infoJSON string, nodeID uint32) (relay, found bool, err error) {
	var env struct {
		Data struct {
			PeerList []struct {
				NodeID uint32 `json:"node_id"`
				Relay  bool   `json:"relay"`
			} `json:"peer_list"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(infoJSON), &env); err != nil {
		return false, false, fmt.Errorf("unmarshal: %w", err)
	}
	for _, p := range env.Data.PeerList {
		if p.NodeID == nodeID {
			return p.Relay, true, nil
		}
	}
	return false, false, nil
}

func tailFile(t *testing.T, path string, n int) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return "<no log>"
	}
	lines := strings.Split(string(b), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
