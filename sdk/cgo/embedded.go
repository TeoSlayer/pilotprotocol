// SPDX-License-Identifier: AGPL-3.0-or-later

// Embedded daemon entry points.
//
// The other half of this package (bindings.go) is a thin RPC client
// that talks to an out-of-process daemon over a Unix socket. That
// model fits desktop SDKs (Python, Node) where the daemon is a
// separate long-running process. It does NOT fit iOS: one app =
// one process, no sibling daemon binary, no system-wide socket.
//
// PilotEmbeddedStart boots a daemon directly inside the host process
// (the goroutine model is unchanged from cmd/daemon). Internally it
// still opens a Unix socket so the existing 45 Pilot* RPC functions
// in bindings.go work unchanged — same wire protocol, just a
// different addressing space.
//
// Lifecycle: PilotEmbeddedStart → PilotConnect(socketPath) → use
// driver functions → PilotClose(handle) → PilotEmbeddedStop.

package main

/*
#include <stdlib.h>
#include <stdint.h>
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/driver"

	"github.com/pilot-protocol/handshake"
	"github.com/pilot-protocol/policy"
	"github.com/pilot-protocol/runtime"
	"github.com/pilot-protocol/skillinject"
)

type embeddedNode struct {
	d  *daemon.Daemon
	rt *runtime.Runtime
}

var embedded struct {
	sync.Mutex
	node *embeddedNode
}

// EmbeddedConfig is what callers supply via JSON in PilotEmbeddedStart.
// Keep it minimal and JSON-friendly so the Swift/Obj-C side can build
// it with a dictionary literal.
type embeddedConfig struct {
	DataDir          string `json:"data_dir"`           // absolute, host-writable
	SocketPath       string `json:"socket_path"`        // ≤ 100 bytes; use relative if abs is too long
	RegistryAddr     string `json:"registry_addr"`      // default 34.71.57.205:9000
	BeaconAddr       string `json:"beacon_addr"`        // default 34.71.57.205:9001
	TrustAutoApprove bool   `json:"trust_auto_approve"` // accept all incoming handshakes
	KeepaliveSec     int    `json:"keepalive_sec"`      // default 30; lower → faster handshake polling
	Version          string `json:"version"`            // surfaced in Info(); cosmetic
}

func (c *embeddedConfig) defaults() {
	if c.RegistryAddr == "" {
		c.RegistryAddr = "34.71.57.205:9000"
	}
	if c.BeaconAddr == "" {
		c.BeaconAddr = "34.71.57.205:9001"
	}
	if c.KeepaliveSec <= 0 {
		c.KeepaliveSec = 30
	}
	if c.Version == "" {
		c.Version = "embedded"
	}
}

// Boot the embedded daemon. configJSON is a JSON-encoded embeddedConfig.
// Returns JSON: on success {"address","node_id","public_key","socket"},
// on failure {"error": "..."}.
//
// Idempotent only in the trivial sense — calling twice without Stop
// returns an error.
//
//export PilotEmbeddedStart
func PilotEmbeddedStart(configJSON *C.char) *C.char {
	embedded.Lock()
	defer embedded.Unlock()
	if embedded.node != nil {
		return errJSON(fmt.Errorf("embedded daemon already started"))
	}

	var cfg embeddedConfig
	if err := unmarshalCString(configJSON, &cfg); err != nil {
		return errJSON(fmt.Errorf("parse config: %w", err))
	}
	cfg.defaults()
	if cfg.DataDir == "" {
		return errJSON(fmt.Errorf("data_dir required"))
	}
	if cfg.SocketPath == "" {
		return errJSON(fmt.Errorf("socket_path required"))
	}

	identityPath := filepath.Join(cfg.DataDir, "identity.json")

	d := daemon.New(daemon.Config{
		RegistryAddr:        cfg.RegistryAddr,
		BeaconAddr:          cfg.BeaconAddr,
		ListenAddr:          ":0",
		SocketPath:          cfg.SocketPath,
		Encrypt:             true,
		IdentityPath:        identityPath,
		DisableEcho:         true,
		DisableDataExchange: true,
		DisableEventStream:  true,
		TrustAutoApprove:    cfg.TrustAutoApprove,
		KeepaliveInterval:   time.Duration(cfg.KeepaliveSec) * time.Second,
		Version:             cfg.Version,
	})

	rt := runtime.New(d)

	// Minimum plugin set for handshake + datagram I/O. No
	// trustedagents (it gates trust to a curated GitHub list and
	// breaks ad-hoc peers), no webhook (spams retries to a stale
	// URL on macOS dev hosts), no dataexchange/eventstream
	// (file-system inbox; clients use SendTo/RecvFrom directly).
	if err := rt.Register(skillinject.NewService(skillinject.Config{})); err != nil {
		return errJSON(fmt.Errorf("register skillinject: %w", err))
	}

	policySvc := policy.NewService(runtime.NewPolicyRuntime(d))
	if err := rt.Register(policySvc); err != nil {
		return errJSON(fmt.Errorf("register policy: %w", err))
	}
	d.RegisterPolicyManager(runtime.AsDaemonPolicyManager(policySvc.Manager()))

	hsSvc := handshake.NewService(runtime.NewHandshakeRuntime(d))
	if err := rt.Register(hsSvc); err != nil {
		return errJSON(fmt.Errorf("register handshake: %w", err))
	}
	d.RegisterHandshakeService(runtime.NewHandshakeServiceAdapter(hsSvc))

	if err := rt.StartPlugins(context.Background()); err != nil {
		return errJSON(fmt.Errorf("plugin startup: %w", err))
	}
	if err := d.Start(); err != nil {
		_ = rt.StopPlugins(context.Background())
		return errJSON(fmt.Errorf("daemon start: %w", err))
	}

	embedded.node = &embeddedNode{d: d, rt: rt}

	// Wait for the IPC socket to exist before we probe Info() — Start
	// returns once IPC is listening, but on slow simulators the file
	// stat can race.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(cfg.SocketPath); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Probe Info() so callers get node_id/address/public_key in the
	// startup response without an extra round-trip.
	probe, err := driver.Connect(cfg.SocketPath)
	if err != nil {
		return okJSON(map[string]interface{}{
			"node_id": d.NodeID(),
			"socket":  cfg.SocketPath,
			"warning": fmt.Sprintf("probe connect: %v", err),
		})
	}
	defer probe.Close()
	info, err := probe.Info()
	if err != nil {
		return okJSON(map[string]interface{}{
			"node_id": d.NodeID(),
			"socket":  cfg.SocketPath,
			"warning": fmt.Sprintf("probe info: %v", err),
		})
	}

	return okJSON(map[string]interface{}{
		"address":    info["address"],
		"node_id":    info["node_id"],
		"public_key": info["public_key"],
		"socket":     cfg.SocketPath,
	})
}

// Tear down the embedded daemon and all plugins. Safe to call when
// not started — returns {"status":"not_started"}.
//
//export PilotEmbeddedStop
func PilotEmbeddedStop() *C.char {
	embedded.Lock()
	n := embedded.node
	embedded.node = nil
	embedded.Unlock()

	if n == nil {
		return okJSON(map[string]string{"status": "not_started"})
	}

	if err := n.d.Stop(); err != nil {
		return errJSON(fmt.Errorf("daemon stop: %w", err))
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := n.rt.StopPlugins(stopCtx); err != nil {
		// Not fatal — daemon is already down, plugin teardown is
		// best-effort. Surface the warning to the caller.
		return okJSON(map[string]string{
			"status":  "stopped",
			"warning": err.Error(),
		})
	}
	return okJSON(map[string]string{"status": "stopped"})
}

// unmarshalCString is a tiny helper to JSON-decode a C string into v.
func unmarshalCString(s *C.char, v interface{}) error {
	if s == nil {
		return fmt.Errorf("nil")
	}
	return json.Unmarshal([]byte(C.GoString(s)), v)
}
