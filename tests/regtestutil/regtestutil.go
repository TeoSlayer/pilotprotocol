// SPDX-License-Identifier: AGPL-3.0-or-later

// Package regtestutil exposes a small fixture for spinning up an
// in-process registry server (and dialed client) for daemon-side tests.
//
// It lives under tests/ because pkg/daemon (L7) cannot import
// pkg/registry/server (L11) without violating the layered architecture,
// but daemon tests genuinely need a real registry to exercise
// regConn.{Lookup,Register,List}Nodes call paths. Tests/ is outside the
// classified layer stack, so an L7 source importing tests/regtestutil
// is not a layer violation.
package regtestutil

import (
	"testing"
	"time"

	registryclient "github.com/TeoSlayer/pilotprotocol/pkg/registry/client"
	registry "github.com/TeoSlayer/pilotprotocol/pkg/registry/server"
)

// StartTestRegistry boots an in-process registry on 127.0.0.1:0 and dials
// it. The test is responsible for closing both the server and the client
// (the standard pattern is `defer reg.Close(); defer rc.Close()`).
func StartTestRegistry(t *testing.T) (*registry.Server, *registryclient.Client) {
	t.Helper()
	reg := registry.New("")
	go func() { _ = reg.ListenAndServe(":0") }()
	select {
	case <-reg.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("registry failed to start")
	}
	rc, err := registryclient.Dial(reg.Addr().String())
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	return reg, rc
}
