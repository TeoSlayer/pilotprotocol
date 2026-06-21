// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"sync"
	"testing"
	"time"

	registryclient "github.com/pilot-protocol/common/registry/client"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon"
)

func TestBroadcast(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	// Sender daemon needs AdminToken set so its own BroadcastDatagram
	// call accepts the token we pass through Driver.Broadcast.
	a := env.AddDaemon(func(c *daemon.Config) { c.AdminToken = env.AdminToken })
	b := env.AddDaemon()
	c := env.AddDaemon()

	// Create a network and join all 3
	rc, err := registryclient.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("registry dial: %v", err)
	}
	defer rc.Close()

	resp, err := rc.CreateNetwork(a.Daemon.NodeID(), "test-topic", "open", "", env.AdminToken, false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))
	t.Logf("created network %d", netID)

	if _, err := rc.JoinNetwork(b.Daemon.NodeID(), netID, "", 0, env.AdminToken); err != nil {
		t.Fatalf("join B: %v", err)
	}
	if _, err := rc.JoinNetwork(c.Daemon.NodeID(), netID, "", 0, env.AdminToken); err != nil {
		t.Fatalf("join C: %v", err)
	}
	t.Log("all 3 nodes joined network")

	// Start receiving datagrams on B and C
	gotB := make(chan string, 1)
	gotC := make(chan string, 1)

	var recvReady sync.WaitGroup
	recvReady.Add(2)
	go func() {
		recvReady.Done()
		dg, err := b.Driver.RecvFrom()
		if err != nil {
			return
		}
		gotB <- string(dg.Data)
	}()
	go func() {
		recvReady.Done()
		dg, err := c.Driver.RecvFrom()
		if err != nil {
			return
		}
		gotC <- string(dg.Data)
	}()

	recvReady.Wait()

	// A broadcasts to the network
	if err := a.Driver.Broadcast(netID, 5000, []byte("hello network"), env.AdminToken); err != nil {
		t.Fatalf("broadcast: %v", err)
	}
	t.Log("broadcast sent")

	// B and C should both receive it
	timeout := time.After(5 * time.Second)
	var bMsg, cMsg string

	for i := 0; i < 2; i++ {
		select {
		case m := <-gotB:
			bMsg = m
			t.Logf("B received: %s", m)
		case m := <-gotC:
			cMsg = m
			t.Logf("C received: %s", m)
		case <-timeout:
			t.Fatalf("timeout: got B=%q C=%q", bMsg, cMsg)
		}
	}

	if bMsg != "hello network" {
		t.Errorf("B expected %q, got %q", "hello network", bMsg)
	}
	if cMsg != "hello network" {
		t.Errorf("C expected %q, got %q", "hello network", cMsg)
	}
}
