package tests

import (
	"sync"
	"testing"
	"time"

	"web4/pkg/protocol"
	"web4/pkg/registry"
)

func TestBroadcast(t *testing.T) {
	t.Skip("custom networks are WIP")
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon()
	b := env.AddDaemon()
	c := env.AddDaemon()

	// Create a network and join all 3
	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("registry dial: %v", err)
	}
	defer rc.Close()

	resp, err := rc.CreateNetwork(a.Daemon.NodeID(), "test-topic", "open", "", env.AdminToken)
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
	bcastAddr := protocol.BroadcastAddr(netID)
	if err := a.Driver.SendTo(bcastAddr, 5000, []byte("hello network")); err != nil {
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
