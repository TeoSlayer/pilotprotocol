// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"encoding/json"
	"net"
	"sync"
	"testing"

	"github.com/pilot-protocol/common/ipcutil"
	registry "github.com/pilot-protocol/common/registry/client"
)

// startFakeRegistry stands up an in-process TCP listener that speaks the
// registry's JSON-over-framed-IPC protocol. The respond callback receives
// each request map and returns the response map. The returned client is
// dialed through the standard registry.Dial path so it exercises the same
// connection lifecycle as a real daemon.
//
// This helper was originally defined alongside the cycle/fetchmembers
// tests; those tests were removed when their referenced symbols moved to
// plugins/handshake (T3.3) and plugins/policy (T2.3). The helper itself
// is still consumed by handshake_dispatch_test.go and a few daemon-side
// info/wire tests, so we keep it here in a dedicated _test.go.
func startFakeRegistry(t *testing.T, respond func(req map[string]interface{}) map[string]interface{}) (*registry.Client, func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var (
		wg     sync.WaitGroup
		quit   = make(chan struct{})
		quitMu sync.Mutex
		closed bool
	)

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				for {
					raw, err := ipcutil.Read(c)
					if err != nil {
						return
					}
					var req map[string]interface{}
					if err := json.Unmarshal(raw, &req); err != nil {
						return
					}
					resp := respond(req)
					if resp == nil {
						resp = map[string]interface{}{}
					}
					// common@v0.4.7 (PILOT-132) rejects any non-empty
					// registry response that lacks a "type" envelope
					// field. The fake-registry callbacks predate that
					// requirement and rarely set "type" explicitly;
					// inject a default so we don't have to update every
					// single test. Tests that exercise a specific type
					// (e.g. error envelopes) still win — we only fill
					// the field when the callback didn't.
					if len(resp) > 0 {
						if _, hasType := resp["type"]; !hasType {
							resp["type"] = "response"
						}
					}
					out, _ := json.Marshal(resp)
					if err := ipcutil.Write(c, out); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	client, err := registry.Dial(lis.Addr().String())
	if err != nil {
		lis.Close()
		t.Fatalf("dial fake registry: %v", err)
	}

	// Configure a no-op test signer. After PILOT-128 the registry client
	// refuses to send any signed request when no signer is set. The fake
	// registry doesn't verify signatures, so any non-empty string suffices.
	// Tests that need the no-signer error path should call client.SetSigner(nil).
	client.SetSigner(func(challenge string) string {
		return "test-sig:" + challenge
	})

	cleanup := func() {
		quitMu.Lock()
		if closed {
			quitMu.Unlock()
			return
		}
		closed = true
		close(quit)
		quitMu.Unlock()
		client.Close()
		lis.Close()
		wg.Wait()
	}
	return client, cleanup
}
