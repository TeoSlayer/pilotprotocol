// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

// dashRegisterNode is shared test scaffolding. Used by zz_tags_test.go
// (default-tag) so it lives in a default-tag helper file; originally
// defined in zz_dashboard_test.go which got tagged //go:build nightly
// to keep the dashboard-endpoint integration suite out of PR CI.

import (
	"testing"

	registryclient "github.com/TeoSlayer/pilotprotocol/pkg/registry/client"
	icrypto "github.com/pilot-protocol/common/crypto"
)

func dashRegisterNode(t *testing.T, addr, hostname string) {
	t.Helper()
	ident, err := icrypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	rc, err := registryclient.Dial(addr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()

	msg := map[string]interface{}{
		"type":        "register",
		"listen_addr": "127.0.0.1:4000",
		"public_key":  icrypto.EncodePublicKey(ident.PublicKey),
	}
	if hostname != "" {
		msg["hostname"] = hostname
	}

	resp, err := rc.Send(msg)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if resp["type"] != "register_ok" {
		t.Fatalf("expected register_ok, got %v", resp["type"])
	}
}
