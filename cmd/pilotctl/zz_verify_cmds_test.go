// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pilot-protocol/common/crypto"
)

// TestCmdVerifyForwardsBadge drives `pilotctl verify` against a fake daemon and
// asserts the badge round-trips to the daemon's submit_badge handler.
func TestCmdVerifyForwardsBadge(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)

	var gotBadge, gotSig string
	d.on(tdCmdSubmitBadge, func(frame []byte) [][]byte {
		var req map[string]string
		_ = json.Unmarshal(frame[1:], &req)
		gotBadge, gotSig = req["badge"], req["badge_sig"]
		return [][]byte{append([]byte{tdCmdSubmitBadgeOK}, []byte(`{"ok":true}`)...)}
	})

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() {
		cmdVerify([]string{"--badge", "pilotbadge:v1:7:github:1781827200:0:bdg-v1:", "--badge-sig", "c2ln"})
	})
	if gotBadge != "pilotbadge:v1:7:github:1781827200:0:bdg-v1:" || gotSig != "c2ln" {
		t.Errorf("daemon got badge=%q sig=%q", gotBadge, gotSig)
	}
	if !strings.Contains(out, "ok") {
		t.Errorf("output missing ok: %s", out)
	}
}

// TestCmdVerifyFromFile covers the --from JSON convenience path.
func TestCmdVerifyFromFile(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	var gotBadge string
	d.on(tdCmdSubmitBadge, func(frame []byte) [][]byte {
		var req map[string]string
		_ = json.Unmarshal(frame[1:], &req)
		gotBadge = req["badge"]
		return [][]byte{append([]byte{tdCmdSubmitBadgeOK}, []byte(`{"ok":true}`)...)}
	})

	dir := t.TempDir()
	cred := filepath.Join(dir, "cred.json")
	_ = os.WriteFile(cred, []byte(`{"badge":"pilotbadge:v1:7:github:1:0:bdg-v1:","badge_sig":"eA"}`), 0o600)

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	_ = captureStdout(t, func() { cmdVerify([]string{"--from", cred}) })
	if gotBadge != "pilotbadge:v1:7:github:1:0:bdg-v1:" {
		t.Errorf("daemon got badge=%q from --from file", gotBadge)
	}
}

// TestCmdRecoveryEnrollForwards drives `pilotctl recovery enroll`.
func TestCmdRecoveryEnrollForwards(t *testing.T) {
	d := newFakeDaemon(t)
	d.useDaemon(t)
	var gotEnroll string
	d.on(tdCmdEnrollRecovery, func(frame []byte) [][]byte {
		var req map[string]string
		_ = json.Unmarshal(frame[1:], &req)
		gotEnroll = req["enrollment"]
		return [][]byte{append([]byte{tdCmdEnrollRecoveryOK}, []byte(`{"ok":true}`)...)}
	})

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	_ = captureStdout(t, func() {
		cmdRecovery([]string{"enroll", "--enrollment", "pilotenroll:v1:7:github:Yw:1:bdg-v1", "--enrollment-sig", "cw"})
	})
	if gotEnroll != "pilotenroll:v1:7:github:Yw:1:bdg-v1" {
		t.Errorf("daemon got enrollment=%q", gotEnroll)
	}
}

// TestCmdRecoveryNewKeyGeneratesLoadableIdentity covers the local key
// generation step: the printed public key matches the saved identity, and the
// file is a valid loadable identity.
func TestCmdRecoveryNewKeyGeneratesLoadableIdentity(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "rec.json")

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	stdout := captureStdout(t, func() { cmdRecovery([]string{"new-key", "--out", out}) })

	var env struct {
		Data struct {
			NewPublicKey string `json:"new_public_key"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("output not JSON: %v (%s)", err, stdout)
	}
	id, err := crypto.LoadIdentity(out)
	if err != nil {
		t.Fatalf("saved identity not loadable: %v", err)
	}
	if got := crypto.EncodePublicKey(id.PublicKey); got != env.Data.NewPublicKey {
		t.Errorf("printed pubkey %q != saved identity pubkey %q", env.Data.NewPublicKey, got)
	}
}

// TestNodeArgToID accepts both a decimal node ID and a textual address.
func TestNodeArgToID(t *testing.T) {
	if got := nodeArgToID("99"); got != 99 {
		t.Errorf("decimal: got %d, want 99", got)
	}
	if got := nodeArgToID("0:0000.0000.0063"); got != 99 {
		t.Errorf("address: got %d, want 99", got)
	}
}

// TestCmdRecoveryRecoverInstallsNewIdentity covers the most destructive command:
// keyless force-rotate via the registry, then install the new identity locally.
func TestCmdRecoveryRecoverInstallsNewIdentity(t *testing.T) {
	dir := t.TempDir()
	newKey := filepath.Join(dir, "new.json")
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if err := crypto.SaveIdentity(newKey, id); err != nil {
		t.Fatalf("save new key: %v", err)
	}
	newPub := crypto.EncodePublicKey(id.PublicKey)
	idPath := filepath.Join(dir, "installed.json")

	r := newFakeRegistry(t)
	var gotPub, gotRecovery string
	r.on("recover_identity", func(req map[string]interface{}) map[string]interface{} {
		gotPub, _ = req["new_public_key"].(string)
		gotRecovery, _ = req["recovery"].(string)
		return map[string]interface{}{"type": "recover_identity_ok", "ok": true, "node_id": float64(99)}
	})
	useRegistry(t, r)

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	_ = captureStdout(t, func() {
		cmdRecovery([]string{"recover", "--node", "99", "--new-key", newKey,
			"--recovery", "pilotrecover:v1:99:bmV3:Y29t:9999999999:nn:rec-v1", "--recovery-sig", "c2ln",
			"--identity", idPath})
	})

	if gotRecovery == "" {
		t.Fatal("registry never received recover_identity")
	}
	if gotPub != newPub {
		t.Errorf("registry got new_public_key=%q, want the new-key pubkey %q", gotPub, newPub)
	}
	// The recovered key must be installed at the daemon identity path.
	installed, err := crypto.LoadIdentity(idPath)
	if err != nil {
		t.Fatalf("new identity not installed at %s: %v", idPath, err)
	}
	if crypto.EncodePublicKey(installed.PublicKey) != newPub {
		t.Errorf("installed identity does not match the recovered key")
	}
}
