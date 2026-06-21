// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"os"

	"github.com/pilot-protocol/common/crypto"
	"github.com/pilot-protocol/common/protocol"
	registry "github.com/pilot-protocol/common/registry/client"
)

// loadJSONFile reads a small JSON credential file into v, exiting on error.
func loadJSONFile(path string, v interface{}) {
	data, err := os.ReadFile(path)
	if err != nil {
		fatalCode("invalid_argument", "read %s: %v", path, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		fatalCode("invalid_argument", "parse %s: %v", path, err)
	}
}

// nodeArgToID accepts either a textual Pilot address (N:NNNN.HHHH.LLLL) or a
// decimal node ID and returns the 32-bit node ID.
func nodeArgToID(s string) uint32 {
	if addr, err := protocol.ParseAddr(s); err == nil {
		return addr.Node
	}
	return parseNodeID(s)
}

// cmdVerify attaches a verified-address badge to this node. The badge and its
// issuer signature are produced by the verifier (`pilot-verify verify`); this
// command hands them to the daemon, which proves ownership with the node key
// and submits to the registry.
//
//	pilotctl verify --badge <badge> --badge-sig <sig>
//	pilotctl verify --from cred.json        # {"badge":..,"badge_sig":..}
func cmdVerify(args []string) {
	flags, _ := parseFlags(args)
	badge := flagString(flags, "badge", "")
	badgeSig := flagString(flags, "badge-sig", "")
	if from := flagString(flags, "from", ""); from != "" {
		var m struct {
			Badge    string `json:"badge"`
			BadgeSig string `json:"badge_sig"`
		}
		loadJSONFile(from, &m)
		if badge == "" {
			badge = m.Badge
		}
		if badgeSig == "" {
			badgeSig = m.BadgeSig
		}
	}
	if badge == "" || badgeSig == "" {
		fatalCode("invalid_argument",
			"usage: pilotctl verify --badge <badge> --badge-sig <sig>  (or --from cred.json)")
	}
	d := connectDriver()
	defer d.Close()
	resp, err := d.SubmitBadge(badge, badgeSig)
	if err != nil {
		fatalCode("connection_failed", "verify: %v", err)
	}
	output(resp)
}

// cmdRecovery dispatches the recovery subcommands.
func cmdRecovery(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl recovery <enroll|new-key|recover> ...")
	}
	switch args[0] {
	case "enroll":
		cmdRecoveryEnroll(args[1:])
	case "new-key":
		cmdRecoveryNewKey(args[1:])
	case "recover":
		cmdRecoveryRecover(args[1:])
	default:
		fatalCode("invalid_argument", "unknown recovery subcommand %q (want enroll|new-key|recover)", args[0])
	}
}

// cmdRecoveryEnroll records this node's opaque recovery commitment so the
// address can be recovered later if the key is lost. The enrollment + signature
// come from `pilot-verify enroll`.
//
//	pilotctl recovery enroll --enrollment <e> --enrollment-sig <sig>
//	pilotctl recovery enroll --from enroll.json
func cmdRecoveryEnroll(args []string) {
	flags, _ := parseFlags(args)
	enrollment := flagString(flags, "enrollment", "")
	enrollSig := flagString(flags, "enrollment-sig", "")
	if from := flagString(flags, "from", ""); from != "" {
		var m struct {
			Enrollment    string `json:"enrollment"`
			EnrollmentSig string `json:"enrollment_sig"`
		}
		loadJSONFile(from, &m)
		if enrollment == "" {
			enrollment = m.Enrollment
		}
		if enrollSig == "" {
			enrollSig = m.EnrollmentSig
		}
	}
	if enrollment == "" || enrollSig == "" {
		fatalCode("invalid_argument",
			"usage: pilotctl recovery enroll --enrollment <e> --enrollment-sig <sig>  (or --from enroll.json)")
	}
	d := connectDriver()
	defer d.Close()
	resp, err := d.EnrollRecovery(enrollment, enrollSig)
	if err != nil {
		fatalCode("connection_failed", "recovery enroll: %v", err)
	}
	output(resp)
}

// cmdRecoveryNewKey generates a fresh keypair for an address that is being
// recovered and prints its public key. The custodian of the cold recovery key
// signs an authorization binding this public key; `pilotctl recovery recover`
// then submits it. The private key stays local in --out.
//
//	pilotctl recovery new-key [--out <path>]
func cmdRecoveryNewKey(args []string) {
	flags, _ := parseFlags(args)
	out := flagString(flags, "out", configDir()+"/recovery-identity.json")
	id, err := crypto.GenerateIdentity()
	if err != nil {
		fatalCode("internal_error", "recovery new-key: generate: %v", err)
	}
	if err := crypto.SaveIdentity(out, id); err != nil {
		fatalCode("internal_error", "recovery new-key: save %s: %v", out, err)
	}
	output(map[string]interface{}{
		"new_identity_path": out,
		"new_public_key":    crypto.EncodePublicKey(id.PublicKey),
		"next": "give new_public_key and your node address to the recovery-key custodian; " +
			"they return a recovery authorization for `pilotctl recovery recover`",
	})
}

// cmdRecoveryRecover force-rotates a lost address to the new key created by
// `recovery new-key`, using a cold-key-signed authorization. No current key is
// required — that is the point of recovery. On success the new identity is
// installed at the daemon identity path; restart the daemon to adopt it.
//
//	pilotctl recovery recover --node <addr|id> --new-key <path> \
//	    --recovery <auth> --recovery-sig <sig> [--from recover.json] \
//	    [--identity <path>] [--registry host:port]
func cmdRecoveryRecover(args []string) {
	flags, _ := parseFlags(args)
	nodeArg := flagString(flags, "node", "")
	recovery := flagString(flags, "recovery", "")
	recoverySig := flagString(flags, "recovery-sig", "")
	newKeyPath := flagString(flags, "new-key", "")
	if from := flagString(flags, "from", ""); from != "" {
		var m struct {
			Recovery    string `json:"recovery"`
			RecoverySig string `json:"recovery_sig"`
		}
		loadJSONFile(from, &m)
		if recovery == "" {
			recovery = m.Recovery
		}
		if recoverySig == "" {
			recoverySig = m.RecoverySig
		}
	}
	if nodeArg == "" || recovery == "" || recoverySig == "" || newKeyPath == "" {
		fatalCode("invalid_argument",
			"usage: pilotctl recovery recover --node <addr|id> --new-key <path> --recovery <auth> --recovery-sig <sig>")
	}
	nodeID := nodeArgToID(nodeArg)
	id, err := crypto.LoadIdentity(newKeyPath)
	if err != nil {
		fatalCode("invalid_argument", "recovery recover: load new key %s: %v", newKeyPath, err)
	}
	newPub := crypto.EncodePublicKey(id.PublicKey)

	addr := flagString(flags, "registry", getRegistry())
	rc, err := registry.Dial(addr)
	if err != nil {
		fatalCode("connection_failed", "recovery recover: cannot reach registry at %s: %v", addr, err)
	}
	defer rc.Close()

	resp, err := rc.RecoverIdentity(nodeID, recovery, recoverySig, newPub)
	if err != nil {
		fatalCode("permission_denied", "recovery recover: %v", err)
	}

	// The registry rotated the address to the new key; install it locally so
	// the daemon can authenticate as the recovered node after a restart.
	idPath := flagString(flags, "identity", configDir()+"/identity.json")
	if err := crypto.SaveIdentity(idPath, id); err != nil {
		fatalCode("internal_error",
			"recovery recover: registry rotated key but installing new identity at %s failed: %v", idPath, err)
	}
	output(map[string]interface{}{
		"recovered":      true,
		"node_id":        nodeID,
		"new_public_key": newPub,
		"identity_path":  idPath,
		"next":           "restart the daemon so it authenticates with the recovered key",
		"registry":       resp,
	})
}
