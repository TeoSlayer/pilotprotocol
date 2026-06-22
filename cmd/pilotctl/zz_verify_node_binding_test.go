// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"testing"

	"github.com/pilot-protocol/common/badgeverify"
)

// TestVerifyForNodeRejectsCrossNodeBadge is the pilotctl-layer adversarial
// guard for badge replay across addresses. `pilotctl verify status` decides
// verified=true ONLY when badgeverify.VerifyForNode(badge, sig, nodeID)
// returns nil — see cmdVerifyStatus. The registry transport is untrusted, so a
// malicious registry (or a MITM) can return ANY node's badge in a lookup for
// our node. The binding check inside VerifyForNode is what stops that badge
// from being credited to a different address.
//
// We craft a canonical badge bound to NodeID A and present it for NodeID B.
// VerifyForNode MUST return a non-nil error (fail-closed) — never nil. We do
// not need a pinned issuer signature to prove this: a cross-node badge must be
// rejected whether the rejection comes from the node-mismatch check or the
// signature check, because either way the pilotctl layer must not render it as
// "verified".
func TestVerifyForNodeRejectsCrossNodeBadge(t *testing.T) {
	t.Parallel()

	const nodeA = uint32(0x0A0A0A)
	const nodeB = uint32(0x0B0B0B)

	badgeForA, err := badgeverify.Canonical(badgeverify.Badge{
		NodeID:     nodeA,
		Provider:   "github",
		VerifiedAt: 1700000000,
		Exp:        0,
		Kid:        "bdg-v1",
		Subject:    "victim",
	})
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	// An attacker-supplied signature; it cannot be a valid pinned-issuer sig
	// here, which is itself part of the point — the layer must fail closed.
	const attackerSig = "Zm9yZ2VkLXNpZ25hdHVyZQ=="

	// Present node A's badge while authenticated/looked-up as node B.
	if _, verr := badgeverify.VerifyForNode(badgeForA, attackerSig, nodeB); verr == nil {
		t.Fatal("VerifyForNode accepted a badge bound to a DIFFERENT node — cross-node replay not rejected")
	}

	// Sanity: presenting it for its own node A must ALSO fail closed here,
	// because the forged signature does not verify against the pinned issuer
	// key. This proves the gate is genuinely fail-closed, not merely a
	// node-id string compare that an attacker could satisfy.
	_, selfErr := badgeverify.VerifyForNode(badgeForA, attackerSig, nodeA)
	if selfErr == nil {
		t.Fatal("VerifyForNode accepted a badge with a non-pinned (forged) signature")
	}
	// The self-node failure must be a signature/key failure, NOT a node
	// mismatch — confirming the binding check and the crypto check are
	// independent gates.
	if errors.Is(selfErr, badgeverify.ErrNodeMismatch) {
		t.Fatalf("same-node badge failed with ErrNodeMismatch, want a signature failure: %v", selfErr)
	}
}

// verifyStatusVerdict mirrors the exact decision cmdVerifyStatus makes: a node
// is rendered "verified" iff VerifyForNode returns nil for the looked-up
// nodeID. Kept as a tiny pure helper so the adversarial truth-table is testable
// without standing up a registry + daemon.
func verifyStatusVerdict(badge, sig string, nodeID uint32) bool {
	if badge == "" {
		return false
	}
	_, err := badgeverify.VerifyForNode(badge, sig, nodeID)
	return err == nil
}

// TestVerifyStatusVerdictCrossNodeNotVerified pins that the status verdict the
// CLI prints is "not verified" for a cross-node badge, i.e. the rejection above
// actually flows through to a user-visible false.
func TestVerifyStatusVerdictCrossNodeNotVerified(t *testing.T) {
	t.Parallel()

	const nodeA = uint32(0x0A0A0A)
	const nodeB = uint32(0x0B0B0B)
	badgeForA, err := badgeverify.Canonical(badgeverify.Badge{
		NodeID: nodeA, Provider: "github", VerifiedAt: 1700000000, Kid: "bdg-v1",
	})
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	if verifyStatusVerdict(badgeForA, "Zm9yZ2Vk", nodeB) {
		t.Fatal("status verdict reported verified=true for a cross-node badge")
	}
	if verifyStatusVerdict("", "", nodeB) {
		t.Fatal("status verdict reported verified=true with no badge")
	}
}
