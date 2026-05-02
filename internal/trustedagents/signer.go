// SPDX-License-Identifier: AGPL-3.0-or-later

// Package trustedagents distributes a signed list of well-known agent
// pubkeys whose handshake requests the daemon may auto-accept. The list is
// signed offline by an Ed25519 key whose public half is baked into the
// daemon binary as SignerPublicKey — that way GitHub (or any other
// distribution channel) can be compromised without an attacker being able
// to forge the list.
//
// Adding a new trusted agent: edit trusted-agents.json, bump version,
// re-sign with the offline private key (kept off the build machine) using
// `pilotctl trusted sign`, commit both files. Daemons in the field pick
// up the new list within the fetch interval (~1h) without needing an
// upgrade. Brand-new daemons get the list embedded at build time so the
// feature works on first boot, even airgapped.
package trustedagents

// SignerPublicKey is the Ed25519 public key (base64) corresponding to the
// offline private key that signs trusted-agents.json. The matching
// private half MUST be kept off any build machine and rotated only via a
// coordinated release. Bootstrapped 2026-05-02; private half is at
// ~/.pilot/trusted-agents-signer.key on the bootstrap operator's machine.
const SignerPublicKey = "asDz7xZo0/22MJdRMlWO6/uoL/e+W8R1H1VhGwALhyA="
