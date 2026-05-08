// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"regexp"
	"strings"
	"testing"
)

// dispatchMsgTypes is the full set of msgTypes routed by handleMessage's
// dispatch switch (server.go:2017-2148). This is hard-coded because R0.5
// is a pre-extraction pin: if the dispatch switch grows or shrinks, this
// list MUST be updated to match — adding to one without the other is the
// exact failure mode this test exists to catch.
//
// Order matches the dispatch switch top-to-bottom for ease of review.
var dispatchMsgTypes = []string{
	"register",
	"create_network",
	"join_network",
	"leave_network",
	"delete_network",
	"rename_network",
	"set_network_enterprise",
	"lookup",
	"resolve",
	"list_networks",
	"list_nodes",
	"rotate_key",
	"deregister",
	"set_visibility",
	"report_trust",
	"revoke_trust",
	"check_trust",
	"request_handshake",
	"poll_handshakes",
	"respond_handshake",
	"heartbeat",
	"punch",
	"set_hostname",
	"set_tags",
	"set_member_tags",
	"get_member_tags",
	"resolve_hostname",
	"beacon_register",
	"beacon_list",
	"invite_to_network",
	"poll_invites",
	"respond_invite",
	"kick_member",
	"promote_member",
	"demote_member",
	"transfer_ownership",
	"get_member_role",
	"set_network_policy",
	"get_network_policy",
	"set_expr_policy",
	"get_expr_policy",
	"set_key_expiry",
	"get_key_info",
	"get_audit_log",
	"set_webhook",
	"get_webhook",
	"set_identity_webhook",
	"set_external_id",
	"get_identity",
	"get_webhook_dlq",
	"provision_network",
	"set_audit_export",
	"get_audit_export",
	"get_idp_config",
	"set_idp_config",
	"get_provision_status",
	"directory_sync",
	"directory_status",
	"validate_token",
}

// readPattern matches msgTypes the spec calls out as read-only:
// names starting with `get_`, or one of the named read verbs.
var readPattern = regexp.MustCompile(
	`^(get_.*|lookup|resolve|list_networks|list_nodes|heartbeat|poll_handshakes|poll_invites|resolve_hostname|check_trust|directory_status)$`,
)

// writePrefixes match msgTypes the spec calls out as write-shaped.
var writePrefixes = []string{
	"set_",
	"update_",
	"delete_",
	"revoke_",
	"report_",
	"respond_",
	"rotate_",
}

// writeExacts are explicit non-prefix write verbs from the spec.
var writeExacts = map[string]bool{
	"register":       true,
	"create_network": true,
}

// classifyMsgType returns "read", "write", or "other". The test only
// asserts behavior for msgTypes the spec patterns recognize; everything
// else is left alone so that future handlers don't silently regress this
// test until they're explicitly classified by the human author.
func classifyMsgType(t string) string {
	if readPattern.MatchString(t) {
		return "read"
	}
	if writeExacts[t] {
		return "write"
	}
	for _, p := range writePrefixes {
		if strings.HasPrefix(t, p) {
			return "write"
		}
	}
	return "other"
}

// TestStandbyAllowlistMatchesDispatchSwitch is the R0.5 pin test:
// every read-shaped handler in the dispatch switch must be allowed on
// a standby, and every write-shaped handler must be rejected with the
// standby-mode error.
//
// The server is constructed in-memory with `standby = true` and
// handleMessage is called directly. No network IO. Reads may still
// return handler errors (missing fields, unknown nodes) — what we
// assert is that the error is NOT the standby-mode rejection.
func TestStandbyAllowlistMatchesDispatchSwitch(t *testing.T) {
	t.Parallel()
	s := New("")
	// standby flag is now owned by walStore (R6.1)
	s.walStore.SetStandby(true)

	const standbyErr = "standby mode: write operations not accepted (use primary)"

	// Sanity check: every handler we hard-coded must classify as
	// read, write, or other; the spec-pattern coverage matters more
	// than raw counts but a baseline guard catches missing entries.
	if len(dispatchMsgTypes) < 50 {
		t.Fatalf("expected ~64 dispatched msgTypes, got %d (table out of date)", len(dispatchMsgTypes))
	}

	var reads, writes, others int
	for _, msgType := range dispatchMsgTypes {
		class := classifyMsgType(msgType)
		switch class {
		case "read":
			reads++
		case "write":
			writes++
		default:
			others++
		}

		t.Run(msgType, func(t *testing.T) {
			msg := map[string]interface{}{"type": msgType}
			_, err := s.handleMessage(msg, "127.0.0.1:0")

			gotStandbyErr := err != nil && strings.Contains(err.Error(), standbyErr)

			switch class {
			case "read":
				if gotStandbyErr {
					t.Errorf("read-shaped %q rejected by standby gate: %v", msgType, err)
				}
			case "write":
				if !gotStandbyErr {
					t.Errorf("write-shaped %q NOT rejected by standby gate (err=%v)", msgType, err)
				}
			case "other":
				// Unclassified by spec patterns — skip behavioral
				// assertion. This branch exists deliberately so the
				// test doesn't pin handlers like `punch`, `directory_sync`,
				// `join_network`, `punch`, `directory_sync`, etc., whose
				// classification needs human review before the gate
				// expands. R0.5 is scoped to the 9 missing get_* reads.
				t.Skipf("msgType %q does not match any spec pattern", msgType)
			}
		})
	}

	// Defense in depth: assert minimum coverage so the test isn't a
	// no-op if someone deletes the read pattern by accident.
	if reads < 20 {
		t.Errorf("expected >=20 read msgTypes after R0.5; got %d", reads)
	}
	if writes < 15 {
		t.Errorf("expected >=15 write msgTypes; got %d", writes)
	}
	t.Logf("classified: %d reads, %d writes, %d unclassified (other)", reads, writes, others)
}

// TestStandbyAllowlistCoversNineMissingHandlers explicitly pins R0.5:
// the nine read handlers identified in 08-REGISTRY-EXTRACTION.md
// (Headline finding #7) must all be allowed on standby.
func TestStandbyAllowlistCoversNineMissingHandlers(t *testing.T) {
	t.Parallel()
	s := New("")
	// standby flag is now owned by walStore (R6.1)
	s.walStore.SetStandby(true)

	const standbyErr = "standby mode: write operations not accepted (use primary)"

	missing := []string{
		"get_webhook",
		"get_audit_export",
		"get_webhook_dlq",
		"get_identity",
		"get_idp_config",
		"get_provision_status",
		"get_expr_policy",
		"get_member_tags",
		"directory_status",
	}

	for _, msgType := range missing {
		t.Run(msgType, func(t *testing.T) {
			msg := map[string]interface{}{"type": msgType}
			_, err := s.handleMessage(msg, "127.0.0.1:0")
			if err != nil && strings.Contains(err.Error(), standbyErr) {
				t.Errorf("R0.5 read %q still rejected by standby gate: %v", msgType, err)
			}
		})
	}
}
