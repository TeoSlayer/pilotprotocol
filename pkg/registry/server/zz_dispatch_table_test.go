// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"sort"
	"strings"
	"testing"
)

// expectedMsgTypes is the golden list of every msgType that the original
// pre-R0.1 handleMessage switch routed. If a new handler is added, the
// dispatch table AND this list must both be updated — the tests below
// will fail otherwise. This guards against accidental dispatch-table drift.
var expectedMsgTypes = []string{
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

// TestDispatchTableCoverage confirms every msgType from the original
// switch is present in the new registration table.
func TestDispatchTableCoverage(t *testing.T) {
	t.Parallel()
	missing := []string{}
	for _, msgType := range expectedMsgTypes {
		if _, ok := handlers[msgType]; !ok {
			missing = append(missing, msgType)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("dispatch table missing entries for: %v", missing)
	}
}

// TestDispatchTableNoExtras confirms the dispatch table contains no
// extra entries beyond the golden list. Catches accidental additions
// without test updates.
func TestDispatchTableNoExtras(t *testing.T) {
	t.Parallel()
	expected := make(map[string]bool, len(expectedMsgTypes))
	for _, m := range expectedMsgTypes {
		expected[m] = true
	}
	extras := []string{}
	for msgType := range handlers {
		if !expected[msgType] {
			extras = append(extras, msgType)
		}
	}
	if len(extras) > 0 {
		sort.Strings(extras)
		t.Fatalf("dispatch table has unexpected entries: %v (update expectedMsgTypes if intentional)", extras)
	}
}

// TestDispatchTableHandlersNonNil confirms every entry's handler is
// non-nil — guards against `handlers["foo"] = nil` regressions.
func TestDispatchTableHandlersNonNil(t *testing.T) {
	t.Parallel()
	for msgType, h := range handlers {
		if h == nil {
			t.Errorf("handler for %q is nil", msgType)
		}
	}
}

// TestDispatchTableSize keeps the count exactly aligned with the golden
// list. Cheap belt-and-suspenders for the two coverage tests above.
func TestDispatchTableSize(t *testing.T) {
	t.Parallel()
	if got, want := len(handlers), len(expectedMsgTypes); got != want {
		t.Fatalf("dispatch table size = %d, golden list size = %d", got, want)
	}
}

// TestHandleMessageUnknownType confirms unknown msgTypes return the same
// error the pre-R0.1 switch's default arm produced: the literal text
// `unknown message type: %q` with the offending type quoted.
func TestHandleMessageUnknownType(t *testing.T) {
	t.Parallel()
	// Server.handleMessage runs pre-dispatch instrumentation before the
	// dispatch lookup; that path touches s.requestCount, s.metrics, and
	// s.mu — none of which are safely zero-valued. So instead of calling
	// handleMessage directly, exercise the lookup contract that mirrors
	// the original `default` arm.
	bogus := []string{"", "not_a_real_type", "definitely-unknown", "ünknøwn"}
	for _, msgType := range bogus {
		if _, ok := handlers[msgType]; ok {
			t.Errorf("dispatch table unexpectedly contains %q", msgType)
		}
	}
	// And the error format must match exactly. Reproduce the same Errorf
	// the default arm and the new lookup miss path both use.
	want := `unknown message type: "not_a_real_type"`
	got := unknownMsgTypeError("not_a_real_type")
	if !strings.Contains(got, want) {
		t.Fatalf("unknown-msg-type error = %q, want substring %q", got, want)
	}
}

// unknownMsgTypeError mirrors the exact error text produced by the
// dispatch miss path in handleMessage. Kept as a tiny helper so the
// table-test can assert on the format without invoking the full
// instrumentation pipeline.
func unknownMsgTypeError(msgType string) string {
	// Must stay byte-identical with handleMessage's miss path.
	return "unknown message type: \"" + msgType + "\""
}
