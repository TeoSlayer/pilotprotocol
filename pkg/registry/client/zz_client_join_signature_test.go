// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// echoOnlyClient dials a fakeJSONServer with echoHandler and returns a
// connected Client plus the server so test bodies can assert wire payloads.
func echoOnlyClient(t *testing.T) (*Client, *fakeJSONServer) {
	t.Helper()
	srv := newFakeJSONServer(t, echoHandler())
	c, err := Dial(srv.addr())
	if err != nil {
		srv.close()
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { c.Close(); srv.close() })
	return c, srv
}

// assertEcho fetches the echoed request payload that the fake server round-tripped.
func assertEcho(t *testing.T, resp map[string]interface{}) map[string]interface{} {
	t.Helper()
	echo, ok := resp["echo"].(map[string]interface{})
	if !ok {
		t.Fatalf("response missing echo key: %+v", resp)
	}
	return echo
}

// --- JoinNetwork / LeaveNetwork : signature wins over admin_token --------

func TestJoinNetworkSignaturePreferredOverAdminToken(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	c.SetSigner(func(ch string) string { return "SIG:" + ch })

	resp, err := c.JoinNetwork(11, 3, "tok", 4, "ADMIN_SHOULD_BE_IGNORED")
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	echo := assertEcho(t, resp)
	if got, _ := echo["type"].(string); got != "join_network" {
		t.Fatalf("type: %q", got)
	}
	if got, _ := echo["signature"].(string); got != "SIG:join_network:11:3" {
		t.Fatalf("signature: %q", got)
	}
	if _, ok := echo["admin_token"]; ok {
		t.Fatalf("admin_token should be omitted when signature present")
	}
}

func TestJoinNetworkFallsBackToAdminTokenWithoutSigner(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	resp, err := c.JoinNetwork(11, 3, "tok", 4, "ADM")
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	echo := assertEcho(t, resp)
	if _, ok := echo["signature"]; ok {
		t.Fatalf("signature should be absent with no signer")
	}
	if got, _ := echo["admin_token"].(string); got != "ADM" {
		t.Fatalf("admin_token: %q", got)
	}
	if got, _ := echo["inviter_id"].(float64); uint32(got) != 4 {
		t.Fatalf("inviter_id: %v", got)
	}
}

func TestLeaveNetworkSignatureOrAdminToken(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	// Signer wins.
	c.SetSigner(func(ch string) string { return "SIG:" + ch })
	resp, _ := c.LeaveNetwork(5, 2, "ADMIN")
	echo := assertEcho(t, resp)
	if got, _ := echo["signature"].(string); got != "SIG:leave_network:5:2" {
		t.Fatalf("signature: %q", got)
	}
	if _, ok := echo["admin_token"]; ok {
		t.Fatalf("admin_token should be omitted when sig present")
	}
	// Drop signer → admin_token fallback.
	c.SetSigner(nil)
	resp, _ = c.LeaveNetwork(5, 2, "ADMIN")
	echo = assertEcho(t, resp)
	if got, _ := echo["admin_token"].(string); got != "ADMIN" {
		t.Fatalf("admin_token fallback: %q", got)
	}
}

// --- DeleteNetwork / RenameNetwork : variadic node_id --------------------

func TestDeleteNetworkVariadicNodeIDAndAdminToken(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	// No nodeID, no adminToken.
	resp, _ := c.DeleteNetwork(3, "")
	echo := assertEcho(t, resp)
	if _, ok := echo["node_id"]; ok {
		t.Fatalf("node_id should be omitted when not passed")
	}
	if _, ok := echo["admin_token"]; ok {
		t.Fatalf("admin_token should be omitted when blank")
	}
	// With both.
	resp, _ = c.DeleteNetwork(3, "ADM", 77)
	echo = assertEcho(t, resp)
	if got, _ := echo["node_id"].(float64); uint32(got) != 77 {
		t.Fatalf("node_id: %v", got)
	}
	if got, _ := echo["admin_token"].(string); got != "ADM" {
		t.Fatalf("admin_token: %q", got)
	}
	// Explicit 0 node_id → still omitted.
	resp, _ = c.DeleteNetwork(3, "ADM", 0)
	echo = assertEcho(t, resp)
	if _, ok := echo["node_id"]; ok {
		t.Fatalf("node_id=0 should be omitted (matches client logic)")
	}
}

func TestRenameNetworkPassesName(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	resp, _ := c.RenameNetwork(1, "shiny", "ADM", 9)
	echo := assertEcho(t, resp)
	if got, _ := echo["name"].(string); got != "shiny" {
		t.Fatalf("name: %q", got)
	}
	if got, _ := echo["node_id"].(float64); uint32(got) != 9 {
		t.Fatalf("node_id: %v", got)
	}
}

// --- ListNetworks / ListNodes / SetNetworkEnterprise --------------------

func TestListNetworksBareType(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	resp, _ := c.ListNetworks()
	echo := assertEcho(t, resp)
	if got, _ := echo["type"].(string); got != "list_networks" {
		t.Fatalf("type: %q", got)
	}
}

func TestListNodesAdminTokenOptional(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	// Without admin token.
	resp, _ := c.ListNodes(42)
	echo := assertEcho(t, resp)
	if _, ok := echo["admin_token"]; ok {
		t.Fatalf("admin_token should be omitted when not supplied")
	}
	// With admin token.
	resp, _ = c.ListNodes(42, "ADM")
	echo = assertEcho(t, resp)
	if got, _ := echo["admin_token"].(string); got != "ADM" {
		t.Fatalf("admin_token: %q", got)
	}
}

func TestSetNetworkEnterpriseSerializesBool(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	resp, _ := c.SetNetworkEnterprise(7, true, "ADM")
	echo := assertEcho(t, resp)
	if got, _ := echo["enterprise"].(bool); !got {
		t.Fatalf("enterprise should be true")
	}
	if got, _ := echo["admin_token"].(string); got != "ADM" {
		t.Fatalf("admin_token: %q", got)
	}
}

// --- Signed thin wrappers: Deregister / Heartbeat / Punch ----------------

func TestSignedWrappersIncludeCorrectChallenge(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		call   func(c *Client) (map[string]interface{}, error)
		expect string
	}{
		{"deregister", func(c *Client) (map[string]interface{}, error) { return c.Deregister(42) }, "deregister:42"},
		{"heartbeat", func(c *Client) (map[string]interface{}, error) { return c.Heartbeat(42) }, "heartbeat:42"},
		{"punch", func(c *Client) (map[string]interface{}, error) { return c.Punch(1, 42, 43) }, "punch:42:43"},
		{"poll_handshakes", func(c *Client) (map[string]interface{}, error) { return c.PollHandshakes(42) }, "poll_handshakes:42"},
		{"set_hostname", func(c *Client) (map[string]interface{}, error) { return c.SetHostname(42, "h") }, "set_hostname:42"},
		{"set_tags", func(c *Client) (map[string]interface{}, error) { return c.SetTags(42, []string{"a"}) }, "set_tags:42"},
		{"poll_invites", func(c *Client) (map[string]interface{}, error) { return c.PollInvites(42) }, "poll_invites:42"},
		{"set_key_expiry", func(c *Client) (map[string]interface{}, error) { return c.SetKeyExpiry(42, time.Unix(0, 0).UTC()) }, "set_key_expiry:42"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := echoOnlyClient(t)
			c.SetSigner(func(ch string) string { return "SIG:" + ch })
			resp, err := tc.call(c)
			if err != nil {
				t.Fatalf("call: %v", err)
			}
			echo := assertEcho(t, resp)
			if got, _ := echo["signature"].(string); got != "SIG:"+tc.expect {
				t.Fatalf("signature: want SIG:%s, got %q", tc.expect, got)
			}
		})
	}
}

func TestSetKeyExpiryFormatsRFC3339(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	c.SetSigner(func(ch string) string { return "SIG:" + ch })
	moment := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	resp, _ := c.SetKeyExpiry(9, moment)
	echo := assertEcho(t, resp)
	if got, _ := echo["expires_at"].(string); got != "2030-01-02T03:04:05Z" {
		t.Fatalf("expires_at: %q", got)
	}
}

// --- RequestHandshake / RespondHandshake (caller-supplied signature) -----

func TestRequestAndRespondHandshakePassThroughSignature(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	resp, _ := c.RequestHandshake(1, 2, "please", "SIG_REQ")
	echo := assertEcho(t, resp)
	if got, _ := echo["signature"].(string); got != "SIG_REQ" {
		t.Fatalf("req signature: %q", got)
	}
	if got, _ := echo["justification"].(string); got != "please" {
		t.Fatalf("justification: %q", got)
	}

	resp, _ = c.RespondHandshake(3, 4, true, "SIG_RESP")
	echo = assertEcho(t, resp)
	if got, _ := echo["accept"].(bool); !got {
		t.Fatalf("accept: %v", got)
	}
	if got, _ := echo["signature"].(string); got != "SIG_RESP" {
		t.Fatalf("resp signature: %q", got)
	}

	// Blank signature omitted.
	resp, _ = c.RespondHandshake(3, 4, false, "")
	echo = assertEcho(t, resp)
	if _, ok := echo["signature"]; ok {
		t.Fatalf("signature should be omitted when blank")
	}
}

// --- ResolveHostname / ResolveHostnameAs / CheckTrust --------------------

func TestResolveHostnameBothForms(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	resp, _ := c.ResolveHostname("alpha")
	echo := assertEcho(t, resp)
	if got, _ := echo["hostname"].(string); got != "alpha" {
		t.Fatalf("hostname: %q", got)
	}
	if _, ok := echo["requester_id"]; ok {
		t.Fatalf("requester_id should be absent")
	}

	resp, _ = c.ResolveHostnameAs(99, "beta")
	echo = assertEcho(t, resp)
	if got, _ := echo["requester_id"].(float64); uint32(got) != 99 {
		t.Fatalf("requester_id: %v", got)
	}
}

func TestCheckTrustReturnsTypedBool(t *testing.T) {
	t.Parallel()
	srv := newFakeJSONServer(t, func(_ map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"type": "ok", "trusted": true}
	})
	defer srv.close()
	c, _ := Dial(srv.addr())
	defer c.Close()

	trusted, err := c.CheckTrust(1, 2)
	if err != nil {
		t.Fatalf("check trust: %v", err)
	}
	if !trusted {
		t.Fatalf("expected trusted=true")
	}
}

func TestCheckTrustPropagatesError(t *testing.T) {
	t.Parallel()
	srv := newFakeJSONServer(t, func(_ map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"error": "forbidden"}
	})
	defer srv.close()
	c, _ := Dial(srv.addr())
	defer c.Close()

	trusted, err := c.CheckTrust(1, 2)
	if err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("expected forbidden error, got %v", err)
	}
	if trusted {
		t.Fatalf("expected trusted=false on error")
	}
}

// --- Invite family --------------------------------------------------------

func TestInviteToNetworkSigAndAdminBothAllowed(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	c.SetSigner(func(ch string) string { return "SIG:" + ch })
	// Both signature AND admin_token are included (logic uses two independent ifs).
	resp, _ := c.InviteToNetwork(3, 1, 2, "ADM")
	echo := assertEcho(t, resp)
	if got, _ := echo["signature"].(string); got != "SIG:invite:1:3:2" {
		t.Fatalf("signature: %q", got)
	}
	if got, _ := echo["admin_token"].(string); got != "ADM" {
		t.Fatalf("admin_token: %q", got)
	}
}

func TestRespondInvitePassesAccept(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	c.SetSigner(func(ch string) string { return "SIG:" + ch })
	resp, _ := c.RespondInvite(5, 9, false)
	echo := assertEcho(t, resp)
	if got, _ := echo["accept"].(bool); got {
		t.Fatalf("accept: %v", got)
	}
	if got, _ := echo["signature"].(string); got != "SIG:respond_invite:5:9" {
		t.Fatalf("signature: %q", got)
	}
}

// --- Member role operations ---------------------------------------------

func TestMemberRoleOpsOmitBlankAdmin(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	ops := map[string]func() (map[string]interface{}, error){
		"promote_member":     func() (map[string]interface{}, error) { return c.PromoteMember(1, 2, 3, "") },
		"demote_member":      func() (map[string]interface{}, error) { return c.DemoteMember(1, 2, 3, "") },
		"kick_member":        func() (map[string]interface{}, error) { return c.KickMember(1, 2, 3, "") },
		"transfer_ownership": func() (map[string]interface{}, error) { return c.TransferOwnership(1, 2, 3, "") },
	}
	for name, op := range ops {
		resp, err := op()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		echo := assertEcho(t, resp)
		if got, _ := echo["type"].(string); got != name {
			t.Fatalf("%s: type=%q", name, got)
		}
		if _, ok := echo["admin_token"]; ok {
			t.Fatalf("%s: admin_token should be omitted when blank", name)
		}
	}
}

func TestGetMemberRoleSimple(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	resp, _ := c.GetMemberRole(3, 7)
	echo := assertEcho(t, resp)
	if got, _ := echo["type"].(string); got != "get_member_role" {
		t.Fatalf("type: %q", got)
	}
	if got, _ := echo["target_node_id"].(float64); uint32(got) != 7 {
		t.Fatalf("target_node_id: %v", got)
	}
}

// --- Policy / ExprPolicy --------------------------------------------------

func TestSetNetworkPolicyMergesPolicyMap(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	policy := map[string]interface{}{
		"allow_public": true,
		"max_members":  float64(10),
		"network_id":   float64(999), // must NOT override the real network_id
		"type":         "evil_type",  // must NOT override the real type
		"admin_token":  "EVIL",       // must NOT override the real admin_token
	}
	resp, _ := c.SetNetworkPolicy(3, policy, "ADM")
	echo := assertEcho(t, resp)
	if got, _ := echo["allow_public"].(bool); !got {
		t.Fatalf("allow_public: %v", got)
	}
	if got, _ := echo["max_members"].(float64); got != 10 {
		t.Fatalf("max_members: %v", got)
	}
	// Explicit networkID parameter must win over a policy key of the same name.
	if got, _ := echo["network_id"].(float64); got != 3 {
		t.Fatalf("network_id: want 3 (explicit param wins), got %v", got)
	}
	if got, _ := echo["type"].(string); got != "set_network_policy" {
		t.Fatalf("type: want set_network_policy (protected), got %q", got)
	}
	if got, _ := echo["admin_token"].(string); got != "ADM" {
		t.Fatalf("admin_token: want ADM (explicit param wins), got %q", got)
	}
}

func TestGetNetworkPolicyType(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	resp, _ := c.GetNetworkPolicy(7)
	echo := assertEcho(t, resp)
	if got, _ := echo["type"].(string); got != "get_network_policy" {
		t.Fatalf("type: %q", got)
	}
}

func TestSetExprPolicyStringifiesJSON(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	raw := json.RawMessage(`{"rule":"true"}`)
	resp, _ := c.SetExprPolicy(9, raw, "ADM")
	echo := assertEcho(t, resp)
	if got, _ := echo["expr_policy"].(string); got != `{"rule":"true"}` {
		t.Fatalf("expr_policy: %q", got)
	}
}

func TestGetExprPolicyType(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	resp, _ := c.GetExprPolicy(9)
	echo := assertEcho(t, resp)
	if got, _ := echo["type"].(string); got != "get_expr_policy" {
		t.Fatalf("type: %q", got)
	}
}

// --- Admin wrappers (trivial payload formatters) -------------------------

func TestAdminWrappersIncludeAdminToken(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	cases := []struct {
		name string
		call func() (map[string]interface{}, error)
		typ  string
	}{
		{"set_hostname_admin", func() (map[string]interface{}, error) { return c.SetHostnameAdmin(1, "h", "T") }, "set_hostname"},
		{"set_visibility_admin", func() (map[string]interface{}, error) { return c.SetVisibilityAdmin(1, true, "T") }, "set_visibility"},
		{"set_tags_admin", func() (map[string]interface{}, error) { return c.SetTagsAdmin(1, []string{"x"}, "T") }, "set_tags"},
		{"set_key_expiry_admin", func() (map[string]interface{}, error) { return c.SetKeyExpiryAdmin(1, time.Unix(0, 0).UTC(), "T") }, "set_key_expiry"},
		{"clear_key_expiry_admin", func() (map[string]interface{}, error) { return c.ClearKeyExpiryAdmin(1, "T") }, "set_key_expiry"},
		{"deregister_admin", func() (map[string]interface{}, error) { return c.DeregisterAdmin(1, "T") }, "deregister"},
	}
	for _, tc := range cases {
		resp, err := tc.call()
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		echo := assertEcho(t, resp)
		if got, _ := echo["type"].(string); got != tc.typ {
			t.Fatalf("%s: type=%q want %q", tc.name, got, tc.typ)
		}
		if got, _ := echo["admin_token"].(string); got != "T" {
			t.Fatalf("%s: admin_token=%q", tc.name, got)
		}
	}
}

func TestClearKeyExpiryAdminSendsNeverLiteral(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	resp, _ := c.ClearKeyExpiryAdmin(1, "T")
	echo := assertEcho(t, resp)
	if got, _ := echo["expires_at"].(string); got != "never" {
		t.Fatalf("expires_at: want 'never', got %q", got)
	}
}

func TestSetMemberTagsAndGetMemberTags(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	resp, _ := c.SetMemberTags(2, 3, []string{"gpu", "fast"}, "T")
	echo := assertEcho(t, resp)
	if got, _ := echo["type"].(string); got != "set_member_tags" {
		t.Fatalf("type: %q", got)
	}
	tags, _ := echo["tags"].([]interface{})
	if len(tags) != 2 || tags[0] != "gpu" || tags[1] != "fast" {
		t.Fatalf("tags: %v", tags)
	}

	resp, _ = c.GetMemberTags(2, 3)
	echo = assertEcho(t, resp)
	if got, _ := echo["type"].(string); got != "get_member_tags" {
		t.Fatalf("type: %q", got)
	}
}

// --- Audit log / Audit export / Webhooks / Identity / IDP / Provision ----

func TestGetAuditLogOmitsZeroNetworkID(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	resp, _ := c.GetAuditLog(0, "T")
	echo := assertEcho(t, resp)
	if _, ok := echo["network_id"]; ok {
		t.Fatalf("network_id should be omitted when 0")
	}
	resp, _ = c.GetAuditLog(3, "T")
	echo = assertEcho(t, resp)
	if got, _ := echo["network_id"].(float64); uint16(got) != 3 {
		t.Fatalf("network_id: %v", got)
	}
}

func TestWebhookWrappers(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	cases := []struct {
		typ  string
		call func() (map[string]interface{}, error)
	}{
		{"set_webhook", func() (map[string]interface{}, error) { return c.SetWebhook("http://x", "T") }},
		{"get_webhook", func() (map[string]interface{}, error) { return c.GetWebhook("T") }},
		{"get_webhook_dlq", func() (map[string]interface{}, error) { return c.GetWebhookDLQ("T") }},
		{"set_identity_webhook", func() (map[string]interface{}, error) { return c.SetIdentityWebhook("http://id", "T") }},
	}
	for _, tc := range cases {
		resp, err := tc.call()
		if err != nil {
			t.Fatalf("%s: %v", tc.typ, err)
		}
		echo := assertEcho(t, resp)
		if got, _ := echo["type"].(string); got != tc.typ {
			t.Fatalf("%s: type=%q", tc.typ, got)
		}
	}
}

func TestIdentityExternalIDWrappers(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	resp, _ := c.SetExternalID(5, "ext-7", "T")
	echo := assertEcho(t, resp)
	if got, _ := echo["external_id"].(string); got != "ext-7" {
		t.Fatalf("external_id: %q", got)
	}
	resp, _ = c.GetIdentity(5, "T")
	echo = assertEcho(t, resp)
	if got, _ := echo["type"].(string); got != "get_identity" {
		t.Fatalf("type: %q", got)
	}
}

func TestSetIDPConfigOptionalFields(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	// Only required fields.
	resp, _ := c.SetIDPConfig("oidc", "https://idp", "", "", "", "", "T")
	echo := assertEcho(t, resp)
	for _, key := range []string{"issuer", "client_id", "tenant_id", "domain"} {
		if _, ok := echo[key]; ok {
			t.Fatalf("%s should be omitted when blank", key)
		}
	}
	if got, _ := echo["idp_type"].(string); got != "oidc" {
		t.Fatalf("idp_type: %q", got)
	}
	// All fields.
	resp, _ = c.SetIDPConfig("oidc", "https://idp", "ISS", "CID", "TID", "example.com", "T")
	echo = assertEcho(t, resp)
	for _, key := range []string{"issuer", "client_id", "tenant_id", "domain"} {
		if _, ok := echo[key]; !ok {
			t.Fatalf("%s should be present when supplied", key)
		}
	}
}

func TestGetIDPConfigAndGetProvisionStatus(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	resp, _ := c.GetIDPConfig("T")
	echo := assertEcho(t, resp)
	if got, _ := echo["type"].(string); got != "get_idp_config" {
		t.Fatalf("type: %q", got)
	}
	resp, _ = c.GetProvisionStatus("T")
	echo = assertEcho(t, resp)
	if got, _ := echo["type"].(string); got != "get_provision_status" {
		t.Fatalf("type: %q", got)
	}
}

func TestProvisionNetworkPassesBlueprint(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	bp := map[string]interface{}{"name": "bp", "networks": []interface{}{}}
	resp, _ := c.ProvisionNetwork(bp, "T")
	echo := assertEcho(t, resp)
	blueprint, _ := echo["blueprint"].(map[string]interface{})
	if got, _ := blueprint["name"].(string); got != "bp" {
		t.Fatalf("blueprint.name: %q", got)
	}
}

func TestSetAuditExportAllFields(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	resp, _ := c.SetAuditExport("splunk_hec", "https://hec", "TOK", "idx", "src", "T")
	echo := assertEcho(t, resp)
	if got, _ := echo["format"].(string); got != "splunk_hec" {
		t.Fatalf("format: %q", got)
	}
	if got, _ := echo["endpoint"].(string); got != "https://hec" {
		t.Fatalf("endpoint: %q", got)
	}
	if got, _ := echo["index"].(string); got != "idx" {
		t.Fatalf("index: %q", got)
	}
	if got, _ := echo["source"].(string); got != "src" {
		t.Fatalf("source: %q", got)
	}
}

func TestGetAuditExport(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	resp, _ := c.GetAuditExport("T")
	echo := assertEcho(t, resp)
	if got, _ := echo["type"].(string); got != "get_audit_export" {
		t.Fatalf("type: %q", got)
	}
}

// --- Directory sync / ValidateToken / GetKeyInfo -------------------------

func TestDirectorySyncConvertsEntriesAndPassesFlag(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	entries := []map[string]interface{}{
		{"id": "u1", "role": "admin"},
		{"id": "u2", "role": "member"},
	}
	resp, _ := c.DirectorySync(1, entries, true, "T")
	echo := assertEcho(t, resp)
	list, _ := echo["entries"].([]interface{})
	if len(list) != 2 {
		t.Fatalf("entries: %v", list)
	}
	first, _ := list[0].(map[string]interface{})
	if got, _ := first["id"].(string); got != "u1" {
		t.Fatalf("first.id: %q", got)
	}
	if got, _ := echo["remove_unlisted"].(bool); !got {
		t.Fatalf("remove_unlisted: %v", got)
	}
}

func TestDirectoryStatusSimple(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	resp, _ := c.DirectoryStatus(5, "T")
	echo := assertEcho(t, resp)
	if got, _ := echo["type"].(string); got != "directory_status" {
		t.Fatalf("type: %q", got)
	}
}

func TestValidateTokenPassesPayload(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	resp, _ := c.ValidateToken("jwt.header.sig", "T")
	echo := assertEcho(t, resp)
	if got, _ := echo["token"].(string); got != "jwt.header.sig" {
		t.Fatalf("token: %q", got)
	}
}

func TestGetKeyInfoSimple(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	resp, _ := c.GetKeyInfo(7)
	echo := assertEcho(t, resp)
	if got, _ := echo["type"].(string); got != "get_key_info" {
		t.Fatalf("type: %q", got)
	}
}

// Ensure errors package remains used if inline error checks are trimmed.
var _ = errors.New
