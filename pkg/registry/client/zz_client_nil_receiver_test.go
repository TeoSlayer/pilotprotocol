// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// TestNilClient_AllMethodsReturnError asserts that every exported *Client
// method is safe to call on a typed-nil receiver and returns ErrNoRegistry
// (or, for SetSigner/Close, a no-op without panic). Several callers in the
// daemon (loadPolicyRunners, ManagedEngine.fetchMembers, Daemon.Info →
// nodeNetworks) invoke registry methods without nil-checking the client,
// so the only acceptable behavior is "no panic; recoverable error."
//
// The test invokes each method, recovers any panic, and asserts the
// expected error. A panic counts as a regression and fails the test.
func TestNilClient_AllMethodsReturnError(t *testing.T) {
	t.Parallel()

	var c *Client

	// callErr runs fn and asserts (a) no panic and (b) the returned error
	// is ErrNoRegistry (using errors.Is). name identifies the method.
	callErr := func(name string, fn func() error) {
		t.Helper()
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("%s panicked on nil receiver: %v", name, r)
			}
		}()
		err := fn()
		if !errors.Is(err, ErrNoRegistry) {
			t.Errorf("%s: err = %v, want ErrNoRegistry", name, err)
		}
	}

	// callMap discards the map return and asserts the error contract.
	callMap := func(name string, fn func() (map[string]interface{}, error)) {
		t.Helper()
		callErr(name, func() error {
			_, err := fn()
			return err
		})
	}

	// --- void / no-error methods (must not panic; nothing else to assert) ---
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("SetSigner panicked on nil receiver: %v", r)
			}
		}()
		c.SetSigner(func(string) string { return "" })
	}()

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Close panicked on nil receiver: %v", r)
			}
		}()
		if err := c.Close(); err != nil {
			t.Errorf("Close on nil receiver: err = %v, want nil", err)
		}
	}()

	// --- methods that return (map, error) — go through Send ---
	callMap("Send", func() (map[string]interface{}, error) {
		return c.Send(map[string]interface{}{"type": "ping"})
	})
	callMap("Register", func() (map[string]interface{}, error) { return c.Register("127.0.0.1:0") })
	callMap("RegisterWithOwner", func() (map[string]interface{}, error) {
		return c.RegisterWithOwner("127.0.0.1:0", "owner")
	})
	callMap("RegisterWithKey", func() (map[string]interface{}, error) {
		return c.RegisterWithKey("127.0.0.1:0", "key", "owner", nil)
	})
	callMap("RegisterWithKeyOpts", func() (map[string]interface{}, error) {
		return c.RegisterWithKeyOpts(RegisterOpts{ListenAddr: "127.0.0.1:0", PublicKey: "k"})
	})
	callMap("RotateKey", func() (map[string]interface{}, error) {
		return c.RotateKey(1, "sig", "newkey")
	})
	callMap("Lookup", func() (map[string]interface{}, error) { return c.Lookup(1) })
	callMap("Resolve", func() (map[string]interface{}, error) { return c.Resolve(1, 2) })
	callMap("ReportTrust", func() (map[string]interface{}, error) { return c.ReportTrust(1, 2) })
	callMap("RevokeTrust", func() (map[string]interface{}, error) { return c.RevokeTrust(1, 2) })
	callMap("SetVisibility", func() (map[string]interface{}, error) { return c.SetVisibility(1, true) })
	callMap("CreateNetwork", func() (map[string]interface{}, error) {
		return c.CreateNetwork(1, "name", "open", "tok", "admin", false)
	})
	callMap("CreateManagedNetwork", func() (map[string]interface{}, error) {
		return c.CreateManagedNetwork(1, "name", "open", "tok", "admin", false, "{}")
	})
	callMap("JoinNetwork", func() (map[string]interface{}, error) {
		return c.JoinNetwork(1, 2, "tok", 3, "admin")
	})
	callMap("LeaveNetwork", func() (map[string]interface{}, error) {
		return c.LeaveNetwork(1, 2, "admin")
	})
	callMap("DeleteNetwork", func() (map[string]interface{}, error) { return c.DeleteNetwork(1, "admin") })
	callMap("RenameNetwork", func() (map[string]interface{}, error) {
		return c.RenameNetwork(1, "new", "admin")
	})
	callMap("SetNetworkEnterprise", func() (map[string]interface{}, error) {
		return c.SetNetworkEnterprise(1, true, "admin")
	})
	callMap("ListNetworks", func() (map[string]interface{}, error) { return c.ListNetworks() })
	callMap("ListNodes", func() (map[string]interface{}, error) { return c.ListNodes(1) })
	callMap("Deregister", func() (map[string]interface{}, error) { return c.Deregister(1) })
	callMap("Heartbeat", func() (map[string]interface{}, error) { return c.Heartbeat(1) })
	callMap("Punch", func() (map[string]interface{}, error) { return c.Punch(1, 2, 3) })
	callMap("RequestHandshake", func() (map[string]interface{}, error) {
		return c.RequestHandshake(1, 2, "why", "sig")
	})
	callMap("PollHandshakes", func() (map[string]interface{}, error) { return c.PollHandshakes(1) })
	callMap("RespondHandshake", func() (map[string]interface{}, error) {
		return c.RespondHandshake(1, 2, true, "sig")
	})
	callMap("SetHostname", func() (map[string]interface{}, error) { return c.SetHostname(1, "h") })
	callMap("SetTags", func() (map[string]interface{}, error) { return c.SetTags(1, []string{"t"}) })
	callMap("ResolveHostname", func() (map[string]interface{}, error) { return c.ResolveHostname("h") })
	callMap("ResolveHostnameAs", func() (map[string]interface{}, error) {
		return c.ResolveHostnameAs(1, "h")
	})
	callMap("InviteToNetwork", func() (map[string]interface{}, error) {
		return c.InviteToNetwork(1, 2, 3, "admin")
	})
	callMap("PollInvites", func() (map[string]interface{}, error) { return c.PollInvites(1) })
	callMap("RespondInvite", func() (map[string]interface{}, error) {
		return c.RespondInvite(1, 2, true)
	})
	callMap("PromoteMember", func() (map[string]interface{}, error) {
		return c.PromoteMember(1, 2, 3, "admin")
	})
	callMap("DemoteMember", func() (map[string]interface{}, error) {
		return c.DemoteMember(1, 2, 3, "admin")
	})
	callMap("KickMember", func() (map[string]interface{}, error) {
		return c.KickMember(1, 2, 3, "admin")
	})
	callMap("TransferOwnership", func() (map[string]interface{}, error) {
		return c.TransferOwnership(1, 2, 3, "admin")
	})
	callMap("GetMemberRole", func() (map[string]interface{}, error) {
		return c.GetMemberRole(1, 2)
	})
	callMap("SetNetworkPolicy", func() (map[string]interface{}, error) {
		return c.SetNetworkPolicy(1, map[string]interface{}{}, "admin")
	})
	callMap("GetNetworkPolicy", func() (map[string]interface{}, error) {
		return c.GetNetworkPolicy(1)
	})
	callMap("SetExprPolicy", func() (map[string]interface{}, error) {
		return c.SetExprPolicy(1, json.RawMessage(`{}`), "admin")
	})
	callMap("GetExprPolicy", func() (map[string]interface{}, error) { return c.GetExprPolicy(1) })
	callMap("SetKeyExpiry", func() (map[string]interface{}, error) {
		return c.SetKeyExpiry(1, time.Now())
	})
	callMap("GetKeyInfo", func() (map[string]interface{}, error) { return c.GetKeyInfo(1) })
	callMap("SetHostnameAdmin", func() (map[string]interface{}, error) {
		return c.SetHostnameAdmin(1, "h", "admin")
	})
	callMap("SetVisibilityAdmin", func() (map[string]interface{}, error) {
		return c.SetVisibilityAdmin(1, true, "admin")
	})
	callMap("SetTagsAdmin", func() (map[string]interface{}, error) {
		return c.SetTagsAdmin(1, []string{"t"}, "admin")
	})
	callMap("SetMemberTags", func() (map[string]interface{}, error) {
		return c.SetMemberTags(1, 2, []string{"t"}, "admin")
	})
	callMap("GetMemberTags", func() (map[string]interface{}, error) {
		return c.GetMemberTags(1, 2)
	})
	callMap("SetKeyExpiryAdmin", func() (map[string]interface{}, error) {
		return c.SetKeyExpiryAdmin(1, time.Now(), "admin")
	})
	callMap("ClearKeyExpiryAdmin", func() (map[string]interface{}, error) {
		return c.ClearKeyExpiryAdmin(1, "admin")
	})
	callMap("DeregisterAdmin", func() (map[string]interface{}, error) {
		return c.DeregisterAdmin(1, "admin")
	})
	callMap("GetAuditLog", func() (map[string]interface{}, error) {
		return c.GetAuditLog(1, "admin")
	})
	callMap("SetWebhook", func() (map[string]interface{}, error) {
		return c.SetWebhook("http://x", "admin")
	})
	callMap("GetWebhook", func() (map[string]interface{}, error) { return c.GetWebhook("admin") })
	callMap("GetWebhookDLQ", func() (map[string]interface{}, error) {
		return c.GetWebhookDLQ("admin")
	})
	callMap("SetIdentityWebhook", func() (map[string]interface{}, error) {
		return c.SetIdentityWebhook("http://x", "admin")
	})
	callMap("SetExternalID", func() (map[string]interface{}, error) {
		return c.SetExternalID(1, "ext", "admin")
	})
	callMap("GetIdentity", func() (map[string]interface{}, error) {
		return c.GetIdentity(1, "admin")
	})
	callMap("ProvisionNetwork", func() (map[string]interface{}, error) {
		return c.ProvisionNetwork(map[string]interface{}{}, "admin")
	})
	callMap("SetAuditExport", func() (map[string]interface{}, error) {
		return c.SetAuditExport("splunk", "https://x", "t", "i", "s", "admin")
	})
	callMap("GetAuditExport", func() (map[string]interface{}, error) {
		return c.GetAuditExport("admin")
	})
	callMap("SetIDPConfig", func() (map[string]interface{}, error) {
		return c.SetIDPConfig("oidc", "https://x", "iss", "cid", "tid", "dom", "admin")
	})
	callMap("GetIDPConfig", func() (map[string]interface{}, error) {
		return c.GetIDPConfig("admin")
	})
	callMap("GetProvisionStatus", func() (map[string]interface{}, error) {
		return c.GetProvisionStatus("admin")
	})
	callMap("DirectorySync", func() (map[string]interface{}, error) {
		return c.DirectorySync(1, nil, false, "admin")
	})
	callMap("DirectoryStatus", func() (map[string]interface{}, error) {
		return c.DirectoryStatus(1, "admin")
	})
	callMap("ValidateToken", func() (map[string]interface{}, error) {
		return c.ValidateToken("tok", "admin")
	})

	// --- CheckTrust: (bool, error) — pinned separately because the
	// return type differs and a non-false bool would be misleading.
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("CheckTrust panicked on nil receiver: %v", r)
			}
		}()
		ok, err := c.CheckTrust(1, 2)
		if ok {
			t.Errorf("CheckTrust: ok = true, want false")
		}
		if !errors.Is(err, ErrNoRegistry) {
			t.Errorf("CheckTrust: err = %v, want ErrNoRegistry", err)
		}
	}()
}
