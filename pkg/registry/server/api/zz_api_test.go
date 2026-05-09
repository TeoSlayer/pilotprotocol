// SPDX-License-Identifier: AGPL-3.0-or-later

package api_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/registry/server/api"
)

// --- compile-time interface satisfaction checks ---
//
// Each stub type below implements exactly one View interface. The
// var-block assertions fail at compile time if the interface changes
// and the stub no longer satisfies it, making this the coverage signal
// for the interface contracts.

type stubDirectory struct{}

func (stubDirectory) GetNode(uint32) (*api.NodeInfo, bool)   { return nil, false }
func (stubDirectory) NodeCount() int                         { return 0 }
func (stubDirectory) List() []*api.NodeInfo                  { return nil }
func (stubDirectory) Online(time.Time) int                   { return 0 }
func (stubDirectory) TaskExecutorCount() int                 { return 0 }
func (stubDirectory) LookupByPubKey(string) (uint32, bool)   { return 0, false }
func (stubDirectory) LookupByHostname(string) (uint32, bool) { return 0, false }

var _ api.DirectoryView = stubDirectory{}

type stubIdentity struct{}

func (stubIdentity) Configured() bool                       { return false }
func (stubIdentity) GetKeyInfo(uint32) (*api.KeyInfo, bool) { return nil, false }

var _ api.IdentityView = stubIdentity{}

type stubMembership struct{}

func (stubMembership) GetNetwork(uint16) (*api.NetworkInfo, bool) { return nil, false }
func (stubMembership) Count() int                                 { return 0 }
func (stubMembership) Networks() []*api.NetworkInfo               { return nil }
func (stubMembership) Members(uint16) []uint32                    { return nil }
func (stubMembership) NetworksFor(uint32) []uint16                { return nil }
func (stubMembership) MemberRole(uint16, uint32) (api.Role, error) {
	return "", errors.New("not found")
}
func (stubMembership) MemberTags(uint16, uint32) []string { return nil }
func (stubMembership) PendingInvites(uint32) int          { return 0 }

var _ api.MembershipView = stubMembership{}

type stubTrust struct{}

func (stubTrust) Count() int                 { return 0 }
func (stubTrust) IsTrusted(a, b uint32) bool { return false }

var _ api.TrustView = stubTrust{}

type stubPolicy struct{}

func (stubPolicy) Get(uint16) (*api.NetworkPolicy, bool) { return nil, false }
func (stubPolicy) GetExpr(uint16) ([]byte, bool)         { return nil, false }

var _ api.PolicyView = stubPolicy{}

// --- Role constants ---

func TestRoleConstants(t *testing.T) {
	t.Parallel()
	tests := []struct {
		role api.Role
		want string
	}{
		{api.RoleOwner, "owner"},
		{api.RoleAdmin, "admin"},
		{api.RoleMember, "member"},
	}
	for _, tc := range tests {
		if string(tc.role) != tc.want {
			t.Errorf("Role %q: got %q", tc.want, tc.role)
		}
	}
}

// --- JSON round-trip for tagged types ---

func TestKeyInfoJSON(t *testing.T) {
	t.Parallel()
	now := time.Now().Truncate(time.Second).UTC()
	orig := api.KeyInfo{
		CreatedAt:   now,
		RotatedAt:   now.Add(time.Hour),
		RotateCount: 3,
		ExpiresAt:   now.Add(24 * time.Hour),
	}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got api.KeyInfo
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !got.CreatedAt.Equal(orig.CreatedAt) {
		t.Errorf("CreatedAt: got %v want %v", got.CreatedAt, orig.CreatedAt)
	}
	if got.RotateCount != orig.RotateCount {
		t.Errorf("RotateCount: got %d want %d", got.RotateCount, orig.RotateCount)
	}
}

func TestKeyInfoJSONRoundTripZero(t *testing.T) {
	t.Parallel()
	// A zero KeyInfo must survive a marshal/unmarshal cycle without error.
	// encoding/json does not omit zero time.Time struct fields even with the
	// omitempty tag (structs are not considered "empty" by the standard library),
	// so we only verify that the round-trip is lossless, not that fields are absent.
	orig := api.KeyInfo{}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got api.KeyInfo
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.RotateCount != 0 || !got.RotatedAt.IsZero() || !got.ExpiresAt.IsZero() {
		t.Errorf("zero round-trip failed: %+v", got)
	}
}

func TestNetworkInviteJSON(t *testing.T) {
	t.Parallel()
	now := time.Now().Truncate(time.Second).UTC()
	orig := api.NetworkInvite{NetworkID: 7, InviterID: 42, Timestamp: now}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got api.NetworkInvite
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.NetworkID != orig.NetworkID || got.InviterID != orig.InviterID {
		t.Errorf("round-trip mismatch: %+v", got)
	}
	if !got.Timestamp.Equal(orig.Timestamp) {
		t.Errorf("Timestamp: got %v want %v", got.Timestamp, orig.Timestamp)
	}
}

func TestNetworkPolicyJSON(t *testing.T) {
	t.Parallel()
	orig := api.NetworkPolicy{
		MaxMembers:   100,
		AllowedPorts: []uint16{80, 443, 8080},
		Description:  "test policy",
	}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got api.NetworkPolicy
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.MaxMembers != orig.MaxMembers || got.Description != orig.Description {
		t.Errorf("round-trip mismatch: %+v", got)
	}
	if len(got.AllowedPorts) != len(orig.AllowedPorts) {
		t.Errorf("AllowedPorts length: got %d want %d", len(got.AllowedPorts), len(orig.AllowedPorts))
	}
}

func TestTrustViewSymmetry(t *testing.T) {
	t.Parallel()
	// IsTrusted is documented as symmetric; verify the stub upholds the contract
	// (both directions return the same value).
	tv := stubTrust{}
	if tv.IsTrusted(1, 2) != tv.IsTrusted(2, 1) {
		t.Error("IsTrusted must be symmetric")
	}
}
