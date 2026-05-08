// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

// fakeRuntime is the test stub for the daemon-provided Runtime
// interface. Each method is a no-op or returns zero-valued data.
// Tests that need specific behaviour can populate the function fields
// or wrap a fakeRuntime with custom logic.
type fakeRuntime struct {
	NodeIDFn        func() uint32
	PublishEventFn  func(string, map[string]any)
	AdminTokenFn    func() string
	ListNodesFn     func(uint16, string) (map[string]any, error)
	SetMemberTagsFn func(uint16, []string)
	TrustedPeersFn  func() []TrustRecord
	RevokeTrustFn   func(uint32) error
	SendHandshakeFn func(uint32, string) error
}

func (r *fakeRuntime) NodeID() uint32 {
	if r.NodeIDFn != nil {
		return r.NodeIDFn()
	}
	return 0
}
func (r *fakeRuntime) PublishEvent(topic string, payload map[string]any) {
	if r.PublishEventFn != nil {
		r.PublishEventFn(topic, payload)
	}
}
func (r *fakeRuntime) AdminToken() string {
	if r.AdminTokenFn != nil {
		return r.AdminTokenFn()
	}
	return ""
}
func (r *fakeRuntime) ListNodes(netID uint16, token string) (map[string]any, error) {
	if r.ListNodesFn != nil {
		return r.ListNodesFn(netID, token)
	}
	return map[string]any{}, nil
}
func (r *fakeRuntime) SetMemberTags(netID uint16, tags []string) {
	if r.SetMemberTagsFn != nil {
		r.SetMemberTagsFn(netID, tags)
	}
}
func (r *fakeRuntime) TrustedPeers() []TrustRecord {
	if r.TrustedPeersFn != nil {
		return r.TrustedPeersFn()
	}
	return nil
}
func (r *fakeRuntime) RevokeTrust(nodeID uint32) error {
	if r.RevokeTrustFn != nil {
		return r.RevokeTrustFn(nodeID)
	}
	return nil
}
func (r *fakeRuntime) SendHandshakeRequest(nodeID uint32, reason string) error {
	if r.SendHandshakeFn != nil {
		return r.SendHandshakeFn(nodeID, reason)
	}
	return nil
}
