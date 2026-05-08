// SPDX-License-Identifier: AGPL-3.0-or-later

package server

// Handler is the unified shape of every registry message handler invoked
// by the dispatch table. Each entry in `handlers` maps a wire `msgType`
// (e.g. "register", "create_network", ...) to a thin closure that calls
// the corresponding `s.handleX(...)` method on *Server.
//
// This file is the R3 dispatch layer per architecture-notes/07-REGISTRY-LAYERS.md.
// Handlers themselves stay defined as methods on *Server (in server.go and
// related files); this layer only routes msgType -> handler. Tier R0.1
// of the registry-server extraction plan: refactor only, zero behavior
// change.
type Handler func(s *Server, msg map[string]interface{}, remoteAddr string) (map[string]interface{}, error)

// handlers is the dispatch table consulted by Server.handleMessage.
// Adding a new handler means adding an entry here; never editing a
// 200-line switch (per R3 invariant 5: "R3 dispatch is a lookup, not a
// switch").
//
// The closures preserve the exact argument shape of the original switch
// arms — handlers that ignored remoteAddr still ignore it; handlers that
// took no msg (e.g. handleBeaconList) still take none. This keeps the
// refactor byte-identical in behavior.
var handlers = map[string]Handler{
	"register": func(s *Server, msg map[string]interface{}, remoteAddr string) (map[string]interface{}, error) {
		return s.handleRegister(msg, remoteAddr)
	},
	"create_network": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.membership.HandleCreateNetwork(msg)
	},
	"join_network": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.membership.HandleJoinNetwork(msg)
	},
	"leave_network": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.membership.HandleLeaveNetwork(msg)
	},
	"delete_network": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.membership.HandleDeleteNetwork(msg)
	},
	"rename_network": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.membership.HandleRenameNetwork(msg)
	},
	"set_network_enterprise": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.membership.HandleSetNetworkEnterprise(msg)
	},
	"lookup": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.directory.HandleLookup(msg)
	},
	"resolve": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.directory.HandleResolve(msg)
	},
	"list_networks": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.membership.HandleListNetworks(msg)
	},
	"list_nodes": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.directory.HandleListNodes(msg, s.requireAdminToken)
	},
	"rotate_key": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.identity.HandleRotateKey(msg)
	},
	"deregister": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.directory.HandleDeregister(msg)
	},
	"set_visibility": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.directory.HandleSetVisibility(msg)
	},
	"report_trust": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.trust.HandleReportTrust(msg)
	},
	"revoke_trust": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.trust.HandleRevokeTrust(msg)
	},
	"check_trust": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.trust.HandleCheckTrust(msg)
	},
	"request_handshake": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.trust.HandleRequestHandshake(msg)
	},
	"poll_handshakes": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.trust.HandlePollHandshakes(msg)
	},
	"respond_handshake": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.trust.HandleRespondHandshake(msg)
	},
	"heartbeat": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.directory.HandleHeartbeat(msg)
	},
	"punch": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.routing.HandlePunch(msg)
	},
	"set_hostname": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.directory.HandleSetHostname(msg)
	},
	"set_tags": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.directory.HandleSetTags(msg)
	},
	"set_member_tags": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.membership.HandleSetMemberTags(msg)
	},
	"get_member_tags": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.membership.HandleGetMemberTags(msg)
	},
	"resolve_hostname": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.directory.HandleResolveHostname(msg)
	},
	"beacon_register": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.handleBeaconRegister(msg)
	},
	"beacon_list": func(s *Server, _ map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.routing.HandleBeaconList()
	},
	"invite_to_network": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.membership.HandleInviteToNetwork(msg)
	},
	"poll_invites": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.membership.HandlePollInvites(msg)
	},
	"respond_invite": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.membership.HandleRespondInvite(msg)
	},
	"kick_member": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.membership.HandleKickMember(msg)
	},
	"promote_member": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.membership.HandlePromoteMember(msg)
	},
	"demote_member": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.membership.HandleDemoteMember(msg)
	},
	"transfer_ownership": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.membership.HandleTransferOwnership(msg)
	},
	"get_member_role": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.membership.HandleGetMemberRole(msg)
	},
	"set_network_policy": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.policy.HandleSetNetworkPolicy(msg)
	},
	"get_network_policy": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.policy.HandleGetNetworkPolicy(msg)
	},
	"set_expr_policy": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.policy.HandleSetExprPolicy(msg)
	},
	"get_expr_policy": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.policy.HandleGetExprPolicy(msg)
	},
	"set_key_expiry": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.identity.HandleSetKeyExpiry(msg)
	},
	"get_key_info": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.identity.HandleGetKeyInfo(msg)
	},
	"get_audit_log": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.handleGetAuditLog(msg)
	},
	"set_webhook": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.handleSetWebhook(msg)
	},
	"get_webhook": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.handleGetWebhook(msg)
	},
	"set_identity_webhook": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.handleSetIdentityWebhook(msg)
	},
	"set_external_id": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.identity.HandleSetExternalID(msg)
	},
	"get_identity": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.identity.HandleGetIdentity(msg)
	},
	"get_webhook_dlq": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.handleGetWebhookDLQ(msg)
	},
	"provision_network": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.handleProvisionNetwork(msg)
	},
	"set_audit_export": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.handleSetAuditExport(msg)
	},
	"get_audit_export": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.handleGetAuditExport(msg)
	},
	"get_idp_config": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.handleGetIDPConfig(msg)
	},
	"set_idp_config": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.handleSetIDPConfig(msg)
	},
	"get_provision_status": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.handleGetProvisionStatus(msg)
	},
	"directory_sync": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.handleDirectorySync(msg)
	},
	"directory_status": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.handleGetDirectoryStatus(msg)
	},
	"validate_token": func(s *Server, msg map[string]interface{}, _ string) (map[string]interface{}, error) {
		return s.identity.HandleValidateToken(msg)
	},
}
