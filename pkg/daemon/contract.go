// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import "github.com/pilot-protocol/common/daemonapi"

// This file used to declare a daemon-local plugin-handle contract.
// Those declarations now live in github.com/pilot-protocol/common/daemonapi
// where every plugin can import them without taking a dependency on
// the daemon engine. The aliases here preserve the daemon-local
// names so the rest of pkg/daemon keeps compiling unchanged — Go
// type aliases give the renamed types the same identity, so existing
// "daemon.HandshakeService" usages resolve to the canonical
// daemonapi types.

// Plugin lifecycle / contracts (interface aliases)
type (
	TrustChecker     = daemonapi.TrustChecker
	HandshakeService = daemonapi.HandshakeService
	PolicyRunner     = daemonapi.PolicyRunner
	PolicyManager    = daemonapi.PolicyManager
	WebhookManager   = daemonapi.WebhookManager
)

// Plugin record types (struct aliases)
type (
	HandshakeTrustRecord   = daemonapi.HandshakeTrustRecord
	HandshakePendingRecord = daemonapi.HandshakePendingRecord
	WebhookStats           = daemonapi.WebhookStats
)

// PolicyEventType is a type alias to string (same as daemonapi).
type PolicyEventType = daemonapi.PolicyEventType

// Constants for policy event types — re-exported so daemon-internal
// code can use the short package-qualified names (daemon.PolicyEventConnect
// vs daemonapi.PolicyEventConnect).
const (
	PolicyEventConnect  = daemonapi.PolicyEventConnect
	PolicyEventDial     = daemonapi.PolicyEventDial
	PolicyEventDatagram = daemonapi.PolicyEventDatagram
	PolicyEventJoin     = daemonapi.PolicyEventJoin
	PolicyEventLeave    = daemonapi.PolicyEventLeave
	PolicyEventCycle    = daemonapi.PolicyEventCycle
)
