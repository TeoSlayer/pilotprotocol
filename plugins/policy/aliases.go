// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import (
	policylang "github.com/TeoSlayer/pilotprotocol/internal/policy"
)

// Re-exports of the pure policy lang (parser, validator, compiler,
// evaluator, types). Lives in internal/policy so cmd/pilotctl can call
// it without importing the L11 plugin package. plugins/policy keeps
// the daemon-side runner, runtime, peer-eviction logic, and L11
// Service shell.

// Document/version aliases.
type (
	PolicyDocument = policylang.PolicyDocument
	Rule           = policylang.Rule
	Action         = policylang.Action
	ActionType     = policylang.ActionType
	EventType      = policylang.EventType
	Directive      = policylang.Directive
	DirectiveType  = policylang.DirectiveType
	CompiledPolicy = policylang.CompiledPolicy
)

// Version is the policy schema version.
const Version = policylang.Version

// EventType constants.
const (
	EventConnect  = policylang.EventConnect
	EventDial     = policylang.EventDial
	EventDatagram = policylang.EventDatagram
	EventCycle    = policylang.EventCycle
	EventJoin     = policylang.EventJoin
	EventLeave    = policylang.EventLeave
)

// ActionType constants.
const (
	ActionAllow      = policylang.ActionAllow
	ActionDeny       = policylang.ActionDeny
	ActionTag        = policylang.ActionTag
	ActionEvict      = policylang.ActionEvict
	ActionEvictWhere = policylang.ActionEvictWhere
	ActionPrune      = policylang.ActionPrune
	ActionFill       = policylang.ActionFill
	ActionPruneTrust = policylang.ActionPruneTrust
	ActionFillTrust  = policylang.ActionFillTrust
	ActionWebhook    = policylang.ActionWebhook
	ActionLog        = policylang.ActionLog
)

// DirectiveType constants.
const (
	DirectiveAllow      = policylang.DirectiveAllow
	DirectiveDeny       = policylang.DirectiveDeny
	DirectiveTag        = policylang.DirectiveTag
	DirectiveEvict      = policylang.DirectiveEvict
	DirectiveEvictWhere = policylang.DirectiveEvictWhere
	DirectivePrune      = policylang.DirectivePrune
	DirectiveFill       = policylang.DirectiveFill
	DirectivePruneTrust = policylang.DirectivePruneTrust
	DirectiveFillTrust  = policylang.DirectiveFillTrust
	DirectiveWebhook    = policylang.DirectiveWebhook
	DirectiveLog        = policylang.DirectiveLog
)

// Lang free-function re-exports. Functions can't be aliased — wrap.
func Parse(data []byte) (*PolicyDocument, error)           { return policylang.Parse(data) }
func Validate(doc *PolicyDocument) error                   { return policylang.Validate(doc) }
func Compile(doc *PolicyDocument) (*CompiledPolicy, error) { return policylang.Compile(doc) }
func IsGateEvent(e EventType) bool                         { return policylang.IsGateEvent(e) }
