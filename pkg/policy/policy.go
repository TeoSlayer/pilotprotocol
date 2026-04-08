package policy

import (
	"encoding/json"
	"fmt"
	"time"
)

// Version is the current policy document schema version.
const Version = 1

// EventType identifies the protocol event a rule matches against.
type EventType string

const (
	EventConnect  EventType = "connect"  // inbound SYN
	EventDial     EventType = "dial"     // outbound SYN
	EventDatagram EventType = "datagram" // inbound/outbound datagram
	EventCycle    EventType = "cycle"    // periodic timer tick
	EventJoin     EventType = "join"     // peer joins network
	EventLeave    EventType = "leave"    // peer leaves network
)

// gateEvents are events that produce allow/deny verdicts.
var gateEvents = map[EventType]bool{
	EventConnect:  true,
	EventDial:     true,
	EventDatagram: true,
}

// IsGateEvent returns true if the event type produces allow/deny verdicts.
func (e EventType) IsGateEvent() bool { return gateEvents[e] }

// ActionType identifies what a rule does when it matches.
type ActionType string

const (
	ActionAllow     ActionType = "allow"
	ActionDeny      ActionType = "deny"
	ActionScore     ActionType = "score"
	ActionTag       ActionType = "tag"
	ActionEvict     ActionType = "evict"
	ActionEvictWhere ActionType = "evict_where"
	ActionPrune     ActionType = "prune"
	ActionFill      ActionType = "fill"
	ActionWebhook   ActionType = "webhook"
	ActionLog       ActionType = "log"
)

// verdictActions are actions that produce a gate verdict.
var verdictActions = map[ActionType]bool{
	ActionAllow: true,
	ActionDeny:  true,
}

// Action is a single action within a rule.
type Action struct {
	Type   ActionType             `json:"type"`
	Params map[string]interface{} `json:"params,omitempty"`
}

// Rule is a single policy rule: when event matches, execute actions.
type Rule struct {
	Name    string   `json:"name"`
	On      EventType `json:"on"`
	Match   string   `json:"match"`
	Actions []Action `json:"actions"`
}

// PolicyDocument is the top-level policy structure stored as JSON.
type PolicyDocument struct {
	Version int                    `json:"version"`
	Config  map[string]interface{} `json:"config,omitempty"`
	Rules   []Rule                 `json:"rules"`
}

// DirectiveType identifies the kind of directive returned by evaluation.
type DirectiveType int

const (
	DirectiveAllow DirectiveType = iota
	DirectiveDeny
	DirectiveScore
	DirectiveTag
	DirectiveEvict
	DirectiveEvictWhere
	DirectivePrune
	DirectiveFill
	DirectiveWebhook
	DirectiveLog
)

// Directive is an instruction produced by evaluating a rule.
type Directive struct {
	Type   DirectiveType
	Rule   string                 // source rule name
	Params map[string]interface{} // action parameters
}

// Parse unmarshals and validates a policy document from JSON.
func Parse(data []byte) (*PolicyDocument, error) {
	var doc PolicyDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("policy: invalid JSON: %w", err)
	}
	if err := Validate(&doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

// Validate checks structural validity of a policy document.
// It does NOT compile expressions — use Compile for full validation.
func Validate(doc *PolicyDocument) error {
	if doc.Version != Version {
		return fmt.Errorf("policy: unsupported version %d (want %d)", doc.Version, Version)
	}
	if len(doc.Rules) == 0 {
		return fmt.Errorf("policy: at least one rule is required")
	}

	names := make(map[string]bool, len(doc.Rules))
	for i, r := range doc.Rules {
		if r.Name == "" {
			return fmt.Errorf("policy: rule[%d]: name is required", i)
		}
		if names[r.Name] {
			return fmt.Errorf("policy: duplicate rule name %q", r.Name)
		}
		names[r.Name] = true

		switch r.On {
		case EventConnect, EventDial, EventDatagram, EventCycle, EventJoin, EventLeave:
			// valid
		default:
			return fmt.Errorf("policy: rule %q: unknown event type %q", r.Name, r.On)
		}

		if r.Match == "" {
			return fmt.Errorf("policy: rule %q: match expression is required", r.Name)
		}

		if len(r.Actions) == 0 {
			return fmt.Errorf("policy: rule %q: at least one action is required", r.Name)
		}

		for j, a := range r.Actions {
			if err := validateAction(r.Name, j, a); err != nil {
				return err
			}
		}
	}

	// Validate config durations if present
	if doc.Config != nil {
		if v, ok := doc.Config["cycle"]; ok {
			s, ok := v.(string)
			if !ok {
				return fmt.Errorf("policy: config.cycle must be a string")
			}
			d, err := time.ParseDuration(s)
			if err != nil {
				return fmt.Errorf("policy: config.cycle: %w", err)
			}
			if d < 1*time.Minute {
				return fmt.Errorf("policy: config.cycle must be >= 1m")
			}
		}
	}

	return nil
}

func validateAction(ruleName string, idx int, a Action) error {
	switch a.Type {
	case ActionAllow, ActionDeny, ActionEvict:
		// no required params
	case ActionScore:
		if _, ok := a.Params["delta"]; !ok {
			return fmt.Errorf("policy: rule %q action[%d]: score requires 'delta' param", ruleName, idx)
		}
	case ActionTag:
		_, hasAdd := a.Params["add"]
		_, hasRemove := a.Params["remove"]
		if !hasAdd && !hasRemove {
			return fmt.Errorf("policy: rule %q action[%d]: tag requires 'add' or 'remove' param", ruleName, idx)
		}
	case ActionEvictWhere:
		if _, ok := a.Params["match"]; !ok {
			return fmt.Errorf("policy: rule %q action[%d]: evict_where requires 'match' param", ruleName, idx)
		}
	case ActionPrune:
		if _, ok := a.Params["count"]; !ok {
			return fmt.Errorf("policy: rule %q action[%d]: prune requires 'count' param", ruleName, idx)
		}
	case ActionFill:
		if _, ok := a.Params["count"]; !ok {
			return fmt.Errorf("policy: rule %q action[%d]: fill requires 'count' param", ruleName, idx)
		}
	case ActionWebhook:
		if _, ok := a.Params["event"]; !ok {
			return fmt.Errorf("policy: rule %q action[%d]: webhook requires 'event' param", ruleName, idx)
		}
	case ActionLog:
		if _, ok := a.Params["message"]; !ok {
			return fmt.Errorf("policy: rule %q action[%d]: log requires 'message' param", ruleName, idx)
		}
	default:
		return fmt.Errorf("policy: rule %q action[%d]: unknown action type %q", ruleName, idx, a.Type)
	}
	return nil
}
