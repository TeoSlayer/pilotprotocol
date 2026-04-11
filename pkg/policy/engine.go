package policy

import (
	"fmt"
	"time"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
)

// compiledRule is a single rule with its match expression pre-compiled.
type compiledRule struct {
	rule    Rule
	program *vm.Program
}

// CompiledPolicy holds a fully compiled and validated policy ready for evaluation.
type CompiledPolicy struct {
	Doc   PolicyDocument
	rules []compiledRule

	// Pre-compiled sub-expressions for evict_where actions.
	// Key: "ruleName:actionIdx"
	peerPrograms map[string]*vm.Program
}

// Compile validates and compiles all expressions in a policy document.
// Returns an error if any expression fails type-checking or compilation.
func Compile(doc *PolicyDocument) (*CompiledPolicy, error) {
	if err := Validate(doc); err != nil {
		return nil, err
	}

	cp := &CompiledPolicy{
		Doc:          *doc,
		rules:        make([]compiledRule, 0, len(doc.Rules)),
		peerPrograms: make(map[string]*vm.Program),
	}

	for i, r := range doc.Rules {
		opts := envOptions(r.On)
		prog, err := expr.Compile(r.Match, opts...)
		if err != nil {
			return nil, fmt.Errorf("policy: rule %q match: %w", r.Name, err)
		}
		cp.rules = append(cp.rules, compiledRule{rule: r, program: prog})

		// Compile sub-expressions in actions (e.g. evict_where.match)
		for j, a := range r.Actions {
			if a.Type == ActionEvictWhere {
				matchExpr, _ := a.Params["match"].(string)
				if matchExpr == "" {
					return nil, fmt.Errorf("policy: rule %q action[%d]: evict_where match must be a string", r.Name, j)
				}
				peerProg, err := expr.Compile(matchExpr, peerEnvOptions()...)
				if err != nil {
					return nil, fmt.Errorf("policy: rule %q action[%d] evict_where match: %w", r.Name, j, err)
				}
				key := fmt.Sprintf("%s:%d", r.Name, j)
				cp.peerPrograms[key] = peerProg
			}
		}

		_ = i
	}

	return cp, nil
}

// Evaluate runs all rules for the given event type against the provided context.
// For gate events (connect, dial, datagram), evaluation stops at the first verdict.
// For action events (cycle, join, leave), all matching rules fire.
//
// The context map must contain the variables declared for the event type (see env.go).
// Returns a list of directives the caller should execute.
func (cp *CompiledPolicy) Evaluate(eventType EventType, ctx map[string]interface{}) ([]Directive, error) {
	if eventType.IsGateEvent() {
		return cp.evaluateGate(eventType, ctx)
	}
	return cp.evaluateActions(eventType, ctx)
}

// evaluateGate evaluates rules for a gate event, stopping at the first verdict.
func (cp *CompiledPolicy) evaluateGate(eventType EventType, ctx map[string]interface{}) ([]Directive, error) {
	var sideEffects []Directive

	for _, cr := range cp.rules {
		if cr.rule.On != eventType {
			continue
		}

		matched, err := runProgram(cr.program, ctx)
		if err != nil {
			return nil, fmt.Errorf("policy: rule %q eval: %w", cr.rule.Name, err)
		}
		if !matched {
			continue
		}

		// Collect all directives from this rule
		directives := toDirectives(cr.rule)

		// Separate verdict from side effects
		for _, d := range directives {
			if d.Type == DirectiveAllow || d.Type == DirectiveDeny {
				// Return verdict + any accumulated side effects + side effects from this rule
				result := make([]Directive, 0, len(sideEffects)+len(directives))
				result = append(result, sideEffects...)
				result = append(result, directives...)
				return result, nil
			}
		}

		// No verdict in this rule — accumulate side effects and continue
		sideEffects = append(sideEffects, directives...)
	}

	// No verdict rule matched — default allow + any accumulated side effects
	result := append(sideEffects, Directive{
		Type: DirectiveAllow,
		Rule: "_default",
	})
	return result, nil
}

// evaluateActions evaluates all matching rules for an action event.
func (cp *CompiledPolicy) evaluateActions(eventType EventType, ctx map[string]interface{}) ([]Directive, error) {
	var directives []Directive

	for _, cr := range cp.rules {
		if cr.rule.On != eventType {
			continue
		}

		matched, err := runProgram(cr.program, ctx)
		if err != nil {
			return nil, fmt.Errorf("policy: rule %q eval: %w", cr.rule.Name, err)
		}
		if !matched {
			continue
		}

		directives = append(directives, toDirectives(cr.rule)...)
	}

	return directives, nil
}

// EvaluatePeerExpr evaluates a pre-compiled peer sub-expression (e.g. evict_where)
// against per-peer variables. Returns true if the peer matches.
func (cp *CompiledPolicy) EvaluatePeerExpr(ruleName string, actionIdx int, peerCtx map[string]interface{}) (bool, error) {
	key := fmt.Sprintf("%s:%d", ruleName, actionIdx)
	prog, ok := cp.peerPrograms[key]
	if !ok {
		return false, fmt.Errorf("policy: no compiled peer expression for %s", key)
	}
	return runProgram(prog, peerCtx)
}

// HasRulesFor returns true if the policy has any rules for the given event type.
func (cp *CompiledPolicy) HasRulesFor(eventType EventType) bool {
	for _, cr := range cp.rules {
		if cr.rule.On == eventType {
			return true
		}
	}
	return false
}

// CycleDuration returns the configured cycle interval from config, or zero if not set.
func (cp *CompiledPolicy) CycleDuration() (dur, grace string) {
	if cp.Doc.Config == nil {
		return "", ""
	}
	if v, ok := cp.Doc.Config["cycle"]; ok {
		dur, _ = v.(string)
	}
	if v, ok := cp.Doc.Config["grace"]; ok {
		grace, _ = v.(string)
	}
	return dur, grace
}

// MaxPeers returns the configured max_peers from config, or 0 if not set.
func (cp *CompiledPolicy) MaxPeers() int {
	if cp.Doc.Config == nil {
		return 0
	}
	if v, ok := cp.Doc.Config["max_peers"]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case int:
			return n
		}
	}
	return 0
}

// --- helpers ---

func runProgram(prog *vm.Program, ctx map[string]interface{}) (bool, error) {
	type result struct {
		val interface{}
		err error
	}
	ch := make(chan result, 1)
	go func() {
		out, err := expr.Run(prog, ctx)
		ch <- result{out, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return false, r.err
		}
		b, ok := r.val.(bool)
		if !ok {
			return false, fmt.Errorf("expression returned %T, want bool", r.val)
		}
		return b, nil
	case <-time.After(100 * time.Millisecond):
		return false, fmt.Errorf("expression evaluation timed out")
	}
}

var actionTypeToDirective = map[ActionType]DirectiveType{
	ActionAllow:      DirectiveAllow,
	ActionDeny:       DirectiveDeny,
	ActionScore:      DirectiveScore,
	ActionTag:        DirectiveTag,
	ActionEvict:      DirectiveEvict,
	ActionEvictWhere: DirectiveEvictWhere,
	ActionPrune:      DirectivePrune,
	ActionFill:       DirectiveFill,
	ActionPruneTrust: DirectivePruneTrust,
	ActionFillTrust:  DirectiveFillTrust,
	ActionWebhook:    DirectiveWebhook,
	ActionLog:        DirectiveLog,
}

func toDirectives(rule Rule) []Directive {
	directives := make([]Directive, 0, len(rule.Actions))
	for _, a := range rule.Actions {
		dt, ok := actionTypeToDirective[a.Type]
		if !ok {
			continue
		}
		directives = append(directives, Directive{
			Type:   dt,
			Rule:   rule.Name,
			Params: a.Params,
		})
	}
	return directives
}
