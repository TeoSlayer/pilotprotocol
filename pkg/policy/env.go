package policy

import (
	"time"

	"github.com/expr-lang/expr"
)

// envOptions returns the common expr options for compiling match expressions.
// The environment defines all variables available to expressions and custom functions.
func envOptions(eventType EventType) []expr.Option {
	opts := []expr.Option{
		expr.AsBool(),       // match expressions must return bool
		expr.AllowUndefinedVariables(), // forward compat: unknown vars → zero value

		// Custom functions
		expr.Function("has_tag", hasTagFn,
			new(func([]string, string) bool),
		),
		expr.Function("duration", durationFn,
			new(func(string) float64),
		),
		expr.Function("since", sinceFn,
			new(func(float64) float64),
		),
	}

	// Declare typed environment variables per event type so expr can
	// type-check at compile time. We use Env() with a map schema.
	env := baseEnv()
	switch eventType {
	case EventConnect:
		env["peer_id"] = 0          // uint32 as int
		env["port"] = 0             // uint16 as int
		env["network_id"] = 0       // uint16 as int
		env["peer_score"] = 0       // int
		env["peer_tags"] = []string{}
		env["peer_age_s"] = 0.0     // float64: seconds since peer added
		env["members"] = 0          // int: member count
	case EventDial:
		env["peer_id"] = 0
		env["port"] = 0
		env["network_id"] = 0
	case EventDatagram:
		env["peer_id"] = 0
		env["port"] = 0
		env["network_id"] = 0
		env["size"] = 0
		env["direction"] = ""       // "in" or "out"
	case EventCycle:
		env["network_id"] = 0
		env["members"] = 0
		env["peer_count"] = 0
		env["cycle_num"] = 0
	case EventJoin:
		env["peer_id"] = 0
		env["network_id"] = 0
		env["members"] = 0
	case EventLeave:
		env["peer_id"] = 0
		env["network_id"] = 0
	}

	opts = append(opts, expr.Env(env))
	return opts
}

// baseEnv returns variables common to all event types.
func baseEnv() map[string]interface{} {
	return map[string]interface{}{}
}

// peerEnvOptions returns expr options for sub-expressions that evaluate
// per-peer (e.g. evict_where match). These have a different variable set.
func peerEnvOptions() []expr.Option {
	return []expr.Option{
		expr.AsBool(),
		expr.AllowUndefinedVariables(),
		expr.Function("has_tag", hasTagFn,
			new(func([]string, string) bool),
		),
		expr.Function("duration", durationFn,
			new(func(string) float64),
		),
		expr.Function("since", sinceFn,
			new(func(float64) float64),
		),
		expr.Env(map[string]interface{}{
			"peer_id":    0,
			"peer_score": 0,
			"peer_tags":  []string{},
			"peer_age_s": 0.0,
			"last_seen":  0.0, // unix timestamp
		}),
	}
}

// --- Custom functions ---

// has_tag checks if a tag exists in a tag slice.
func hasTagFn(params ...interface{}) (interface{}, error) {
	tags := params[0].([]string)
	name := params[1].(string)
	for _, t := range tags {
		if t == name {
			return true, nil
		}
	}
	return false, nil
}

// duration parses a Go duration string and returns seconds as float64.
func durationFn(params ...interface{}) (interface{}, error) {
	s := params[0].(string)
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0.0, err
	}
	return d.Seconds(), nil
}

// since returns seconds elapsed since the given unix timestamp.
func sinceFn(params ...interface{}) (interface{}, error) {
	ts := params[0].(float64)
	if ts <= 0 {
		return 0.0, nil
	}
	elapsed := time.Since(time.Unix(int64(ts), 0))
	return elapsed.Seconds(), nil
}
