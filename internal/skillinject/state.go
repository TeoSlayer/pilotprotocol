// SPDX-License-Identifier: AGPL-3.0-or-later

package skillinject

import (
	"os"
	"time"
)

// State is the classification of one managed file at the start of a tick.
type State string

const (
	// File (or marker block) does not exist on disk.
	StateAbsent State = "absent"
	// File/marker exists and matches the canonical we want.
	StateIdentical State = "identical"
	// File/marker exists but the content/hash differs from canonical.
	StateDrifted State = "drifted"
)

// Action is what the reconcile loop chose to do in response to a State.
type Action string

const (
	ActionNoop    Action = "noop"
	ActionCreate  Action = "create"
	ActionRewrite Action = "rewrite"
	ActionError   Action = "error"
)

// FileKind names which of a target's managed surfaces an Outcome is
// about.
type FileKind string

const (
	KindSkill           FileKind = "skill"
	KindMarker          FileKind = "marker"
	KindHelper          FileKind = "helper"
	KindPluginFile      FileKind = "plugin_file"
	KindPluginAllowList FileKind = "plugin_allowlist"
)

func actionFor(s State) Action {
	switch s {
	case StateAbsent:
		return ActionCreate
	case StateDrifted:
		return ActionRewrite
	default:
		return ActionNoop
	}
}

// Outcome records one reconcile decision.
type Outcome struct {
	Tool   string   `json:"tool"`
	Kind   FileKind `json:"kind"`
	Path   string   `json:"path"`
	State  State    `json:"state"`
	Action Action   `json:"action"`
	Hash   string   `json:"hash,omitempty"`
	Err    string   `json:"err,omitempty"`
}

// Report is the result of one Tick.
type Report struct {
	At       time.Time `json:"at"`
	Outcomes []Outcome `json:"outcomes"`
	Skipped  []string  `json:"skipped,omitempty"`
	// Disabled is true if the tick was a no-op because the user has
	// `pilotctl skills disable`'d injection.
	Disabled bool `json:"disabled,omitempty"`
}

// Counts returns how many outcomes hit each Action.
func (r *Report) Counts() map[Action]int {
	c := map[Action]int{}
	for _, o := range r.Outcomes {
		c[o.Action]++
	}
	return c
}

// classifySkill inspects path and returns the State of the skill copy.
func classifySkill(path, wantHash string) State {
	cur, err := os.ReadFile(path)
	if err != nil {
		return StateAbsent
	}
	if sha256Hex(cur) == wantHash {
		return StateIdentical
	}
	return StateDrifted
}

// classifyMarker inspects the heartbeat file at path and returns the State
// of *our* marker block within it.
func classifyMarker(path, wantShort string) State {
	cur, err := os.ReadFile(path)
	if err != nil {
		return StateAbsent
	}
	m := markerRE.FindStringSubmatch(string(cur))
	if m == nil {
		return StateAbsent
	}
	if m[1] == wantShort {
		return StateIdentical
	}
	return StateDrifted
}

// classifyPluginFile inspects a plugin source file at path and returns
// the State by content-hash comparison. Identical → noop; drifted →
// rewrite; absent → create.
func classifyPluginFile(path, wantHash string) State {
	cur, err := os.ReadFile(path)
	if err != nil {
		return StateAbsent
	}
	if sha256Hex(cur) == wantHash {
		return StateIdentical
	}
	return StateDrifted
}
