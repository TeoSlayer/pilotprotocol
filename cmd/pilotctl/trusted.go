// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"

	"github.com/TeoSlayer/pilotprotocol/internal/trustedagents"
)

func cmdTrusted(args []string) {
	if len(args) < 1 {
		fatalHint("invalid_argument",
			"available: pilotctl trusted list",
			"missing subcommand")
	}
	switch args[0] {
	case "list":
		cmdTrustedList()
	default:
		fatalHint("invalid_argument",
			"available: list",
			"unknown trusted subcommand: %s", args[0])
	}
}

// cmdTrustedList prints the trusted-agents list embedded in this binary
// (the agents whose inbound handshakes the local daemon auto-accepts).
func cmdTrustedList() {
	store, err := trustedagents.NewStore("")
	if err != nil {
		fatalCode("internal", "load embedded list: %v", err)
	}
	snap := store.Snapshot()
	if jsonOutput {
		output(map[string]interface{}{
			"version":   snap.Version,
			"issued_at": snap.IssuedAt,
			"agents":    snap.Agents,
		})
		return
	}
	fmt.Printf("trusted-agents list v%d (issued %s)\n", snap.Version, snap.IssuedAt)
	if len(snap.Agents) == 0 {
		fmt.Println("(no agents — list is empty; daemon will never auto-accept via this path)")
		return
	}
	for _, a := range snap.Agents {
		fmt.Printf("  %-20s %s  added=%s\n", a.Name, a.PublicKey, a.AddedAt)
	}
}
