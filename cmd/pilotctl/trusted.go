// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"

	"github.com/pilot-protocol/trustedagents"
)

func cmdTrusted(args []string) {
	if len(args) < 1 || args[0] != "list" {
		fatalHint("invalid_argument",
			"available: pilotctl trusted list",
			"usage: pilotctl trusted list")
	}
	agents := trustedagents.All()
	if len(agents) == 0 {
		fmt.Println("(no trusted agents — daemon will not auto-accept any handshakes via this path)")
		return
	}
	for _, a := range agents {
		fmt.Printf("  %-32s %s  node_id=%d\n", a.Hostname, a.Address, a.NodeID)
	}
}
