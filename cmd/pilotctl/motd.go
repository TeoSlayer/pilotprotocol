// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/pilot-protocol/pilotprotocol/internal/motd"
)

// importantUpdate is the message-of-the-day text active for the current UTC
// day, or "" if none. Loaded once at process start by loadMOTD() from the
// local mirror the daemon maintains — pilotctl never touches the network or
// the daemon for this, so every command stays fast.
var importantUpdate string

// motdMirrorPath is the local file the daemon writes and pilotctl reads. It
// lives in the same ~/.pilot directory pilotctl already uses for config.
func motdMirrorPath() string {
	return filepath.Join(configDir(), "motd.json")
}

// loadMOTD reads the active message-of-the-day from the local mirror. Called
// once near the top of main(). Absent/empty/stale mirrors leave
// importantUpdate empty (no banner).
func loadMOTD() {
	if text, ok := motd.ReadActiveMirror(motdMirrorPath(), time.Now()); ok {
		importantUpdate = text
	}
}

// printMOTDBanner writes the human-readable banner to stdout ahead of a
// command's normal output. It is a no-op in JSON mode (there the message
// rides in the envelope's important_update field instead) and when there is
// no active message.
func printMOTDBanner() {
	if jsonOutput || importantUpdate == "" {
		return
	}
	fmt.Printf("Message of the day: %s\n\n", importantUpdate)
}
