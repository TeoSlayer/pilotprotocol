// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pilot-protocol/common/consent"

	"github.com/TeoSlayer/pilotprotocol/pkg/telemetry"
)

// reviewHelpText is the canonical help block for `pilotctl review`.
// Registered in commandHelp in main.go so `pilotctl review --help` works.
const reviewHelpText = `Usage: pilotctl review <pilot|app-id> [--rating N] [--text "..."]

Submit a review for Pilot itself or for an installed app.

Arguments:
  pilot           review the Pilot Protocol itself
  <app-id>        review a specific app (e.g. io.pilot.cosift)

Flags:
  --rating N      integer rating 1–5 (optional)
  --text "..."    review text (optional)
  --help          show this help

Examples:
  pilotctl review pilot
  pilotctl review pilot --rating 5 --text "Works great"
  pilotctl review io.pilot.cosift --rating 4
  pilotctl review io.pilot.cosift --text "Very useful app"

Reviews are sent to the telemetry endpoint and are consent-gated: no-op
when reviews consent is off (set {"consent": {"reviews": false}} in
~/.pilot/config.json). When consent is on, falls back to the default
endpoint if PILOT_TELEMETRY_URL is unset.
`

// cmdReview handles `pilotctl review <pilot|app-id> [--rating N] [--text "..."]`.
//
// Validation:
//   - subject is required and must be non-empty
//   - --rating, when present, must be an integer in [1, 5]
//   - --text is free-form (no constraint)
//
// On valid input: routes to telemetry (consent-gated) then confirms.
// On invalid input: prints an error + usage hint to stderr, exits 1.
func cmdReview(args []string) {
	flags, pos := parseFlags(args)

	if len(pos) == 0 {
		if jsonOutput {
			fatalCode("invalid_argument",
				"subject is required: 'pilot' or an app-id (e.g. io.pilot.cosift)")
		}
		fmt.Fprintf(os.Stderr, "error: subject is required\nhint:  usage: pilotctl review <pilot|app-id> [--rating N] [--text \"...\"]\n")
		os.Exit(1)
	}

	subject := pos[0]
	if strings.TrimSpace(subject) == "" {
		fatalCode("invalid_argument", "subject must not be empty")
	}

	// Validate --rating when provided.
	var rating int
	hasRating := false
	if rStr, ok := flags["rating"]; ok {
		hasRating = true
		n, err := strconv.Atoi(rStr)
		if err != nil {
			if jsonOutput {
				fatalCode("invalid_argument",
					"--rating must be an integer between 1 and 5, got %q", rStr)
			}
			fmt.Fprintf(os.Stderr,
				"error: --rating must be an integer between 1 and 5, got %q\nhint:  usage: pilotctl review <pilot|app-id> [--rating N] [--text \"...\"]\n",
				rStr)
			os.Exit(1)
		}
		if n < 1 || n > 5 {
			if jsonOutput {
				fatalCode("invalid_argument",
					"--rating must be between 1 and 5, got %d", n)
			}
			fmt.Fprintf(os.Stderr,
				"error: --rating must be between 1 and 5, got %d\nhint:  usage: pilotctl review <pilot|app-id> [--rating N] [--text \"...\"]\n",
				n)
			os.Exit(1)
		}
		rating = n
	}

	reviewText := flagString(flags, "text", "")

	// Route to telemetry if reviews consent is on (default on when absent).
	// Best-effort: a send failure is logged but not fatal.
	home, _ := os.UserHomeDir()
	if consent.GetConsent(home, "reviews") {
		url := os.Getenv("PILOT_TELEMETRY_URL")
		if url == "" {
			url = telemetry.DefaultEndpoint
		}
		identityPath := configDir() + "/identity.json"
		payload := map[string]interface{}{"subject": subject}
		if hasRating {
			payload["rating"] = rating
		}
		if reviewText != "" {
			payload["text"] = reviewText
		}
		payloadBytes, _ := json.Marshal(payload)
		client := telemetry.NewClientFromIdentity(url, identityPath, nodeIDFromDaemon())
		if err := client.Send(telemetry.Event{
			Kind:    "review",
			TS:      time.Now().UTC().Format(time.RFC3339),
			Payload: payloadBytes,
		}); err != nil {
			slog.Warn("review telemetry send failed, review still accepted", "subject", subject, "err", err)
		}
	}

	if jsonOutput {
		out := map[string]interface{}{
			"subject":   subject,
			"submitted": true,
		}
		if hasRating {
			out["rating"] = rating
		}
		if reviewText != "" {
			out["text"] = reviewText
		}
		outputOK(out)
		return
	}

	fmt.Printf("Review submitted for %s. Thank you!\n", subject)
}
