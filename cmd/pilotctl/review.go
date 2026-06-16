// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/pilot-protocol/common/protocol"
	"github.com/pilot-protocol/trustedagents"
)

// reviewPayload is the JSON body sent to the feedback agent.
type reviewPayload struct {
	Kind      string `json:"kind"`                 // always "review"
	Target    string `json:"target"`               // "pilot" or the app identifier
	Rating    int    `json:"rating,omitempty"`      // 1–5, 0 = unrated
	Text      string `json:"text,omitempty"`        // free-form review text
	Timestamp int64  `json:"timestamp,omitempty"`   // unix epoch seconds
}

const (
	reviewFeedbackHostname = "feedback"
	reviewFeedbackNodeID   = 16437
)

// cmdReview dispatches the `pilotctl review` command.
//
// Usage:  pilotctl review <pilot|app-id> [--rating 1-5] [--text "..."]
//
// Sends a structured review event as a datagram to the Feedback agent
// (node 16437, hostname "feedback"). The feedback agent forwards the
// review to the telemetry pipeline where it is persisted as a signed
// "kind=review" event.
func cmdReview(args []string) {
	flags, pos := parseFlags(args)

	if len(pos) < 1 {
		fatalCode("invalid_argument",
			"usage: pilotctl review <pilot|app-id> [--rating 1-5] [--text \"...\"]")
	}

	target := strings.TrimSpace(pos[0])
	if target == "" {
		fatalCode("invalid_argument", "review target cannot be empty")
	}

	rating := flagInt(flags, "rating", 0)
	text := flagString(flags, "text", "")

	if rating < 0 || rating > 5 {
		fatalCode("invalid_argument", "--rating must be between 1 and 5 (or 0 to omit)")
	}
	if text != "" {
		text = strings.TrimSpace(text)
		if len(text) > 4096 {
			fatalCode("invalid_argument", "review text must not exceed 4096 characters")
		}
	}

	if rating == 0 && text == "" {
		fatalCode("invalid_argument",
			"provide at least one of --rating or --text")
	}

	// Build the review payload
	payload := reviewPayload{
		Kind:      "review",
		Target:    target,
		Rating:    rating,
		Text:      text,
		Timestamp: time.Now().Unix(),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		fatalCode("internal", "marshal review: %v", err)
	}

	// Connect to the daemon and resolve the feedback agent.
	d := connectDriver()
	defer d.Close()

	// Find the feedback agent — first from trusted-agents list, then
	// fall back to hostname resolution.
	var feedbackAddr protocol.Addr
	allAgents := trustedagents.All()
	var agent *trustedagents.Agent
	for i := range allAgents {
		if allAgents[i].NodeID == reviewFeedbackNodeID || allAgents[i].Hostname == reviewFeedbackHostname {
			agent = &allAgents[i]
			break
		}
	}
	if agent == nil {
		result, rerr := d.ResolveHostname(reviewFeedbackHostname)
		if rerr != nil {
			fatalHint("not_found",
				"ensure the daemon is running and has reached the registry",
				"cannot find the feedback agent: %v", rerr)
		}
		addrStr, _ := result["address"].(string)
		fa, perr := protocol.ParseAddr(addrStr)
		if perr != nil {
			fatalCode("connection_failed", "parse feedback address %q: %v", addrStr, perr)
		}
		feedbackAddr = fa
	} else {
		addr, perr := protocol.ParseAddr(agent.Address)
		if perr != nil {
			fatalCode("internal", "parse trusted agent address %q: %v", agent.Address, perr)
		}
		feedbackAddr = addr
	}

	// Auto-handshake: the feedback agent is in the trusted-agents list,
	// so the daemon auto-approves on first contact.
	maybeAutoHandshake(d, feedbackAddr, false)

	// Send the review as a datagram (fire-and-forget) on STDI/O port.
	if err := d.SendTo(feedbackAddr, protocol.PortStdIO, body); err != nil {
		fatalCode("connection_failed", "send review: %v", err)
	}

	if jsonOutput {
		outputOK(map[string]interface{}{
			"target":  target,
			"rating":  rating,
			"text":    text,
			"to_node": int(reviewFeedbackNodeID),
		})
		return
	}

	// Human output
	fmt.Printf("review submitted for %s → feedback agent (node %d)\n", target, reviewFeedbackNodeID)
	if rating > 0 {
		if text != "" {
			fmt.Printf("  rating: %d/5, text: %q\n", rating, text)
		} else {
			fmt.Printf("  rating: %d/5\n", rating)
		}
	} else if text != "" {
		fmt.Printf("  text: %q\n", text)
	}
}
