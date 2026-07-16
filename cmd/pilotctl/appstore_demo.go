// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Install-time "product demo" rendering.
//
// An app's catalogue metadata.json (fetched + sha-verified via
// catalogueEntry.MetadataURL/MetadataSHA — see appstore_metadata.go) may
// carry an optional `product_demo`: a compact, example-driven usage guide
// authored once at submit time. It is a superset of <ns>.help tuned for a
// small-context agent: one first call, a handful of worked examples, and — for
// metered apps — an explicit cost/budget line.
//
// The DATA (the demo itself) lives entirely in metadata.json; this file is only
// the INSERTION mechanism — a single pure renderer plus the last-step install
// hook. The two are decoupled: RenderInstallDemo is a pure function of its
// argument and knows nothing about any specific app, and maybeShowProductDemo
// only sources the data (via the sha-verified metadata) and prints it.
//
// Everything here is additive and best-effort: when `product_demo` is absent
// (the common case for existing apps), or malformed, install behaves exactly
// as before. The demo lives inside the already-sha-verified metadata.json, so
// it introduces no new trust surface.

package main

import (
	"fmt"
	"strings"
)

// ProductDemo mirrors the FROZEN `product_demo` object authors write in
// submission.json and that flows verbatim into catalogue metadata.json. Every
// field is optional at the wire level; a nil *ProductDemo means "no demo".
type ProductDemo struct {
	Skill      string     `json:"skill"`
	Title      string     `json:"title,omitempty"`
	WhenToUse  string     `json:"when_to_use"`
	Metered    bool       `json:"metered"`
	Quickstart demoStep   `json:"quickstart"`
	Examples   []demoStep `json:"examples"`
	Cost       *demoCost  `json:"cost,omitempty"`
	Gotchas    []string   `json:"gotchas,omitempty"`
	Next       []string   `json:"next,omitempty"`
}

// demoStep is one runnable example: a goal, the exact command, the output to
// expect, and (for metered spending calls) the cost of running it.
type demoStep struct {
	Title   string `json:"title,omitempty"`
	Goal    string `json:"goal,omitempty"`
	Command string `json:"command"`
	Expect  string `json:"expect,omitempty"`
	Cost    string `json:"cost,omitempty"`
	Note    string `json:"note,omitempty"`
}

// demoCost is the per-app cost breakdown for a metered app.
type demoCost struct {
	Unit         string       `json:"unit"`
	FreeBudget   string       `json:"free_budget"`
	HardCapUSD   float64      `json:"hard_cap_usd"`
	Operations   []demoCostOp `json:"operations"`
	WorkedTotal  string       `json:"worked_total,omitempty"`
	CheckBalance string       `json:"check_balance,omitempty"`
}

// demoCostOp is one row of the price table.
type demoCostOp struct {
	Op    string `json:"op"`
	Price string `json:"price,omitempty"`
	Note  string `json:"note,omitempty"`
}

// titleOr returns the demo title, defaulting to "Full usage demo".
func (d *ProductDemo) titleOr() string {
	if strings.TrimSpace(d.Title) != "" {
		return d.Title
	}
	return "Full usage demo"
}

// RenderInstallDemo produces the compact banner pilotctl prints at the last
// step of a successful install: a headline, the first call, the worked
// examples, and (for metered apps) a one-line budget summary + balance check.
// Deterministic and side-effect free — a pure function of (appID, d). Returns
// "" for a nil demo.
func RenderInstallDemo(appID string, d *ProductDemo) string {
	if d == nil {
		return ""
	}
	var b strings.Builder
	bar := strings.Repeat("─", 64)
	fmt.Fprintf(&b, "%s\n", bar)
	fmt.Fprintf(&b, "  %s installed — %s\n", appID, d.titleOr())
	fmt.Fprintf(&b, "%s\n\n", bar)
	if wt := strings.TrimSpace(d.WhenToUse); wt != "" {
		fmt.Fprintf(&b, "  When to use: %s\n\n", wt)
	}

	if strings.TrimSpace(d.Quickstart.Command) != "" {
		b.WriteString("  ▶ Run this first:\n")
		fmt.Fprintf(&b, "    %s\n", d.Quickstart.Command)
		if d.Quickstart.Expect != "" {
			fmt.Fprintf(&b, "    → %s\n", oneLineDemo(d.Quickstart.Expect))
		}
		b.WriteString("\n")
	}

	if len(d.Examples) > 0 {
		b.WriteString("  ▶ More examples:\n")
		for _, ex := range d.Examples {
			if ex.Title != "" {
				fmt.Fprintf(&b, "    # %s%s\n", ex.Title, demoCostSuffix(d.Metered, ex.Cost))
			}
			if strings.TrimSpace(ex.Command) != "" {
				fmt.Fprintf(&b, "    %s\n", ex.Command)
			}
		}
		b.WriteString("\n")
	}

	if d.Metered && d.Cost != nil {
		fmt.Fprintf(&b, "  ▶ Budget: %s. ", strings.TrimSpace(d.Cost.FreeBudget))
		if strings.TrimSpace(d.Cost.WorkedTotal) != "" {
			fmt.Fprintf(&b, "%s\n", strings.TrimSpace(d.Cost.WorkedTotal))
		} else {
			b.WriteString("Reads are free; see the price table above.\n")
		}
		if strings.TrimSpace(d.Cost.CheckBalance) != "" {
			fmt.Fprintf(&b, "    balance: %s\n", d.Cost.CheckBalance)
		}
		b.WriteString("\n")
	}
	if len(d.Next) > 0 {
		fmt.Fprintf(&b, "  Full reference: %s\n", strings.Join(d.Next, " · "))
	}
	fmt.Fprintf(&b, "%s\n", bar)
	return b.String()
}

// maybeShowProductDemo is the LAST-step hook of a successful catalogue install:
// if the installed app's sha-verified metadata carries a `product_demo`, print
// the install banner. It is fully best-effort — any failure (offline, malformed
// demo) is swallowed so a completed install is never turned into a failure. It
// sources the demo (data) and prints RenderInstallDemo (mechanism); the two
// stay decoupled.
func maybeShowProductDemo(appID string) {
	defer func() { _ = recover() }() // a demo must never break a finished install
	c, err := loadCatalogue()
	if err != nil {
		return
	}
	var entry *catalogueEntry
	for i := range c.Apps {
		if c.Apps[i].ID == appID {
			entry = &c.Apps[i]
			break
		}
	}
	if entry == nil {
		return
	}
	meta, err := loadAppMetadata(*entry)
	if err != nil || meta == nil || meta.ProductDemo == nil {
		return
	}
	if banner := RenderInstallDemo(appID, meta.ProductDemo); banner != "" {
		fmt.Print(banner)
	}
}

func demoCostSuffix(metered bool, cost string) string {
	if !metered || strings.TrimSpace(cost) == "" {
		return ""
	}
	return "  (" + strings.TrimSpace(cost) + ")"
}

// oneLineDemo collapses newlines so a value is safe inside a single
// Markdown/terminal line.
func oneLineDemo(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}
