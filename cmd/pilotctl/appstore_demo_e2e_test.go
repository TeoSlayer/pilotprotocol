// SPDX-License-Identifier: AGPL-3.0-or-later
//
// End-to-end test for the product-demo install render. The fixtures under
// testdata/e2e/ are REAL metadata.json files produced by app-template's
// production BuildMetadata path from the merged io.pilot.duckdb and
// io.pilot.agentphone submissions — not hand-written. This test drives them
// through the same appMetadata unmarshal + RenderInstallDemo that
// `pilotctl appstore install` runs at its last step, so a green run proves the
// whole chain: submission.json -> metadata.json -> the banner an agent sees.

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func e2eMetadata(t *testing.T, name string) *appMetadata {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "e2e", name))
	if err != nil {
		t.Fatalf("read e2e fixture %s: %v", name, err)
	}
	var m appMetadata
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal %s into appMetadata: %v", name, err)
	}
	return &m
}

func TestE2E_LocalDemoRender(t *testing.T) {
	m := e2eMetadata(t, "duckdb.metadata.json")
	if m.ProductDemo == nil {
		t.Fatal("real duckdb metadata.json carried no product_demo through BuildMetadata")
	}
	out := RenderInstallDemo(m.ID, m.ProductDemo)
	// The banner an agent sees must carry the real first call and its method.
	if !strings.Contains(out, "io.pilot.duckdb installed") {
		t.Errorf("missing install headline:\n%s", out)
	}
	if !strings.Contains(out, m.ProductDemo.Quickstart.Command) {
		t.Errorf("banner missing the real quickstart command:\n%s", out)
	}
	if !strings.Contains(out, "duckdb.query") {
		t.Errorf("banner missing a real duckdb method:\n%s", out)
	}
	// Non-metered app: no budget line.
	if strings.Contains(out, "Budget:") {
		t.Errorf("non-metered banner must not show a budget line:\n%s", out)
	}
}

func TestE2E_MeteredDemoRender(t *testing.T) {
	m := e2eMetadata(t, "agentphone.metadata.json")
	if m.ProductDemo == nil {
		t.Fatal("real agentphone metadata.json carried no product_demo")
	}
	out := RenderInstallDemo(m.ID, m.ProductDemo)
	for _, want := range []string{
		"io.pilot.agentphone installed",
		m.ProductDemo.Quickstart.Command,
		"agentphone.place_call", // a real worked-example method
		"Budget:",               // metered → budget line present
		"$5.00 per Pilot user",  // the real per-user budget
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metered banner missing %q:\n%s", want, out)
		}
	}
	// The worked flow the banner advertises must stay within the $5 budget: sum
	// the flat per-step dollar costs from the real demo.
	var total float64
	for _, s := range append([]demoStep{m.ProductDemo.Quickstart}, m.ProductDemo.Examples...) {
		total += leadingDollar(s.Cost)
	}
	if m.ProductDemo.Cost != nil && total > m.ProductDemo.Cost.HardCapUSD+1e-9 {
		t.Errorf("real worked flow spends $%.2f, over the $%.2f budget", total, m.ProductDemo.Cost.HardCapUSD)
	}
}

// leadingDollar extracts the dollar amount from a step cost like "$0.10" or
// "$0.00 (read)". Returns 0 when there is no "$n" amount (e.g. "dynamic").
func leadingDollar(cost string) float64 {
	i := strings.Index(cost, "$")
	if i < 0 {
		return 0
	}
	s := cost[i+1:]
	end := 0
	for end < len(s) && (s[end] == '.' || (s[end] >= '0' && s[end] <= '9')) {
		end++
	}
	v, err := strconv.ParseFloat(s[:end], 64)
	if err != nil {
		return 0
	}
	return v
}
