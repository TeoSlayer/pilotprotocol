// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// loadMetadataFixture parses a testdata metadata.json into appMetadata.
func loadMetadataFixture(t *testing.T, name string) *appMetadata {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	var m appMetadata
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal fixture %s: %v", name, err)
	}
	return &m
}

// (a) metadata.json with a product_demo unmarshals into the new struct.
func TestProductDemoUnmarshal(t *testing.T) {
	m := loadMetadataFixture(t, "metadata.metered.json")
	if m.ProductDemo == nil {
		t.Fatal("metered fixture: product_demo did not unmarshal (nil)")
	}
	d := m.ProductDemo
	if d.Skill != "io.pilot.agentphone" {
		t.Errorf("skill = %q, want io.pilot.agentphone", d.Skill)
	}
	if !d.Metered {
		t.Error("metered fixture: Metered = false, want true")
	}
	if d.Cost == nil {
		t.Fatal("metered fixture: Cost is nil")
	}
	if d.Cost.HardCapUSD != 5.0 {
		t.Errorf("hard_cap_usd = %v, want 5.0", d.Cost.HardCapUSD)
	}
	if len(d.Cost.Operations) == 0 {
		t.Error("metered fixture: cost operations table is empty")
	}
	if got := strings.TrimSpace(d.Quickstart.Command); !strings.HasPrefix(got, "pilotctl appstore call ") {
		t.Errorf("quickstart command = %q, want copy-pasteable call", got)
	}
	if len(d.Examples) < 2 {
		t.Errorf("examples len = %d, want at least 2", len(d.Examples))
	}

	// A local (non-metered) fixture must also decode, with no cost block.
	ml := loadMetadataFixture(t, "metadata.local.json")
	if ml.ProductDemo == nil {
		t.Fatal("local fixture: product_demo did not unmarshal (nil)")
	}
	if ml.ProductDemo.Metered {
		t.Error("local fixture: Metered = true, want false")
	}
	if ml.ProductDemo.Cost != nil {
		t.Error("local fixture: Cost should be nil for a non-metered demo")
	}
}

// A metadata.json WITHOUT a product_demo leaves the field nil (the common,
// non-breaking case).
func TestProductDemoAbsent(t *testing.T) {
	var m appMetadata
	if err := json.Unmarshal([]byte(`{"schema_version":1,"id":"io.pilot.x"}`), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m.ProductDemo != nil {
		t.Fatalf("ProductDemo should be nil when absent, got %+v", m.ProductDemo)
	}
	// And a nil demo renders to empty — never panics.
	if s := RenderInstallDemo("io.pilot.x", m.ProductDemo); s != "" {
		t.Errorf("RenderInstallDemo(nil) = %q, want empty", s)
	}
}

// (b) RenderInstallDemo over the METERED fixture: contains the quickstart
// command AND the budget line.
func TestRenderInstallDemoMetered(t *testing.T) {
	d := loadMetadataFixture(t, "metadata.metered.json").ProductDemo
	out := RenderInstallDemo("io.pilot.agentphone", d)

	if !strings.Contains(out, d.Quickstart.Command) {
		t.Errorf("output missing quickstart command:\n%s", out)
	}
	if !strings.Contains(out, "Budget:") {
		t.Errorf("metered output missing the cost/budget line:\n%s", out)
	}
	if !strings.Contains(out, "$5.00 per Pilot user") {
		t.Errorf("metered output missing the free budget:\n%s", out)
	}
	if !strings.Contains(out, "balance:") {
		t.Errorf("metered output missing the check-balance line:\n%s", out)
	}
	// The worked example commands should appear.
	if !strings.Contains(out, "agentphone.place_call") {
		t.Errorf("metered output missing a worked example command:\n%s", out)
	}
}

// (b, cont.) RenderInstallDemo over the NON-METERED fixture: contains the
// quickstart command but does NOT print a cost line.
func TestRenderInstallDemoLocal(t *testing.T) {
	d := loadMetadataFixture(t, "metadata.local.json").ProductDemo
	out := RenderInstallDemo("io.pilot.duckdb", d)

	if !strings.Contains(out, d.Quickstart.Command) {
		t.Errorf("output missing quickstart command:\n%s", out)
	}
	if strings.Contains(out, "Budget:") {
		t.Errorf("non-metered output should NOT contain a cost line:\n%s", out)
	}
	if strings.Contains(out, "balance:") {
		t.Errorf("non-metered output should NOT contain a balance line:\n%s", out)
	}
}

// (c) RenderInstallDemo is a PURE function of its data — the demo content lives
// in metadata.json (the datasource), decoupled from this insertion mechanism.
// Same input → same output, and it embeds no app-specific content of its own.
func TestRenderInstallDemoIsPure(t *testing.T) {
	d := loadMetadataFixture(t, "metadata.metered.json").ProductDemo
	a := RenderInstallDemo("io.pilot.agentphone", d)
	b := RenderInstallDemo("io.pilot.agentphone", d)
	if a != b {
		t.Error("RenderInstallDemo is not deterministic for equal input")
	}
	// Nothing in the render is hard-coded per app: a different appID + demo
	// produces the other fixture's content, not agentphone's.
	loc := loadMetadataFixture(t, "metadata.local.json").ProductDemo
	other := RenderInstallDemo("io.pilot.duckdb", loc)
	if strings.Contains(other, "agentphone") {
		t.Error("renderer leaked app-specific content across demos")
	}
	if !strings.Contains(other, loc.Quickstart.Command) {
		t.Error("renderer did not use the supplied demo's data")
	}
}
