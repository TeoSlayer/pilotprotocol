// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"strings"
	"testing"
)

// makeDoc returns a small layersDoc fixture covering both the legacy
// "no public set" default and the P2-active "public subset" mode.
func makeDoc() *layersDoc {
	return &layersDoc{
		Layers: map[string]layerSpec{
			"L1": {
				Packages: []string{"example.com/proj/pkg/protocol"},
			},
			"L4": {
				// L4 declares an explicit public surface: only "beacon"
				// is importable across layer boundaries; "beacon/internal"
				// is layer-internal.
				Packages: []string{
					"example.com/proj/pkg/beacon",
					"example.com/proj/pkg/beacon/internal",
				},
				Public: []string{
					"example.com/proj/pkg/beacon",
				},
			},
			"L7": {
				// L7 has no `public:` set — legacy default applies, all
				// packages remain cross-layer importable.
				Packages: []string{"example.com/proj/pkg/daemon"},
			},
		},
		Utilities: layerSpec{
			Packages: []string{"example.com/proj/internal/util"},
		},
	}
}

func TestValidateLayersDoc_PublicMustBeSubsetOfPackages(t *testing.T) {
	t.Parallel()
	doc := makeDoc()
	if err := validateLayersDoc(doc); err != nil {
		t.Fatalf("baseline doc should validate: %v", err)
	}
	// Add a `public:` entry that isn't in `packages:` — must reject.
	spec := doc.Layers["L4"]
	spec.Public = append(spec.Public, "example.com/proj/pkg/beacon/notlisted")
	doc.Layers["L4"] = spec
	err := validateLayersDoc(doc)
	if err == nil {
		t.Fatal("expected validation error for public ∉ packages")
	}
	if !strings.Contains(err.Error(), "not listed in packages") {
		t.Fatalf("error should mention subset rule: %v", err)
	}
}

func TestBuildPublicIndex_OnlyLayersWithPolicy(t *testing.T) {
	t.Parallel()
	idx := buildPublicIndex(makeDoc())
	if _, ok := idx["L4"]; !ok {
		t.Fatal("L4 sets public:, must appear in index")
	}
	if !idx["L4"]["example.com/proj/pkg/beacon"] {
		t.Fatal("L4 public set must contain beacon")
	}
	if idx["L4"]["example.com/proj/pkg/beacon/internal"] {
		t.Fatal("internal subpackage must NOT be in L4 public set")
	}
	if _, ok := idx["L7"]; ok {
		t.Fatal("L7 has no public: declared — must NOT appear in index (legacy default)")
	}
	if _, ok := idx["L1"]; ok {
		t.Fatal("L1 has no public: declared — must NOT appear in index")
	}
}

func TestBuildLayerPackageResolver_LongestMatchWins(t *testing.T) {
	t.Parallel()
	doc := &layersDoc{
		Layers: map[string]layerSpec{
			"L8": {
				Packages: []string{"example.com/proj/pkg/registry/client"},
			},
			"L11": {
				Packages: []string{"example.com/proj/pkg/registry/server"},
			},
		},
	}
	resolve := buildLayerPackageResolver(doc)
	tests := map[string]string{
		"example.com/proj/pkg/registry/client":         "example.com/proj/pkg/registry/client",
		"example.com/proj/pkg/registry/client/sub":     "example.com/proj/pkg/registry/client",
		"example.com/proj/pkg/registry/server":         "example.com/proj/pkg/registry/server",
		"example.com/proj/pkg/registry/server/replica": "example.com/proj/pkg/registry/server",
		"example.com/proj/pkg/registry/wire":           "", // not in any layer (would be utility)
		"example.com/some/external":                    "",
	}
	for in, want := range tests {
		got := resolve(in)
		if got != want {
			t.Errorf("resolve(%q) = %q, want %q", in, got, want)
		}
	}
}

// simulateCheck runs the same edge-checking logic main() does, in
// isolation, against an in-memory doc + import edges. It returns
// (violations, warnings) so tests can assert on what surfaces.
func simulateCheck(doc *layersDoc, edges []edge) (vs, ws []violation) {
	classify := buildClassifier(doc)
	resolveLayerPkg := buildLayerPackageResolver(doc)
	publicIdx := buildPublicIndex(doc)
	transitionalIdx := buildTransitionalIndex(doc.KnownTransitional)
	consumesIdx := buildConsumesIndex(doc)

	for _, e := range edges {
		src := classify(e.from)
		dst := classify(e.to)
		if src == "" || src == "excluded" {
			continue
		}
		if dst == "" {
			continue
		}
		ok, reason := edgeAllowed(src, dst, consumesIdx)
		if !ok {
			v := violation{
				FromPkg: e.from, FromLay: src,
				ToPkg: e.to, ToLay: dst,
				Reason: reason, Kind: "import",
			}
			if owner, isKnown := transitionalIdx[edgeKey(e.from, e.to)]; isKnown {
				v.Owner = owner
				ws = append(ws, v)
			} else {
				vs = append(vs, v)
			}
			continue
		}
		if src != dst && strings.HasPrefix(dst, "L") {
			toLayerPkg := resolveLayerPkg(e.to)
			if toLayerPkg == "" {
				continue
			}
			pubs, hasPolicy := publicIdx[dst]
			if !hasPolicy {
				continue
			}
			if pubs[toLayerPkg] {
				continue
			}
			v := violation{
				FromPkg: e.from, FromLay: src,
				ToPkg: e.to, ToLay: dst,
				Reason: "P2-internal",
				Kind:   "import",
			}
			if owner, isKnown := transitionalIdx[edgeKey(e.from, e.to)]; isKnown {
				v.Owner = owner
				ws = append(ws, v)
			} else {
				vs = append(vs, v)
			}
		}
	}
	return vs, ws
}

type edge struct{ from, to string }

func TestP2_CrossLayerImportOfInternalSubpackageFails(t *testing.T) {
	t.Parallel()
	// L7 (daemon) imports L4 (beacon)'s internal subpackage —
	// disallowed by P2 since L4 declares `public: [beacon]`.
	doc := makeDoc()
	vs, ws := simulateCheck(doc, []edge{
		{from: "example.com/proj/pkg/daemon", to: "example.com/proj/pkg/beacon/internal"},
	})
	if len(vs) != 1 {
		t.Fatalf("expected 1 P2 violation, got %d (warnings=%d)", len(vs), len(ws))
	}
	if vs[0].Reason != "P2-internal" {
		t.Errorf("wrong reason: %q", vs[0].Reason)
	}
	if vs[0].FromLay != "L7" || vs[0].ToLay != "L4" {
		t.Errorf("wrong layers: %s → %s", vs[0].FromLay, vs[0].ToLay)
	}
}

func TestP2_CrossLayerImportOfPublicPackageOK(t *testing.T) {
	t.Parallel()
	doc := makeDoc()
	vs, ws := simulateCheck(doc, []edge{
		{from: "example.com/proj/pkg/daemon", to: "example.com/proj/pkg/beacon"},
	})
	if len(vs) != 0 || len(ws) != 0 {
		t.Fatalf("public import must be clean, got vs=%v ws=%v", vs, ws)
	}
}

func TestP2_SameLayerImportOfInternalOK(t *testing.T) {
	t.Parallel()
	// Same-layer imports of layer-internal subpackages must be allowed.
	// (Imagine pkg/beacon importing pkg/beacon/internal — both L4.)
	doc := makeDoc()
	vs, ws := simulateCheck(doc, []edge{
		{from: "example.com/proj/pkg/beacon", to: "example.com/proj/pkg/beacon/internal"},
	})
	if len(vs) != 0 || len(ws) != 0 {
		t.Fatalf("same-layer internal import must be clean, got vs=%v ws=%v", vs, ws)
	}
}

func TestP2_LegacyDefault_NoPublicSet_AllImportsAllowed(t *testing.T) {
	t.Parallel()
	// L1 has no `public:` set. Importing pkg/protocol from L7 must
	// remain allowed (legacy default = whole layer is public).
	doc := makeDoc()
	vs, ws := simulateCheck(doc, []edge{
		{from: "example.com/proj/pkg/daemon", to: "example.com/proj/pkg/protocol"},
	})
	if len(vs) != 0 || len(ws) != 0 {
		t.Fatalf("legacy default must allow this import, got vs=%v ws=%v", vs, ws)
	}
}

func TestP2_TransitionalP2ViolationDemotedToWarning(t *testing.T) {
	t.Parallel()
	// Demonstrates that the transitional escape hatch covers P2
	// violations the same way it covers P1: the offending edge
	// surfaces as a warning, not an error, when listed.
	doc := makeDoc()
	doc.KnownTransitional = []transitional{
		{
			From:  "example.com/proj/pkg/daemon",
			To:    "example.com/proj/pkg/beacon/internal",
			Owner: "T-test",
		},
	}
	vs, ws := simulateCheck(doc, []edge{
		{from: "example.com/proj/pkg/daemon", to: "example.com/proj/pkg/beacon/internal"},
	})
	if len(vs) != 0 {
		t.Fatalf("expected 0 hard violations (transitional), got %d", len(vs))
	}
	if len(ws) != 1 || ws[0].Owner != "T-test" {
		t.Fatalf("expected 1 transitional warning with owner T-test, got %v", ws)
	}
}

func TestP2_UpwardImportStillBlockedFirst(t *testing.T) {
	t.Parallel()
	// An upward edge must surface as the strict-downward (P1)
	// violation, not be masked by P2 logic.
	doc := makeDoc()
	vs, _ := simulateCheck(doc, []edge{
		{from: "example.com/proj/pkg/protocol", to: "example.com/proj/pkg/beacon"},
	})
	if len(vs) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(vs))
	}
	if !strings.Contains(vs[0].Reason, "upward import") {
		t.Errorf("expected P1 upward error first, got: %q", vs[0].Reason)
	}
}
