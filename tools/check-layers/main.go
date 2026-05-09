// SPDX-License-Identifier: AGPL-3.0-or-later

// Command check-layers verifies the layered architecture. It enforces:
//
//   - P1 — strict downward imports: every Go import must target a layer
//     ≤ source layer - 1.
//   - P2 — single upward interface per layer: when a destination layer
//     declares `public:` in layers.yaml, cross-layer imports may only
//     target one of those packages; sibling packages listed in
//     `packages:` but absent from `public:` are layer-internal.
//   - P5 — tests stay within their layer (when --tests is passed).
//
// Reads layers.yaml from the repo root, runs `go list -json ./...`,
// walks the import graph, and exits non-zero on any forbidden edge.
//
// Known transitional violations (listed under known_transitional in
// layers.yaml) are reported as warnings, not failures, so the build
// stays green during the simplification work even though violations
// exist.
//
// Usage:
//
//	go run ./tools/check-layers ./...        — non-test imports only
//	go run ./tools/check-layers --tests ./... — also walk TestImports + XTestImports (P5)
//
// See docs/architecture/05-VERIFICATION.md for the verification
// framework this is part of.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type layerSpec struct {
	Description string   `yaml:"description"`
	Packages    []string `yaml:"packages"`
	// Consumes lists the layers this layer may directly import. When set,
	// any import targeting a layer NOT in this list (other than utilities
	// and same-layer peers) is a P1-skip violation. When unset, the
	// existing strict-downward rule (no upward imports) applies.
	Consumes []string `yaml:"consumes"`
	// Public is the optional subset of Packages that may be imported
	// from other layers (P2 — single upward interface). When unset, the
	// full Packages list is treated as public, preserving the
	// pre-P2-enforcement behavior. When set, packages listed in
	// Packages but absent from Public are layer-internal: only
	// importable from within the same layer.
	Public []string `yaml:"public"`
}

type transitional struct {
	From  string `yaml:"from"`
	To    string `yaml:"to"`
	Owner string `yaml:"owner"`
}

type sideChannel struct {
	Package                  string   `yaml:"package"`
	Bypasses                 []string `yaml:"bypasses"`
	Rationale                string   `yaml:"rationale"`
	ReviewRequiredForChanges bool     `yaml:"review_required_for_changes"`
}

// bootstrapCallSite is one allowed annotated site for the L5→L1+L2
// bootstrap edge (P8). Loaded here so layers.yaml stays the single
// source of truth; the actual one-marker-only enforcement lives in
// tools/check-bootstrap.
type bootstrapCallSite struct {
	File       string `yaml:"file"`
	Function   string `yaml:"function"`
	LineMarker string `yaml:"line_marker"`
}

type bootstrapException struct {
	Description      string              `yaml:"description"`
	AllowedCallSites []bootstrapCallSite `yaml:"allowed_call_sites"`
}

type layersDoc struct {
	Layers             map[string]layerSpec          `yaml:"layers"`
	Utilities          layerSpec                     `yaml:"utilities"`
	Excluded           layerSpec                     `yaml:"excluded"`
	KnownTransitional  []transitional                `yaml:"known_transitional"`
	SideChannels       map[string]sideChannel        `yaml:"side_channels"`
	BootstrapException map[string]bootstrapException `yaml:"bootstrap_exception"`
}

type pkgInfo struct {
	ImportPath   string   `json:"ImportPath"`
	Imports      []string `json:"Imports"`
	TestImports  []string `json:"TestImports,omitempty"`
	XTestImports []string `json:"XTestImports,omitempty"`
	Deps         []string `json:"Deps,omitempty"`
	Dir          string   `json:"Dir"`
	GoFiles      []string `json:"GoFiles,omitempty"`
	TestGoFiles  []string `json:"TestGoFiles,omitempty"`
	XTestGoFiles []string `json:"XTestGoFiles,omitempty"`
}

// classification = "L1".."L12", "utility", "excluded", or "" (external)
func main() {
	includeTests := flag.Bool("tests", false, "also enforce test-file imports (P5)")
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		args = []string{"./..."}
	}

	doc, err := loadLayersYAML("layers.yaml")
	if err != nil {
		fatalf("load layers.yaml: %v", err)
	}
	if err := validateLayersDoc(doc); err != nil {
		fatalf("layers.yaml: %v", err)
	}

	classify := buildClassifier(doc)
	resolveLayerPkg := buildLayerPackageResolver(doc)
	publicIdx := buildPublicIndex(doc)
	consumesIdx := buildConsumesIndex(doc)
	transitionalIdx := buildTransitionalIndex(doc.KnownTransitional)
	sideChannelTargets := buildSideChannelIndex(doc.SideChannels)

	pkgs, err := goList(args, *includeTests)
	if err != nil {
		fatalf("go list: %v", err)
	}

	violations := []violation{}
	warnings := []violation{}

	checkEdge := func(p pkgInfo, imp, kind string) {
		// Self-imports happen via the xtest pattern: a `package foo_test`
		// in directory pkg/foo imports pkg/foo. Same package — not an
		// upward edge.
		if imp == p.ImportPath {
			return
		}
		src := classify(p.ImportPath)
		if src == "" || src == "excluded" {
			return
		}
		dst := classify(imp)
		if dst == "" {
			return // stdlib or external
		}
		// Side channels are permanent allowed exceptions: any layer
		// listed in `bypasses` may import the side-channel package
		// (or any subpackage of it).
		for target, sc := range sideChannelTargets {
			if imp != target && !strings.HasPrefix(imp, target+"/") {
				continue
			}
			for _, allowed := range sc.Bypasses {
				if allowed == src {
					return
				}
			}
		}
		ok, reason := edgeAllowed(src, dst, consumesIdx)
		if !ok {
			v := violation{
				FromPkg: p.ImportPath,
				FromLay: src,
				ToPkg:   imp,
				ToLay:   dst,
				Reason:  reason,
				Kind:    kind,
			}
			if owner, isKnown := transitionalIdx[edgeKey(p.ImportPath, imp)]; isKnown {
				v.Owner = owner
				warnings = append(warnings, v)
			} else {
				violations = append(violations, v)
			}
			return
		}
		// P2 — single upward interface per layer. Cross-layer imports
		// must target a package listed under the destination layer's
		// `public:` set (or — when `public:` is unset — any package in
		// the layer, preserving the pre-P2 default). Imports inside
		// the same layer are unrestricted.
		if src != dst && strings.HasPrefix(dst, "L") {
			toLayerPkg := resolveLayerPkg(imp)
			if toLayerPkg != "" {
				if pubs, hasPolicy := publicIdx[dst]; hasPolicy {
					if !pubs[toLayerPkg] {
						v := violation{
							FromPkg: p.ImportPath,
							FromLay: src,
							ToPkg:   imp,
							ToLay:   dst,
							Reason:  fmt.Sprintf("P2: %s is layer-internal to %s; cross-layer imports must target one of %s's public packages", toLayerPkg, dst, dst),
							Kind:    kind,
						}
						if owner, isKnown := transitionalIdx[edgeKey(p.ImportPath, imp)]; isKnown {
							v.Owner = owner
							warnings = append(warnings, v)
						} else {
							violations = append(violations, v)
						}
					}
				}
			}
		}
	}

	for _, p := range pkgs {
		for _, imp := range p.Imports {
			checkEdge(p, imp, "import")
		}
		if *includeTests {
			for _, imp := range p.TestImports {
				checkEdge(p, imp, "test")
			}
			for _, imp := range p.XTestImports {
				checkEdge(p, imp, "xtest")
			}
		}
	}

	sort.SliceStable(warnings, func(i, j int) bool {
		return warnings[i].FromPkg < warnings[j].FromPkg
	})
	sort.SliceStable(violations, func(i, j int) bool {
		return violations[i].FromPkg < violations[j].FromPkg
	})

	if len(warnings) > 0 {
		fmt.Fprintln(os.Stderr, "── Transitional violations (known, scheduled for fix) ──")
		for _, v := range warnings {
			fmt.Fprintf(os.Stderr, "  [%s] %s [%s] → %s [%s] (%s): %s\n",
				v.Owner, v.FromPkg, v.FromLay, v.ToPkg, v.ToLay, v.Kind, v.Reason)
		}
		fmt.Fprintln(os.Stderr)
	}

	if len(violations) > 0 {
		fmt.Fprintln(os.Stderr, "── Layer violations (must fix) ──")
		for _, v := range violations {
			fmt.Fprintf(os.Stderr, "  %s [%s] → %s [%s] (%s): %s\n",
				v.FromPkg, v.FromLay, v.ToPkg, v.ToLay, v.Kind, v.Reason)
		}
		fmt.Fprintf(os.Stderr, "\n%d violations\n", len(violations))
		os.Exit(1)
	}

	mode := "imports"
	if *includeTests {
		mode = "imports+tests"
	}
	fmt.Fprintf(os.Stderr, "OK: layered architecture clean — %s (%d packages, %d transitional warnings)\n",
		mode, len(pkgs), len(warnings))
}

type violation struct {
	FromPkg, FromLay string
	ToPkg, ToLay     string
	Reason           string
	Owner            string
	Kind             string // "import", "test", or "xtest"
}

// edgeAllowed returns whether an import from layer `src` to layer `dst`
// is permitted.
//
// Two rules are applied in order:
//  1. No upward imports (dstN > srcN is always forbidden).
//  2. Consumes constraint: if `src` declares a `consumes` list in
//     layers.yaml, only layers in that list (plus utilities and same-layer
//     peers) may be imported. An import targeting any other layer is a
//     P1-skip violation — it jumps past a required abstraction boundary.
func edgeAllowed(src, dst string, consumesIdx map[string]map[string]bool) (bool, string) {
	if dst == "utility" {
		return true, ""
	}
	if dst == "excluded" {
		// Tooling may import excluded packages (they're being moved out).
		// Anyone else importing excluded is a soft warning, but flag it.
		if src == "L12" {
			return true, ""
		}
		return false, "non-tooling import of excluded package"
	}
	if src == "utility" {
		// Utilities are outside the strict stack — no enforcement.
		// They're leaves consumed by everyone; their own imports are
		// reviewed at PR time, not by this checker.
		return true, ""
	}
	if src == "excluded" {
		// don't validate excluded
		return true, ""
	}

	srcN, ok1 := layerOrdinal(src)
	dstN, ok2 := layerOrdinal(dst)
	if !ok1 || !ok2 {
		return false, fmt.Sprintf("unknown layer in edge: %s → %s", src, dst)
	}
	// Same-layer imports are always allowed.
	if dstN == srcN {
		return true, ""
	}
	// Rule 1: no upward imports.
	if dstN > srcN {
		return false, fmt.Sprintf("upward import (%s → %s)", src, dst)
	}
	// Rule 2: if the source layer declares a consumes constraint, the
	// destination layer must appear in it. This catches layer-skipping
	// (e.g. L11 → L7 when L11 is only allowed to import L10).
	if allowed, hasConstraint := consumesIdx[src]; hasConstraint {
		if !allowed[dst] {
			// Build a readable list of what is allowed.
			var permitted []string
			for l := range allowed {
				permitted = append(permitted, l)
			}
			sort.Strings(permitted)
			return false, fmt.Sprintf("layer-skip: %s may only import %v (consumes constraint); importing %s skips the abstraction boundary",
				src, permitted, dst)
		}
	}
	return true, ""
}

// layerOrdinal returns the numeric layer index (1..12) for a label.
func layerOrdinal(label string) (int, bool) {
	if !strings.HasPrefix(label, "L") {
		return 0, false
	}
	n := 0
	if _, err := fmt.Sscanf(label, "L%d", &n); err != nil {
		return 0, false
	}
	return n, true
}

func buildClassifier(doc *layersDoc) func(pkgPath string) string {
	idx := map[string]string{}
	for layer, spec := range doc.Layers {
		for _, p := range spec.Packages {
			idx[p] = layer
		}
	}
	for _, p := range doc.Utilities.Packages {
		idx[p] = "utility"
	}
	for _, p := range doc.Excluded.Packages {
		idx[p] = "excluded"
	}
	return func(pkgPath string) string {
		if c, ok := idx[pkgPath]; ok {
			return c
		}
		// Subpackage match: pkg/daemon/foo classifies same as pkg/daemon.
		for known, layer := range idx {
			if strings.HasPrefix(pkgPath, known+"/") {
				return layer
			}
		}
		return ""
	}
}

// validateLayersDoc enforces simple schema invariants the YAML
// parser does not catch — currently: every entry in a layer's
// `public:` list must also appear in its `packages:` list.
func validateLayersDoc(doc *layersDoc) error {
	for layer, spec := range doc.Layers {
		if len(spec.Public) == 0 {
			continue
		}
		pkgs := map[string]bool{}
		for _, p := range spec.Packages {
			pkgs[p] = true
		}
		for _, p := range spec.Public {
			if !pkgs[p] {
				return fmt.Errorf("layer %s: public package %q is not listed in packages", layer, p)
			}
		}
	}
	return nil
}

// buildLayerPackageResolver maps any importable package path back to
// the canonical layer-package entry it belongs to (i.e. the longest
// prefix in any layer's Packages list). Returns "" for paths that
// are not part of any classified layer (utilities, excluded, stdlib,
// external). Only layer packages are considered — utilities have no
// public/private distinction.
func buildLayerPackageResolver(doc *layersDoc) func(pkgPath string) string {
	var entries []string
	for _, spec := range doc.Layers {
		entries = append(entries, spec.Packages...)
	}
	// Longest-match first so pkg/registry/client beats pkg/registry.
	sort.Slice(entries, func(i, j int) bool { return len(entries[i]) > len(entries[j]) })
	return func(pkgPath string) string {
		for _, e := range entries {
			if pkgPath == e || strings.HasPrefix(pkgPath, e+"/") {
				return e
			}
		}
		return ""
	}
}

// buildPublicIndex returns a per-layer set of public package paths.
// A layer appears in the result only when its spec sets `public:`
// explicitly; absence means "all Packages are public" (the legacy
// default), and the P2 check skips layers without a policy.
func buildPublicIndex(doc *layersDoc) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for layer, spec := range doc.Layers {
		if len(spec.Public) == 0 {
			continue
		}
		set := map[string]bool{}
		for _, p := range spec.Public {
			set[p] = true
		}
		out[layer] = set
	}
	return out
}

// buildConsumesIndex returns a map from layer label to the set of layer
// labels that layer may import. Only layers with an explicit `consumes:`
// list in layers.yaml are included; layers without a constraint fall back
// to the strict-downward rule.
func buildConsumesIndex(doc *layersDoc) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for layer, spec := range doc.Layers {
		if len(spec.Consumes) == 0 {
			continue
		}
		set := map[string]bool{}
		for _, c := range spec.Consumes {
			set[c] = true
		}
		out[layer] = set
	}
	return out
}

func buildTransitionalIndex(items []transitional) map[string]string {
	out := map[string]string{}
	for _, t := range items {
		out[edgeKey(t.From, t.To)] = t.Owner
	}
	return out
}

// buildSideChannelIndex returns a map from target-package importpath to
// the side-channel spec that whitelists imports of that package from
// any layer listed in `bypasses`.
func buildSideChannelIndex(items map[string]sideChannel) map[string]sideChannel {
	out := map[string]sideChannel{}
	for _, sc := range items {
		out[sc.Package] = sc
	}
	return out
}

func edgeKey(from, to string) string { return from + " → " + to }

func loadLayersYAML(path string) (*layersDoc, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		// Fall back to walking up the tree to find layers.yaml.
		cwd, _ := os.Getwd()
		for d := cwd; d != "/" && d != ""; d = filepath.Dir(d) {
			candidate := filepath.Join(d, "layers.yaml")
			if data2, err2 := os.ReadFile(candidate); err2 == nil {
				data = data2
				err = nil
				break
			}
		}
		if err != nil {
			return nil, err
		}
	}
	var doc layersDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

func goList(args []string, withTests bool) ([]pkgInfo, error) {
	listArgs := []string{"list", "-json"}
	if withTests {
		// `-test` makes go list emit TestImports + XTestImports populated
		// for each package and synthesize *.test pseudo-packages. We
		// only consume the original packages' TestImports/XTestImports;
		// the .test entries are skipped below.
		listArgs = append(listArgs, "-test")
	}
	cmd := exec.Command("go", append(listArgs, args...)...)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(strings.NewReader(string(out)))
	var pkgs []pkgInfo
	seen := map[string]bool{}
	for dec.More() {
		var p pkgInfo
		if err := dec.Decode(&p); err != nil {
			return nil, err
		}
		// Skip packages with no Go files (e.g. testdata directories).
		if len(p.GoFiles) == 0 && len(p.TestGoFiles) == 0 && len(p.XTestGoFiles) == 0 {
			continue
		}
		// `go list -test` emits both the original package and a synthetic
		// "*.test" package for the binary. The synthetic one duplicates
		// imports we've already counted under the source package.
		if strings.HasSuffix(p.ImportPath, ".test") {
			continue
		}
		if seen[p.ImportPath] {
			continue
		}
		seen[p.ImportPath] = true
		pkgs = append(pkgs, p)
	}
	return pkgs, nil
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "check-layers: "+format+"\n", args...)
	os.Exit(2)
}
