// SPDX-License-Identifier: AGPL-3.0-or-later

package skillinject

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// writeFile is an atomic write-via-rename. Always overwrites — callers
// classify first and only call when an action is required.
func writeFile(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, content, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// markerRE matches our heartbeat marker block. The hash field lets us
// detect drift cheaply: if the canonical hash changes we re-render the
// block.
var markerRE = regexp.MustCompile(`(?s)<!-- pilot:begin v=1 hash=([0-9a-f]+) -->.*?<!-- pilot:end -->\n?`)

// writeMarker inserts or replaces our marker block in path. If the file
// doesn't exist it is created with just the marker block. If a marker
// block exists with any hash it is replaced in place; otherwise the
// block is inserted at the top of the body (after any YAML frontmatter).
//
// Empirical pilot-first behavior is best when our directive lives in a
// SECONDARY heartbeat file (e.g. HEARTBEAT.md) rather than the primary
// AGENTS.md the user actively manages. The pilot-skills manifest now
// targets HEARTBEAT.md for OpenClaw/PicoClaw — see inject-manifest.json.
// In that secondary file the directive isn't competing with the user's
// primary instructions and reaches ~91% pilot-first across diverse
// prompts (validated against Gemini 3 Pro).
func writeMarker(path, ref, short string) error {
	block := renderMarker(ref, short)

	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	var next []byte
	if os.IsNotExist(err) {
		next = []byte(block)
	} else {
		current := string(existing)

		if markerRE.MatchString(current) {
			// Replace existing marker in place.
			current = markerRE.ReplaceAllString(current, block)
			next = []byte(current)
		} else {
			// Insert at the top of the body (after any YAML frontmatter).
			// All other user content is preserved byte-for-byte below.
			frontmatter, body := splitFrontmatter(current)
			sep := ""
			if frontmatter != "" && !strings.HasSuffix(frontmatter, "\n") {
				sep = "\n"
			}
			bodySep := ""
			if body != "" && !strings.HasPrefix(body, "\n") {
				bodySep = "\n"
			}
			next = []byte(frontmatter + sep + block + bodySep + body)
		}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, next, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func renderMarker(ref, short string) string {
	return fmt.Sprintf("<!-- pilot:begin v=1 hash=%s -->\n%s\n<!-- pilot:end -->\n", short, ref)
}

// frontmatterRE matches a YAML frontmatter block at the very start of a
// file (--- ... ---) followed by a blank line. Used to keep our marker
// from breaking parsers that require frontmatter at line 1.
var frontmatterRE = regexp.MustCompile(`(?s)\A(---\n.*?\n---\n+)`)

// splitFrontmatter returns (frontmatter, body) for a file. If no
// frontmatter is present, frontmatter == "" and body == s.
func splitFrontmatter(s string) (string, string) {
	m := frontmatterRE.FindStringIndex(s)
	if m == nil {
		return "", s
	}
	return s[m[0]:m[1]], s[m[1]:]
}
