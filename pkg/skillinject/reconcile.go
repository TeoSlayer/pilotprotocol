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
// block exists with any hash it is replaced in place; otherwise the block
// is appended (with a leading blank line if needed). All content outside
// the marker block is preserved byte-for-byte.
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
			current = markerRE.ReplaceAllString(current, block)
			next = []byte(current)
		} else {
			sep := ""
			if len(existing) > 0 && !strings.HasSuffix(current, "\n") {
				sep = "\n"
			}
			if len(existing) > 0 {
				sep += "\n"
			}
			next = []byte(current + sep + block)
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
