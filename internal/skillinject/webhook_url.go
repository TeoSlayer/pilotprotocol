// SPDX-License-Identifier: AGPL-3.0-or-later

package skillinject

import (
	"os"
	"path/filepath"
	"strings"
)

// webhookURLFile is the path the webhook plugin reads on Service.Start.
// Sibling to webhook_url.go in plugins/webhook (LoadPersistedURL). We
// don't import the plugin here — that would create a layering edge —
// so the path is duplicated as a known string. If LoadPersistedURL
// ever moves, this constant has to follow.
const webhookURLFile = "webhook_url"

// pilotWebhookURLPath returns the canonical file the daemon's webhook
// plugin reads on startup. Centralized so the test harness can override
// HOME and exercise the file path without rebuilding the plugin.
func pilotWebhookURLPath(home string) string {
	return filepath.Join(home, ".pilot", webhookURLFile)
}

// pickWebhookURL walks the manifest's tools in order and returns the
// first non-empty WebhookURL whose corresponding rootDir exists on
// disk (i.e. the tool is actually installed). Empty result = no tool
// asked for a URL OR no asking tool is installed. Caller leaves the
// existing file alone in that case rather than blanking it.
func pickWebhookURL(tools []ManifestTool, home string) (url string, toolName string) {
	for _, mt := range tools {
		if mt.WebhookURL == "" {
			continue
		}
		root := expandHome(mt.RootDir, home)
		if !dirExists(root) {
			continue
		}
		return mt.WebhookURL, mt.Name
	}
	return "", ""
}

// reconcileWebhookURL writes the picked URL to ~/.pilot/webhook_url so
// the next pilot-daemon restart hands it to the webhook plugin. If the
// file already contains the picked URL, this is a noop. Returns an
// Outcome that surfaces in the tick report.
//
// Today the daemon picks up the change on next restart (hourly via the
// auto-updater, or whenever the operator restarts). Hot-swapping a
// running daemon requires plumbing a callback through skillinject.Run
// → cmd/daemon — left as future work; documented in the manifest
// field comment.
func reconcileWebhookURL(home string, tools []ManifestTool) Outcome {
	url, toolName := pickWebhookURL(tools, home)
	path := pilotWebhookURLPath(home)
	o := Outcome{Tool: toolName, Kind: KindWebhookURL, Path: path}
	if url == "" {
		// No tool wants a URL right now. Leave any existing file in
		// place — operator may have set it manually via pilotctl. We
		// only manage the URL when we have one to write.
		o.State = StateIdentical
		o.Action = ActionNoop
		return o
	}

	current, err := os.ReadFile(path)
	if err == nil && strings.TrimSpace(string(current)) == url {
		o.State = StateIdentical
		o.Action = ActionNoop
		return o
	}
	if err != nil && !os.IsNotExist(err) {
		o.State = StateDrifted
		o.Action = ActionError
		o.Err = err.Error()
		return o
	}
	o.State = StateDrifted
	if os.IsNotExist(err) {
		o.State = StateAbsent
	}
	o.Action = actionFor(o.State)

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		o.Action = ActionError
		o.Err = "ensure parent dir: " + err.Error()
		return o
	}
	if err := writeFileAtomic(path, []byte(url), 0o600); err != nil {
		o.Action = ActionError
		o.Err = err.Error()
		return o
	}
	return o
}
