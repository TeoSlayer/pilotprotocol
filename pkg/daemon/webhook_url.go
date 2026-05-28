// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import "github.com/pilot-protocol/common/urlvalidate"

// ValidateWebhookURL is a thin shim over urlvalidate.Validate. Lives
// in pkg/daemon (rather than plugins/webhook) so the IPC handler in
// ipc.go and external test packages can validate without importing
// the plugin (which would be an upward L7 → L11 edge).
//
// The canonical implementation is pkg/urlvalidate; this shim exists
// only as a stable API surface for callers that pre-date T4.1's
// webhook-inversion.
func ValidateWebhookURL(rawURL string) error {
	return urlvalidate.Validate(rawURL)
}
