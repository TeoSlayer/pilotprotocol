// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"testing"
)

// TestSetIDPConfigRejectsSSRF guards the second path into identityWebhookURL.
// handleSetIdentityWebhook is covered by the shared urlvalidate rules; this
// test ensures handleSetIDPConfig enforces the same check. Without it, an
// admin could pivot SSRF by routing the identity provider config at a cloud
// metadata endpoint — the daemon would then POST tokens to that URL on every
// register call and GET JWKS from it on every token validation.
func TestSetIDPConfigRejectsSSRF(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		url  string
	}{
		{"gcp metadata lower", "http://metadata.google.internal/"},
		{"gcp metadata mixed case", "http://Metadata.Google.Internal/"},
		{"link-local ipv4", "http://169.254.169.254/latest/meta-data/"},
		{"bad scheme", "file:///etc/passwd"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rc, _, cleanup := startTestRegistryWithAdmin(t)
			defer cleanup()

			_, err := rc.SetIDPConfig("oidc", tc.url, "https://issuer.example.com", "client-id", "", "", TestAdminToken)
			if err == nil {
				t.Fatalf("expected SetIDPConfig to reject %q", tc.url)
			}
		})
	}
}
