// SPDX-License-Identifier: AGPL-3.0-or-later

package server_test

import (
	"strings"
	"testing"

	"github.com/pilot-protocol/rendezvous"
)

// TestValidateBlueprintRejectsSSRFURLs guards against a regression where
// blueprint URL fields (identity_provider.url, webhooks.audit_url,
// webhooks.identity_url, audit_export.endpoint) are accepted without
// SSRF validation. Hitting one of these with the GCP metadata hostname
// was the exact path the case-insensitive bypass exploited before the
// urlvalidate extraction.
func TestValidateBlueprintRejectsSSRFURLs(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		bp   server.NetworkBlueprint
		want string
	}{
		{
			name: "identity_provider metadata",
			bp: server.NetworkBlueprint{
				Name: "net",
				IdentityProvider: &server.BlueprintIdentityProvider{
					Type: "webhook",
					URL:  "http://metadata.google.internal/",
				},
			},
			want: "identity_provider.url",
		},
		{
			name: "identity_provider mixed case metadata",
			bp: server.NetworkBlueprint{
				Name: "net",
				IdentityProvider: &server.BlueprintIdentityProvider{
					Type: "webhook",
					URL:  "http://Metadata.Google.Internal/",
				},
			},
			want: "identity_provider.url",
		},
		{
			name: "webhooks.audit_url link-local",
			bp: server.NetworkBlueprint{
				Name: "net",
				Webhooks: &server.BlueprintWebhooks{
					AuditURL: "http://169.254.169.254/latest/meta-data/",
				},
			},
			want: "webhooks.audit_url",
		},
		{
			name: "webhooks.identity_url bad scheme",
			bp: server.NetworkBlueprint{
				Name: "net",
				Webhooks: &server.BlueprintWebhooks{
					IdentityURL: "file:///etc/passwd",
				},
			},
			want: "webhooks.identity_url",
		},
		{
			name: "audit_export.endpoint metadata",
			bp: server.NetworkBlueprint{
				Name: "net",
				AuditExport: &server.BlueprintAuditExport{
					Format:   "splunk_hec",
					Endpoint: "http://metadata.google.internal/services/collector",
				},
			},
			want: "audit_export.endpoint",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := server.ValidateBlueprint(&tc.bp)
			if err == nil {
				t.Fatalf("expected ValidateBlueprint to reject %q", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q missing expected field %q", err, tc.want)
			}
		})
	}
}

// TestValidateBlueprintAllowsSyslogHostPort is a narrow guard: audit_export
// with format=syslog_cef accepts raw host:port targets, so URL validation
// must be skipped for that format. A regression that applied Validate()
// unconditionally would reject syslog sinks and break existing deployments.
func TestValidateBlueprintAllowsSyslogHostPort(t *testing.T) {
	t.Parallel()
	bp := server.NetworkBlueprint{
		Name: "net",
		AuditExport: &server.BlueprintAuditExport{
			Format:   "syslog_cef",
			Endpoint: "siem.internal.example.com:514",
		},
	}
	if err := server.ValidateBlueprint(&bp); err != nil {
		t.Fatalf("syslog_cef host:port endpoint should be allowed, got %v", err)
	}
}
