// SPDX-License-Identifier: AGPL-3.0-or-later

package urlvalidate_test

import (
	"strings"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/urlvalidate"
)

func TestValidate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		url     string
		wantErr string // non-empty = expect error containing this substring
	}{
		// --- valid ---
		{name: "http ok", url: "http://example.com/webhook"},
		{name: "https ok", url: "https://example.com/webhook"},
		{name: "https with port", url: "https://example.com:8443/path"},
		{name: "https with path and query", url: "https://example.com/hook?token=abc"},
		{name: "http ip public", url: "http://1.2.3.4/hook"},
		{name: "https ip public", url: "https://8.8.8.8/"},

		// --- scheme ---
		{name: "ftp rejected", url: "ftp://example.com/", wantErr: "http or https"},
		{name: "grpc rejected", url: "grpc://example.com/", wantErr: "http or https"},
		{name: "empty scheme", url: "example.com/hook", wantErr: "http or https"},
		{name: "file scheme", url: "file:///etc/passwd", wantErr: "http or https"},

		// --- host ---
		{name: "missing host", url: "https:///path", wantErr: "host"},

		// --- link-local IPv4 ---
		{name: "link-local 169.254.0.1", url: "http://169.254.0.1/", wantErr: "link-local"},
		{name: "link-local 169.254.255.255", url: "http://169.254.255.255/", wantErr: "link-local"},
		{name: "link-local boundary 169.253.x ok", url: "http://169.253.0.1/"},

		// --- link-local IPv6 ---
		{name: "link-local fe80::1", url: "http://[fe80::1]/", wantErr: "link-local"},
		{name: "link-local fe80::abcd", url: "https://[fe80::abcd%25eth0]/", wantErr: "link-local"},

		// --- cloud metadata hostnames ---
		{name: "metadata.google.internal blocked", url: "http://metadata.google.internal/", wantErr: "cloud metadata"},
		{name: "metadata.google.com blocked", url: "http://metadata.google.com/", wantErr: "cloud metadata"},
		{name: "metadata case-insensitive", url: "http://METADATA.GOOGLE.INTERNAL/", wantErr: "cloud metadata"},
		{name: "Metadata mixed case", url: "https://Metadata.Google.Internal/path", wantErr: "cloud metadata"},

		// --- invalid URL ---
		{name: "invalid URL", url: "://badurl", wantErr: "invalid URL"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := urlvalidate.Validate(tc.url)
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("Validate(%q) = %v, want nil", tc.url, err)
				}
			} else {
				if err == nil {
					t.Errorf("Validate(%q) = nil, want error containing %q", tc.url, tc.wantErr)
					return
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("Validate(%q) error = %q, want it to contain %q", tc.url, err.Error(), tc.wantErr)
				}
			}
		})
	}
}
