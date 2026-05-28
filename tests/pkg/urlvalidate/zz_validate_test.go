// SPDX-License-Identifier: AGPL-3.0-or-later

package urlvalidate_test

import (
	"strings"
	"testing"

	"github.com/pilot-protocol/common/urlvalidate"
)

func TestValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		url     string
		wantErr bool
		errMsg  string
	}{
		{"valid http", "http://example.com/hook", false, ""},
		{"valid https", "https://hooks.example.com/pilot", false, ""},
		{"valid with port", "https://example.com:8443/hook", false, ""},
		{"valid routable IPv4", "http://192.168.1.100:9000/hook", false, ""},

		{"ftp scheme", "ftp://example.com/hook", true, "http or https"},
		{"file scheme", "file:///etc/passwd", true, "http or https"},
		{"no scheme", "example.com/hook", true, "http or https"},
		{"empty", "", true, "http or https"},

		{"link-local ipv4", "http://169.254.169.254/metadata", true, "link-local"},
		{"link-local ipv6", "http://[fe80::1]/hook", true, "link-local"},

		{"gcp metadata", "http://metadata.google.internal/", true, "cloud metadata"},
		{"gcp metadata alt", "http://metadata.google.com/", true, "cloud metadata"},
		{"gcp metadata mixed case", "http://Metadata.Google.Internal/", true, "cloud metadata"},
		{"gcp metadata upper case", "http://METADATA.GOOGLE.INTERNAL/", true, "cloud metadata"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := urlvalidate.Validate(tc.url)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for URL %q", tc.url)
				}
				if tc.errMsg != "" && !strings.Contains(err.Error(), tc.errMsg) {
					t.Fatalf("expected error containing %q, got: %v", tc.errMsg, err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error for URL %q: %v", tc.url, err)
			}
		})
	}
}
