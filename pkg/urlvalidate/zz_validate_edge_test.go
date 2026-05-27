// SPDX-License-Identifier: AGPL-3.0-or-later

package urlvalidate_test

import (
	"strings"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/urlvalidate"
)

func TestValidate_ParseError(t *testing.T) {
	t.Parallel()
	// %ZZ is an invalid percent-encoding → url.Parse returns an error.
	err := urlvalidate.Validate("http://example.com/%ZZ")
	if err == nil || !strings.Contains(err.Error(), "invalid URL") {
		t.Fatalf("want 'invalid URL', got %v", err)
	}
}

func TestValidate_NoHost(t *testing.T) {
	t.Parallel()
	// "http:" parses but Hostname() returns "".
	err := urlvalidate.Validate("http:")
	if err == nil || !strings.Contains(err.Error(), "URL must have a host") {
		t.Fatalf("want 'URL must have a host', got %v", err)
	}
}

func TestValidate_LinkLocalIPv6WithZone(t *testing.T) {
	t.Parallel()
	// The code strips %zoneid before passing to net.ParseIP. Cover that branch.
	err := urlvalidate.Validate("http://[fe80::1%25eth0]/")
	if err == nil || !strings.Contains(err.Error(), "link-local") {
		t.Fatalf("want 'link-local', got %v", err)
	}
}

func TestValidate_LinkLocalIPv4Multicast(t *testing.T) {
	t.Parallel()
	// 224.0.0.1 is in IPv4 link-local multicast block 224.0.0.0/24.
	err := urlvalidate.Validate("http://224.0.0.1/")
	if err == nil || !strings.Contains(err.Error(), "link-local") {
		t.Fatalf("want 'link-local', got %v", err)
	}
}

func TestValidate_NormalPublicHostsAllowed(t *testing.T) {
	t.Parallel()
	// Spot-checks for non-error happy paths beyond what the table covers.
	for _, u := range []string{
		"https://hooks.example.com/webhook",
		"http://example.org:8080/path?x=1",
		"https://api.example.io/audit",
	} {
		if err := urlvalidate.Validate(u); err != nil {
			t.Errorf("%s: unexpected error: %v", u, err)
		}
	}
}
