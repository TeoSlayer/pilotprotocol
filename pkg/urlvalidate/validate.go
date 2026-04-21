// Package urlvalidate provides SSRF-prevention checks shared across packages
// that accept operator-supplied URLs (webhook endpoints, audit export sinks,
// identity provider verification callbacks, etc.).
//
// The rules are intentionally conservative:
//   - Only http and https schemes are allowed.
//   - Link-local addresses (IPv4 169.254.0.0/16, IPv6 fe80::/10) are blocked
//     because they include cloud metadata services and host-local adjacencies.
//   - A small allowlist of cloud metadata hostnames is blocked outright. DNS
//     is case-insensitive, so the comparison lowercases the hostname before
//     matching — "Metadata.Google.Internal" must not bypass the blocklist.
//
// Placing this in a neutral package lets both pkg/daemon and pkg/registry
// (which cannot import pkg/daemon) share exactly one implementation.
package urlvalidate

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Validate returns nil if rawURL is an acceptable http(s) endpoint that does
// not point at a link-local or well-known cloud-metadata target. Callers are
// responsible for deciding whether an empty URL (which returns an error here)
// should be interpreted as "disable" before calling.
func Validate(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("URL must use http or https scheme, got %q", parsed.Scheme)
	}
	host := parsed.Hostname()
	if host == "" {
		return fmt.Errorf("URL must have a host")
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("URL cannot target link-local address %s", host)
		}
	}
	switch strings.ToLower(host) {
	case "metadata.google.internal", "metadata.google.com":
		return fmt.Errorf("URL cannot target cloud metadata endpoint %s", host)
	}
	return nil
}
