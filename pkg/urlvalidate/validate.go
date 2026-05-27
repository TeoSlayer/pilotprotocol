// SPDX-License-Identifier: AGPL-3.0-or-later

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
	// Strip IPv6 zone identifier (e.g. "fe80::1%eth0") before parsing.
	// net.ParseIP does not handle zone suffixes, so without this a
	// link-local address with a zone ID would pass the check unnoticed.
	ipStr := host
	if i := strings.IndexByte(ipStr, '%'); i != -1 {
		ipStr = ipStr[:i]
	}
	if ip := net.ParseIP(ipStr); ip != nil {
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("URL cannot target link-local address %s", host)
		}
	}
	switch strings.ToLower(host) {
	case
		// GCP
		"metadata.google.internal",
		"metadata.google.com",
		// AWS (DNS names that reach the EC2 instance metadata service
		// without traversing the link-local IP path)
		"ec2.internal",
		"instance-data-service.ec2.internal",
		// Azure (IMDS DNS endpoint)
		"metadata.azure.com":
		return fmt.Errorf("URL cannot target cloud metadata endpoint %s", host)
	}
	return nil
}
