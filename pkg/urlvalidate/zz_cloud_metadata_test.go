// SPDX-License-Identifier: AGPL-3.0-or-later

package urlvalidate_test

// Regression for SSRF allowlist gaps: the original implementation
// blocked GCP metadata.google.{internal,com} + link-local IPs (which
// covers 169.254.169.254 reaching the EC2/Azure metadata services by
// IP). But the AWS DNS-name path (ec2.internal,
// instance-data-service.ec2.internal) and Azure DNS-name path
// (metadata.azure.com) reached the metadata service without hitting
// the link-local check, leaving an SSRF vector for a webhook
// destination targeting `http://ec2.internal/...`.

import (
	"strings"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/urlvalidate"
)

func TestValidate_BlocksAWSMetadataHostnames(t *testing.T) {
	t.Parallel()

	cases := []string{
		"http://ec2.internal/latest/meta-data/iam/security-credentials/",
		"http://instance-data-service.ec2.internal/",
		"http://EC2.Internal/", // case-insensitive
	}
	for _, in := range cases {
		err := urlvalidate.Validate(in)
		if err == nil {
			t.Errorf("Validate(%q) returned nil — AWS metadata hostname not blocked", in)
			continue
		}
		if !strings.Contains(err.Error(), "metadata") {
			t.Errorf("Validate(%q) error %q does not mention 'metadata'", in, err.Error())
		}
	}
}

func TestValidate_BlocksAzureMetadataHostname(t *testing.T) {
	t.Parallel()

	err := urlvalidate.Validate("http://metadata.azure.com/metadata/instance?api-version=2021-02-01")
	if err == nil {
		t.Fatal("Azure metadata.azure.com not blocked — SSRF vector")
	}
	if !strings.Contains(err.Error(), "metadata") {
		t.Errorf("expected error to mention 'metadata', got: %v", err)
	}
}

func TestValidate_StillAllowsLegitimateHosts(t *testing.T) {
	t.Parallel()

	for _, in := range []string{
		"https://example.com/webhook",
		"https://hooks.slack.com/services/T00/B00/abc",
		"https://internal-api.example.com/",
	} {
		if err := urlvalidate.Validate(in); err != nil {
			t.Errorf("Validate(%q) wrongly rejected: %v", in, err)
		}
	}
}
