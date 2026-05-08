// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestLoadSkipsSnapshotIDPConfigWithInvalidURL ensures the snapshot restore
// path does not propagate an SSRF URL into identityWebhookURL. Legacy
// snapshots written before the URL validators existed could contain any
// value; the restore must re-validate and skip the config rather than
// quietly loading an attacker-controlled metadata endpoint.
func TestLoadSkipsSnapshotIDPConfigWithInvalidURL(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	storePath := filepath.Join(dir, "registry.json")

	snap := snapshot{
		Version:  1,
		NextNode: 1,
		NextNet:  1,
		IDPConfig: &BlueprintIdentityProvider{
			Type: "webhook",
			URL:  "http://Metadata.Google.Internal/",
		},
		AuditExportCfg: &BlueprintAuditExport{
			Format:   "splunk_hec",
			Endpoint: "http://169.254.169.254/services/collector",
		},
	}
	data, err := json.Marshal(&snap)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	if err := os.WriteFile(storePath, data, 0o600); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}

	s := NewWithStore("", storePath)
	defer s.Close()

	// Give load() a chance to finish. NewWithStore calls it synchronously
	// before returning, but the field read races with background goroutines
	// that also touch the server — take the lock.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		loaded := s.identity.GetWebhookURL() != "" || s.identity.GetIDPConfig() != nil || s.auditStore.ExporterConfig() != nil
		if loaded {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	idpURL := s.identity.GetWebhookURL()
	idpCfg := s.identity.GetIDPConfig()
	exportCfg := s.auditStore.ExporterConfig()

	if idpURL != "" {
		t.Fatalf("identityWebhookURL should be empty after skipping invalid snapshot URL, got %q", idpURL)
	}
	if idpCfg != nil {
		t.Fatalf("idpConfig should be nil after skipping invalid snapshot URL, got %+v", idpCfg)
	}
	if exportCfg != nil {
		t.Fatalf("auditExportConfig should be nil after skipping invalid snapshot endpoint, got %+v", exportCfg)
	}
}
