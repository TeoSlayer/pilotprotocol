// SPDX-License-Identifier: AGPL-3.0-or-later

package enterprisecontrol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/authority"
)

func TestFleetStateScannerRedactsAndProtectsSensitiveMaterial(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFleetTestFile(t, filepath.Join(root, "settings.json"), []byte(`{"endpoint":"https://example.test","api_token":"do-not-export","nested":{"password":"also-secret"}}`), 0o600)
	writeFleetTestFile(t, filepath.Join(root, "notes.txt"), []byte("visible operator note\n"), 0o600)
	writeFleetTestFile(t, filepath.Join(root, "intent.seed"), []byte("private seed bytes"), 0o600)
	if err := os.Symlink("notes.txt", filepath.Join(root, "notes-link")); err != nil {
		t.Fatal(err)
	}

	entries, err := scanFleetState(root, filepath.Join(root, ".enterprise-fleet-state-cursor.json"))
	if err != nil {
		t.Fatal(err)
	}
	byPath := make(map[string]authority.FleetStateEntry, len(entries))
	for _, entry := range entries {
		byPath[entry.Path] = entry
	}
	settings := byPath["settings.json"]
	if !settings.Redacted || settings.Protected || bytes.Contains(settings.Content, []byte("do-not-export")) || bytes.Contains(settings.Content, []byte("also-secret")) || !bytes.Contains(settings.Content, []byte("[REDACTED]")) {
		t.Fatalf("settings visibility = %+v content=%s", settings, settings.Content)
	}
	if notes := byPath["notes.txt"]; notes.Protected || string(notes.Content) != "visible operator note\n" || notes.Hash != notes.ContentHash {
		t.Fatalf("notes visibility = %+v", notes)
	}
	if seed := byPath["intent.seed"]; !seed.Protected || len(seed.Content) != 0 || seed.Hash == "" {
		t.Fatalf("seed visibility = %+v", seed)
	}
	if link := byPath["notes-link"]; link.Kind != authority.FleetStateSymlink || !link.Protected || len(link.Content) != 0 {
		t.Fatalf("symlink visibility = %+v", link)
	}

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := buildFleetStateSnapshot("tenant-a", "agent-a", "intent-key", 0, "", entries, privateKey)
	if err != nil || snapshot.Verify(privateKey.Public().(ed25519.PublicKey), time.Now()) != nil {
		t.Fatalf("snapshot error=%v snapshot=%+v", err, snapshot)
	}
}

func TestFleetStateMutationIsConfinedAndRollbackSafe(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	original := []byte("before\n")
	filename := filepath.Join(root, "settings.txt")
	writeFleetTestFile(t, filename, original, 0o600)
	originalHash := sha256.Sum256(original)
	replacement := []byte("after\n")
	replacementHash := sha256.Sum256(replacement)
	mutation := authority.FleetStateMutation{
		Version: authority.FleetStateVersion, ID: "mutation-a", TenantID: "tenant-a", AgentID: "agent-a", ExpectedRevision: 1,
		Operations: []authority.FleetStateMutationOperation{{Kind: authority.FleetStatePutFile, Path: "settings.txt", ExpectedHash: hex.EncodeToString(originalHash[:]), Content: replacement, ContentHash: hex.EncodeToString(replacementHash[:]), Mode: 0o600}},
		Reason:     "Approved settings update", IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix(), KeyID: "authority-key",
	}
	transaction, err := prepareFleetStateMutation(root, mutation)
	if err != nil {
		t.Fatal(err)
	}
	if err := transaction.Apply(); err != nil {
		t.Fatal(err)
	}
	if contents, err := os.ReadFile(filename); err != nil || !bytes.Equal(contents, replacement) {
		t.Fatalf("applied contents=%q err=%v", contents, err)
	}
	if err := transaction.Rollback(); err != nil {
		t.Fatal(err)
	}
	if contents, err := os.ReadFile(filename); err != nil || !bytes.Equal(contents, original) {
		t.Fatalf("rolled back contents=%q err=%v", contents, err)
	}

	mutation.Operations[0].Path = "trust-bundle.json"
	if _, err := prepareFleetStateMutation(root, mutation); err == nil || mutationDetailCode(err) != "protected_path" {
		t.Fatalf("protected mutation error=%v", err)
	}
	mutation.Operations[0].Path = "../outside.txt"
	if _, err := prepareFleetStateMutation(root, mutation); err == nil {
		t.Fatal("path traversal mutation was accepted")
	}
}

func TestFleetStateScannerBoundsLargeTextToTailPreview(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	contents := []byte(strings.Repeat("a", fleetStatePerFilePreviewBytes) + "TAIL")
	writeFleetTestFile(t, filepath.Join(root, "agent.log"), contents, 0o600)
	entries, err := scanFleetState(root, filepath.Join(root, ".enterprise-fleet-state-cursor.json"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("scan entries=%d err=%v", len(entries), err)
	}
	if !entries[0].Truncated || entries[0].ContentOffset == 0 || !bytes.HasSuffix(entries[0].Content, []byte("TAIL")) || len(entries[0].Content) != fleetStatePerFilePreviewBytes {
		t.Fatalf("large preview = %+v", entries[0])
	}
}

func writeFleetTestFile(t *testing.T, filename string, contents []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, contents, mode); err != nil {
		t.Fatal(err)
	}
}
