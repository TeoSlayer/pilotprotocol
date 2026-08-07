// SPDX-License-Identifier: AGPL-3.0-or-later

package authority

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	FleetStateVersion               uint16 = 1
	FleetStateSnapshotDomain               = "pilot-fleet-state-snapshot-v1"
	FleetStateMutationDomain               = "pilot-fleet-state-mutation-v1"
	FleetStateMutationResultDomain         = "pilot-fleet-state-mutation-result-v1"
	MaxFleetStateEntries                   = 10_000
	MaxFleetStateVisibleBytes              = 8 << 20
	MaxFleetStateMutationBytes             = 4 << 20
	MaxFleetStateMutationOperations        = 256
)

type FleetStateEntryKind string

const (
	FleetStateDirectory FleetStateEntryKind = "directory"
	FleetStateFile      FleetStateEntryKind = "file"
	FleetStateSymlink   FleetStateEntryKind = "symlink"
)

// FleetStateEntry is one live .pilot tree entry. Hash always identifies the
// complete local file. Content is a bounded full file or preview; protected
// values and symlinks are represented by metadata/fingerprint only.
type FleetStateEntry struct {
	Path             string              `json:"path"`
	Kind             FleetStateEntryKind `json:"kind"`
	Mode             uint32              `json:"mode"`
	Size             uint64              `json:"size"`
	ModifiedAt       int64               `json:"modified_at"`
	Hash             string              `json:"hash,omitempty"`
	Content          []byte              `json:"content,omitempty"`
	ContentOffset    uint64              `json:"content_offset,omitempty"`
	ContentHash      string              `json:"content_hash,omitempty"`
	Truncated        bool                `json:"truncated,omitempty"`
	Redacted         bool                `json:"redacted,omitempty"`
	Protected        bool                `json:"protected,omitempty"`
	ProtectionReason string              `json:"protection_reason,omitempty"`
}

func (entry FleetStateEntry) Validate() error {
	if !validFleetStatePath(entry.Path) || entry.Mode > 0o7777 || entry.ModifiedAt <= 0 {
		return fmt.Errorf("authority: invalid fleet state entry path, mode, or modification time")
	}
	switch entry.Kind {
	case FleetStateDirectory:
		if entry.Size != 0 || entry.Hash != "" || len(entry.Content) != 0 || entry.ContentHash != "" || entry.ContentOffset != 0 || entry.Truncated || entry.Redacted || entry.Protected {
			return fmt.Errorf("authority: directory fleet state entry carries file fields")
		}
	case FleetStateSymlink:
		if !entry.Protected || entry.Hash == "" || len(entry.Content) != 0 || entry.ContentHash != "" {
			return fmt.Errorf("authority: symlink fleet state entry must be metadata-only")
		}
	case FleetStateFile:
		if !lowerHexIdentifier(entry.Hash, 64) {
			return fmt.Errorf("authority: fleet state file requires a complete SHA-256 hash")
		}
		if entry.Protected {
			if len(entry.Content) != 0 || entry.ContentHash != "" || entry.ContentOffset != 0 || entry.Truncated || entry.Redacted || !boundedFleetText(entry.ProtectionReason, 128, false) {
				return fmt.Errorf("authority: invalid protected fleet state entry")
			}
		} else {
			if len(entry.Content) == 0 && entry.Size != 0 || len(entry.Content) > MaxFleetStateVisibleBytes || !lowerHexIdentifier(entry.ContentHash, 64) {
				return fmt.Errorf("authority: invalid visible fleet state content")
			}
			sum := sha256.Sum256(entry.Content)
			if hex.EncodeToString(sum[:]) != entry.ContentHash {
				return fmt.Errorf("authority: fleet state visible content binding mismatch")
			}
			if entry.Redacted {
				if entry.ContentOffset != 0 || entry.Truncated {
					return fmt.Errorf("authority: redacted fleet state content must be a complete sanitized representation")
				}
			} else if entry.ContentOffset+uint64(len(entry.Content)) > entry.Size {
				return fmt.Errorf("authority: fleet state visible content exceeds original file size")
			}
			if !entry.Truncated && !entry.Redacted && (entry.ContentOffset != 0 || uint64(len(entry.Content)) != entry.Size || entry.ContentHash != entry.Hash) {
				return fmt.Errorf("authority: complete fleet state content differs from file hash")
			}
		}
	default:
		return fmt.Errorf("authority: invalid fleet state entry kind")
	}
	return nil
}

type FleetStateSnapshot struct {
	Version    uint16            `json:"version"`
	ID         string            `json:"id"`
	TenantID   string            `json:"tenant_id"`
	AgentID    string            `json:"agent_id"`
	Revision   uint64            `json:"revision"`
	RootHash   string            `json:"root_hash"`
	Entries    []FleetStateEntry `json:"entries"`
	ObservedAt int64             `json:"observed_at"`
	KeyID      string            `json:"key_id"`
	Signature  string            `json:"signature"`
}

func NewFleetStateSnapshot(tenantID, agentID string, revision uint64, entries []FleetStateEntry, observedAt time.Time, keyID string) (FleetStateSnapshot, error) {
	snapshot := FleetStateSnapshot{
		Version: FleetStateVersion, TenantID: tenantID, AgentID: agentID, Revision: revision,
		Entries: cloneFleetStateEntries(entries), ObservedAt: observedAt.UTC().Unix(), KeyID: keyID,
	}
	sort.Slice(snapshot.Entries, func(i, j int) bool { return snapshot.Entries[i].Path < snapshot.Entries[j].Path })
	root, err := fleetStateRootHash(snapshot.Entries)
	if err != nil {
		return FleetStateSnapshot{}, err
	}
	snapshot.RootHash = root
	digest := sha256.Sum256([]byte(FleetStateSnapshotDomain + "\x00" + tenantID + "\x00" + agentID + "\x00" + fmt.Sprint(revision) + "\x00" + root))
	snapshot.ID = "state-" + hex.EncodeToString(digest[:16])
	if err := snapshot.Validate(); err != nil {
		return FleetStateSnapshot{}, err
	}
	return snapshot, nil
}

func (snapshot FleetStateSnapshot) Validate() error {
	if snapshot.Version != FleetStateVersion || snapshot.Revision == 0 || snapshot.ObservedAt <= 0 || !lowerHexIdentifier(snapshot.RootHash, 64) || len(snapshot.Entries) > MaxFleetStateEntries {
		return fmt.Errorf("authority: invalid fleet state snapshot")
	}
	for name, value := range map[string]string{"id": snapshot.ID, "tenant_id": snapshot.TenantID, "agent_id": snapshot.AgentID, "key_id": snapshot.KeyID} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	visible := 0
	last := ""
	for _, entry := range snapshot.Entries {
		if err := entry.Validate(); err != nil {
			return err
		}
		if last != "" && last >= entry.Path {
			return fmt.Errorf("authority: fleet state entries must be uniquely sorted")
		}
		last = entry.Path
		visible += len(entry.Content)
		if visible > MaxFleetStateVisibleBytes {
			return fmt.Errorf("authority: fleet state visible content exceeds snapshot limit")
		}
	}
	root, err := fleetStateRootHash(snapshot.Entries)
	if err != nil || root != snapshot.RootHash {
		return fmt.Errorf("authority: fleet state root hash mismatch")
	}
	return nil
}

func (snapshot FleetStateSnapshot) Canonical() ([]byte, error) {
	if err := snapshot.Validate(); err != nil {
		return nil, err
	}
	w := canonicalWriter{}
	w.string(FleetStateSnapshotDomain)
	w.u16(snapshot.Version)
	w.string(snapshot.ID)
	w.string(snapshot.TenantID)
	w.string(snapshot.AgentID)
	w.u64(snapshot.Revision)
	w.string(snapshot.RootHash)
	w.i64(snapshot.ObservedAt)
	w.string(snapshot.KeyID)
	return w.Buffer.Bytes(), w.err
}

func (snapshot *FleetStateSnapshot) Sign(privateKey ed25519.PrivateKey) error {
	canonical, err := snapshot.Canonical()
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("authority: invalid fleet state snapshot signing input")
	}
	snapshot.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))
	return nil
}

func (snapshot FleetStateSnapshot) Verify(publicKey ed25519.PublicKey, now time.Time) error {
	if err := snapshot.VerifySignature(publicKey); err != nil {
		return err
	}
	if snapshot.ObservedAt > now.Unix()+int64(MaxBundleClockSkew/time.Second) || snapshot.ObservedAt < now.Add(-24*time.Hour).Unix() {
		return fmt.Errorf("authority: fleet state snapshot is outside its accepted observation window")
	}
	return nil
}

// VerifySignature authenticates a retained snapshot without treating its
// observation time as a live admission credential. Ingestion uses Verify;
// history reads and revision recovery use this method.
func (snapshot FleetStateSnapshot) VerifySignature(publicKey ed25519.PublicKey) error {
	canonical, err := snapshot.Canonical()
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(snapshot.Signature)
	if len(publicKey) != ed25519.PublicKeySize || err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, canonical, signature) {
		return fmt.Errorf("authority: invalid fleet state snapshot signature")
	}
	return nil
}

func fleetStateRootHash(entries []FleetStateEntry) (string, error) {
	hash := sha256.New()
	for _, entry := range entries {
		if err := entry.Validate(); err != nil {
			return "", err
		}
		for _, value := range []string{entry.Path, string(entry.Kind), fmt.Sprint(entry.Mode), fmt.Sprint(entry.Size), fmt.Sprint(entry.ModifiedAt), entry.Hash, fmt.Sprint(entry.ContentOffset), entry.ContentHash, fmt.Sprint(entry.Truncated), fmt.Sprint(entry.Redacted), fmt.Sprint(entry.Protected), entry.ProtectionReason} {
			_, _ = hash.Write([]byte(fmt.Sprintf("%08x", len(value))))
			_, _ = hash.Write([]byte(value))
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

type FleetStateMutationKind string

const (
	FleetStatePutFile       FleetStateMutationKind = "put_file"
	FleetStateDeletePath    FleetStateMutationKind = "delete_path"
	FleetStateMakeDirectory FleetStateMutationKind = "make_directory"
)

type FleetStateMutationOperation struct {
	Kind         FleetStateMutationKind `json:"kind"`
	Path         string                 `json:"path"`
	ExpectedHash string                 `json:"expected_hash,omitempty"`
	Content      []byte                 `json:"content,omitempty"`
	ContentHash  string                 `json:"content_hash,omitempty"`
	Mode         uint32                 `json:"mode,omitempty"`
}

func (operation FleetStateMutationOperation) Validate() error {
	if !validFleetStatePath(operation.Path) || operation.Mode > 0o777 {
		return fmt.Errorf("authority: invalid fleet state mutation path or mode")
	}
	if operation.ExpectedHash != "" && !lowerHexIdentifier(operation.ExpectedHash, 64) {
		return fmt.Errorf("authority: invalid fleet state expected hash")
	}
	switch operation.Kind {
	case FleetStatePutFile:
		if len(operation.Content) > MaxFleetStateMutationBytes || !lowerHexIdentifier(operation.ContentHash, 64) {
			return fmt.Errorf("authority: invalid fleet state put operation")
		}
		sum := sha256.Sum256(operation.Content)
		if hex.EncodeToString(sum[:]) != operation.ContentHash {
			return fmt.Errorf("authority: fleet state put content hash mismatch")
		}
	case FleetStateDeletePath, FleetStateMakeDirectory:
		if len(operation.Content) != 0 || operation.ContentHash != "" {
			return fmt.Errorf("authority: non-put fleet state mutation carries content")
		}
	default:
		return fmt.Errorf("authority: unsupported fleet state mutation operation")
	}
	return nil
}

type FleetStateMutation struct {
	Version          uint16                        `json:"version"`
	ID               string                        `json:"id"`
	TenantID         string                        `json:"tenant_id"`
	AgentID          string                        `json:"agent_id"`
	ExpectedRevision uint64                        `json:"expected_revision"`
	Operations       []FleetStateMutationOperation `json:"operations"`
	Reason           string                        `json:"reason"`
	IssuedAt         int64                         `json:"issued_at"`
	ExpiresAt        int64                         `json:"expires_at"`
	KeyID            string                        `json:"key_id"`
	Signature        string                        `json:"signature"`
}

func (mutation FleetStateMutation) Validate() error {
	if mutation.Version != FleetStateVersion || mutation.ExpectedRevision == 0 || len(mutation.Operations) == 0 || len(mutation.Operations) > MaxFleetStateMutationOperations || mutation.IssuedAt <= 0 || mutation.ExpiresAt <= mutation.IssuedAt || mutation.ExpiresAt-mutation.IssuedAt > int64(MaxFleetCommandTTL/time.Second) {
		return fmt.Errorf("authority: invalid fleet state mutation")
	}
	for name, value := range map[string]string{"id": mutation.ID, "tenant_id": mutation.TenantID, "agent_id": mutation.AgentID, "key_id": mutation.KeyID} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	if !boundedFleetText(mutation.Reason, 256, false) || len(strings.TrimSpace(mutation.Reason)) < 8 {
		return fmt.Errorf("authority: invalid fleet state mutation reason")
	}
	total := 0
	seen := make(map[string]struct{}, len(mutation.Operations))
	for _, operation := range mutation.Operations {
		if err := operation.Validate(); err != nil {
			return err
		}
		if _, duplicate := seen[operation.Path]; duplicate {
			return fmt.Errorf("authority: duplicate fleet state mutation path")
		}
		seen[operation.Path] = struct{}{}
		total += len(operation.Content)
		if total > MaxFleetStateMutationBytes {
			return fmt.Errorf("authority: fleet state mutation content exceeds limit")
		}
	}
	return nil
}

func (mutation FleetStateMutation) Canonical() ([]byte, error) {
	if err := mutation.Validate(); err != nil {
		return nil, err
	}
	w := canonicalWriter{}
	w.string(FleetStateMutationDomain)
	w.u16(mutation.Version)
	w.string(mutation.ID)
	w.string(mutation.TenantID)
	w.string(mutation.AgentID)
	w.u64(mutation.ExpectedRevision)
	w.u16(uint16(len(mutation.Operations)))
	for _, operation := range mutation.Operations {
		w.string(string(operation.Kind))
		w.string(operation.Path)
		w.string(operation.ExpectedHash)
		w.string(operation.ContentHash)
		w.u64(uint64(operation.Mode))
	}
	w.string(mutation.Reason)
	w.i64(mutation.IssuedAt)
	w.i64(mutation.ExpiresAt)
	w.string(mutation.KeyID)
	return w.Buffer.Bytes(), w.err
}

func (mutation *FleetStateMutation) SignWith(sign func([]byte) ([]byte, error)) error {
	canonical, err := mutation.Canonical()
	if err != nil {
		return err
	}
	signature, err := sign(canonical)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("authority: fleet state mutation signing failed")
	}
	mutation.Signature = base64.StdEncoding.EncodeToString(signature)
	return nil
}

func (mutation FleetStateMutation) Verify(publicKey ed25519.PublicKey, now time.Time) error {
	canonical, err := mutation.Canonical()
	if err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize || now.Unix() < mutation.IssuedAt-int64(MaxBundleClockSkew/time.Second) || now.Unix() > mutation.ExpiresAt+int64(MaxBundleClockSkew/time.Second) {
		return fmt.Errorf("authority: fleet state mutation is outside its validity window")
	}
	signature, err := base64.StdEncoding.DecodeString(mutation.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, canonical, signature) {
		return fmt.Errorf("authority: invalid fleet state mutation signature")
	}
	return nil
}

type FleetStateMutationResult struct {
	Version      uint16 `json:"version"`
	TenantID     string `json:"tenant_id"`
	AgentID      string `json:"agent_id"`
	MutationID   string `json:"mutation_id"`
	Status       string `json:"status"`
	DetailCode   string `json:"detail_code,omitempty"`
	FromRevision uint64 `json:"from_revision"`
	ToRevision   uint64 `json:"to_revision"`
	ObservedAt   int64  `json:"observed_at"`
	KeyID        string `json:"key_id"`
	Signature    string `json:"signature"`
}

func (result FleetStateMutationResult) Validate() error {
	if result.Version != FleetStateVersion || result.FromRevision == 0 || result.ObservedAt <= 0 {
		return fmt.Errorf("authority: invalid fleet state mutation result")
	}
	for name, value := range map[string]string{"tenant_id": result.TenantID, "agent_id": result.AgentID, "mutation_id": result.MutationID, "key_id": result.KeyID} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	switch result.Status {
	case "applied":
		if result.ToRevision <= result.FromRevision || result.DetailCode != "" {
			return fmt.Errorf("authority: applied fleet state mutation has invalid revision or detail")
		}
	case "rejected", "failed":
		if result.ToRevision != result.FromRevision || validateIdentifier("detail_code", result.DetailCode) != nil {
			return fmt.Errorf("authority: failed fleet state mutation result is invalid")
		}
	default:
		return fmt.Errorf("authority: invalid fleet state mutation result status")
	}
	return nil
}

func (result FleetStateMutationResult) Canonical() ([]byte, error) {
	if err := result.Validate(); err != nil {
		return nil, err
	}
	w := canonicalWriter{}
	w.string(FleetStateMutationResultDomain)
	w.u16(result.Version)
	w.string(result.TenantID)
	w.string(result.AgentID)
	w.string(result.MutationID)
	w.string(result.Status)
	w.string(result.DetailCode)
	w.u64(result.FromRevision)
	w.u64(result.ToRevision)
	w.i64(result.ObservedAt)
	w.string(result.KeyID)
	return w.Buffer.Bytes(), w.err
}

func (result *FleetStateMutationResult) Sign(privateKey ed25519.PrivateKey) error {
	canonical, err := result.Canonical()
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("authority: invalid fleet state mutation result signing input")
	}
	result.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))
	return nil
}

func (result FleetStateMutationResult) Verify(publicKey ed25519.PublicKey, now time.Time) error {
	canonical, err := result.Canonical()
	if err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize || result.ObservedAt > now.Unix()+int64(MaxBundleClockSkew/time.Second) || result.ObservedAt < now.Add(-24*time.Hour).Unix() {
		return fmt.Errorf("authority: fleet state mutation result is outside its accepted observation window")
	}
	signature, err := base64.StdEncoding.DecodeString(result.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, canonical, signature) {
		return fmt.Errorf("authority: invalid fleet state mutation result signature")
	}
	return nil
}

type FleetStatePersistence interface {
	SaveFleetStateSnapshot(context.Context, FleetStateSnapshot) error
	FleetStateSnapshot(context.Context, string, string) (FleetStateSnapshot, bool, error)
	ListFleetStateSnapshots(context.Context, string) ([]FleetStateSnapshot, error)
	SaveFleetStateMutation(context.Context, FleetStateMutation) error
	ListFleetStateMutations(context.Context, string, string) ([]FleetStateMutation, error)
	SaveFleetStateMutationResult(context.Context, FleetStateMutationResult) error
	ListFleetStateMutationResults(context.Context, string, string) ([]FleetStateMutationResult, error)
}

type FleetStateHistoryPersistence interface {
	ListFleetStateSnapshotHistory(context.Context, string, string, int) ([]FleetStateSnapshot, error)
}

func validFleetStatePath(value string) bool {
	if value == "" || value == "." || len(value) > 512 || !utf8.ValidString(value) || strings.ContainsAny(value, "\\\x00\r\n") || strings.HasPrefix(value, "/") {
		return false
	}
	cleaned := path.Clean(value)
	return cleaned == value && cleaned != ".." && !strings.HasPrefix(cleaned, "../")
}

func cloneFleetStateEntries(entries []FleetStateEntry) []FleetStateEntry {
	cloned := append([]FleetStateEntry(nil), entries...)
	for index := range cloned {
		cloned[index].Content = append([]byte(nil), cloned[index].Content...)
	}
	return cloned
}
