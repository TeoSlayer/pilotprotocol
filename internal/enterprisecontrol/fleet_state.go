// SPDX-License-Identifier: AGPL-3.0-or-later

package enterprisecontrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/authority"
)

const fleetStatePerFilePreviewBytes = 256 << 10

type fleetStateCursor struct {
	TenantID       string                               `json:"tenant_id"`
	AgentID        string                               `json:"agent_id"`
	Revision       uint64                               `json:"revision"`
	RootHash       string                               `json:"root_hash"`
	PendingResults []authority.FleetStateMutationResult `json:"pending_results,omitempty"`
}

// FleetStateSyncResult is bounded operational information for daemon logs.
// File names and content deliberately do not cross this boundary.
type FleetStateSyncResult struct {
	Revision          uint64
	Entries           int
	AppliedMutations  int
	RejectedMutations int
}

func (runtime *Runtime) HasFleetStateSync() bool {
	return runtime != nil && runtime.fleetStateEnabled && runtime.HasFleetControl()
}

func (runtime *Runtime) FleetStateSyncInterval() time.Duration {
	if !runtime.HasFleetStateSync() {
		return 0
	}
	return runtime.fleetStateInterval
}

func (runtime *Runtime) loadFleetStateCursor() error {
	if runtime == nil || !runtime.fleetStateEnabled || runtime.fleetStateCursorPath == "" {
		return nil
	}
	if _, err := os.Lstat(runtime.fleetStateCursorPath); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("enterprise control: inspect fleet state cursor: %w", err)
	}
	cursor, err := readSecureJSON[fleetStateCursor](runtime.fleetStateCursorPath)
	if err != nil {
		return fmt.Errorf("enterprise control: read fleet state cursor: %w", err)
	}
	if cursor.TenantID != runtime.tenantID || cursor.AgentID != runtime.rolloutAgentID || cursor.Revision == 0 || !lowerHexSHA256(cursor.RootHash) {
		return fmt.Errorf("enterprise control: invalid fleet state cursor")
	}
	for _, result := range cursor.PendingResults {
		if result.Validate() != nil || result.TenantID != cursor.TenantID || result.AgentID != cursor.AgentID {
			return fmt.Errorf("enterprise control: invalid pending fleet state result")
		}
	}
	runtime.fleetStateRevision = cursor.Revision
	runtime.fleetStateRootHash = cursor.RootHash
	runtime.fleetStatePendingResults = append([]authority.FleetStateMutationResult(nil), cursor.PendingResults...)
	return nil
}

func (runtime *Runtime) saveFleetStateCursorLocked() error {
	if runtime.fleetStateRevision == 0 || !lowerHexSHA256(runtime.fleetStateRootHash) {
		return nil
	}
	return writeSecureJSON(runtime.fleetStateCursorPath, fleetStateCursor{
		TenantID: runtime.tenantID, AgentID: runtime.rolloutAgentID,
		Revision: runtime.fleetStateRevision, RootHash: runtime.fleetStateRootHash,
		PendingResults: append([]authority.FleetStateMutationResult(nil), runtime.fleetStatePendingResults...),
	})
}

// SyncFleetState publishes a signed .pilot mirror, retries durable mutation
// results, and applies any short-lived authority-signed typed mutations. It is
// entirely opt-in; unmanaged nodes never call or initialize this path.
func (runtime *Runtime) SyncFleetState(ctx context.Context) (FleetStateSyncResult, error) {
	if !runtime.HasFleetStateSync() {
		return FleetStateSyncResult{}, fmt.Errorf("enterprise control: fleet state sync is not configured")
	}
	runtime.fleetStateSyncMu.Lock()
	defer runtime.fleetStateSyncMu.Unlock()

	runtime.mu.Lock()
	client, tenantID, agentID, keyID := runtime.rolloutClient, runtime.tenantID, runtime.rolloutAgentID, runtime.rolloutKeyID
	privateKey := append(ed25519.PrivateKey(nil), runtime.rolloutPrivate...)
	root := runtime.fleetStateRoot
	localRevision, localRoot := runtime.fleetStateRevision, runtime.fleetStateRootHash
	pending := append([]authority.FleetStateMutationResult(nil), runtime.fleetStatePendingResults...)
	runtime.mu.Unlock()

	// A result is persisted before returning from a failed report, so replay it
	// before asking for additional mutations.
	remaining := pending[:0]
	for _, result := range pending {
		if err := client.ReportFleetStateMutationResult(ctx, result); err != nil {
			remaining = append(remaining, result)
		}
	}
	runtime.mu.Lock()
	runtime.fleetStatePendingResults = append([]authority.FleetStateMutationResult(nil), remaining...)
	_ = runtime.saveFleetStateCursorLocked()
	runtime.mu.Unlock()

	remote, remoteFound, err := client.FleetStateSnapshot(ctx, tenantID, agentID)
	if err != nil {
		return FleetStateSyncResult{}, err
	}
	if remoteFound {
		if remote.VerifySignature(privateKey.Public().(ed25519.PublicKey)) != nil {
			return FleetStateSyncResult{}, fmt.Errorf("enterprise control: hosted fleet state is not signed by this node")
		}
		if remote.Revision > localRevision {
			localRevision, localRoot = remote.Revision, remote.RootHash
		}
	}

	entries, err := scanFleetState(root, runtime.fleetStateCursorPath)
	if err != nil {
		return FleetStateSyncResult{}, err
	}
	snapshot, err := buildFleetStateSnapshot(tenantID, agentID, keyID, localRevision, localRoot, entries, privateKey)
	if err != nil {
		return FleetStateSyncResult{}, err
	}
	if err := client.ReportFleetStateSnapshot(ctx, snapshot); err != nil {
		return FleetStateSyncResult{}, err
	}
	runtime.setFleetStateCursor(snapshot)
	result := FleetStateSyncResult{Revision: snapshot.Revision, Entries: len(snapshot.Entries)}

	mutations, err := client.FleetStateMutations(ctx, tenantID, agentID)
	if err != nil {
		return result, err
	}
	for _, mutation := range mutations {
		publicKey, keyErr := runtime.trust.DecisionKey(ctx, tenantID, mutation.KeyID)
		if keyErr != nil || mutation.Verify(publicKey, time.Now()) != nil || mutation.AgentID != agentID {
			return result, fmt.Errorf("enterprise control: invalid fleet state mutation")
		}
		if mutation.ExpectedRevision != snapshot.Revision {
			runtime.publishFleetMutationResult(ctx, mutation, "rejected", "revision_conflict", mutation.ExpectedRevision, mutation.ExpectedRevision, privateKey)
			result.RejectedMutations++
			continue
		}
		transaction, applyErr := prepareFleetStateMutation(root, mutation)
		if applyErr != nil {
			runtime.publishFleetMutationResult(ctx, mutation, "rejected", mutationDetailCode(applyErr), snapshot.Revision, snapshot.Revision, privateKey)
			result.RejectedMutations++
			continue
		}
		if err := transaction.Apply(); err != nil {
			_ = transaction.Rollback()
			runtime.publishFleetMutationResult(ctx, mutation, "failed", "apply_failed", snapshot.Revision, snapshot.Revision, privateKey)
			result.RejectedMutations++
			continue
		}
		nextEntries, scanErr := scanFleetState(root, runtime.fleetStateCursorPath)
		if scanErr != nil {
			_ = transaction.Rollback()
			runtime.publishFleetMutationResult(ctx, mutation, "failed", "rescan_failed", snapshot.Revision, snapshot.Revision, privateKey)
			result.RejectedMutations++
			continue
		}
		next, buildErr := buildFleetStateSnapshot(tenantID, agentID, keyID, snapshot.Revision, snapshot.RootHash, nextEntries, privateKey)
		if buildErr != nil || next.Revision <= snapshot.Revision {
			_ = transaction.Rollback()
			runtime.publishFleetMutationResult(ctx, mutation, "failed", "snapshot_failed", snapshot.Revision, snapshot.Revision, privateKey)
			result.RejectedMutations++
			continue
		}
		if reportErr := client.ReportFleetStateSnapshot(ctx, next); reportErr != nil {
			accepted := false
			if current, found, fetchErr := client.FleetStateSnapshot(ctx, tenantID, agentID); fetchErr == nil && found && current.Revision == next.Revision && current.RootHash == next.RootHash {
				accepted = true
			}
			if !accepted {
				_ = transaction.Rollback()
				runtime.publishFleetMutationResult(ctx, mutation, "failed", "snapshot_report_failed", snapshot.Revision, snapshot.Revision, privateKey)
				result.RejectedMutations++
				continue
			}
		}
		if err := transaction.Commit(); err != nil {
			return result, fmt.Errorf("enterprise control: commit fleet state mutation: %w", err)
		}
		runtime.setFleetStateCursor(next)
		runtime.publishFleetMutationResult(ctx, mutation, "applied", "", snapshot.Revision, next.Revision, privateKey)
		snapshot = next
		result.Revision, result.Entries = next.Revision, len(next.Entries)
		result.AppliedMutations++
	}
	return result, nil
}

func (runtime *Runtime) setFleetStateCursor(snapshot authority.FleetStateSnapshot) {
	runtime.mu.Lock()
	runtime.fleetStateRevision, runtime.fleetStateRootHash = snapshot.Revision, snapshot.RootHash
	_ = runtime.saveFleetStateCursorLocked()
	runtime.mu.Unlock()
}

func (runtime *Runtime) publishFleetMutationResult(ctx context.Context, mutation authority.FleetStateMutation, status, detail string, from, to uint64, privateKey ed25519.PrivateKey) {
	result := authority.FleetStateMutationResult{
		Version: authority.FleetStateVersion, TenantID: mutation.TenantID, AgentID: mutation.AgentID,
		MutationID: mutation.ID, Status: status, DetailCode: detail, FromRevision: from,
		ToRevision: to, ObservedAt: time.Now().UTC().Unix(), KeyID: runtime.rolloutKeyID,
	}
	if err := result.Sign(privateKey); err != nil {
		return
	}
	if err := runtime.rolloutClient.ReportFleetStateMutationResult(ctx, result); err == nil {
		return
	}
	runtime.mu.Lock()
	for _, existing := range runtime.fleetStatePendingResults {
		if existing.MutationID == result.MutationID {
			runtime.mu.Unlock()
			return
		}
	}
	runtime.fleetStatePendingResults = append(runtime.fleetStatePendingResults, result)
	_ = runtime.saveFleetStateCursorLocked()
	runtime.mu.Unlock()
}

func buildFleetStateSnapshot(tenantID, agentID, keyID string, baseRevision uint64, baseRoot string, entries []authority.FleetStateEntry, privateKey ed25519.PrivateKey) (authority.FleetStateSnapshot, error) {
	probeRevision := baseRevision
	if probeRevision == 0 {
		probeRevision = 1
	}
	probe, err := authority.NewFleetStateSnapshot(tenantID, agentID, probeRevision, entries, time.Now(), keyID)
	if err != nil {
		return authority.FleetStateSnapshot{}, err
	}
	revision := baseRevision
	if revision == 0 {
		revision = 1
	} else if probe.RootHash != baseRoot {
		revision++
	}
	snapshot, err := authority.NewFleetStateSnapshot(tenantID, agentID, revision, entries, time.Now(), keyID)
	if err != nil {
		return authority.FleetStateSnapshot{}, err
	}
	if err := snapshot.Sign(privateKey); err != nil {
		return authority.FleetStateSnapshot{}, err
	}
	return snapshot, nil
}

func scanFleetState(root, cursorPath string) ([]authority.FleetStateEntry, error) {
	var entries []authority.FleetStateEntry
	visibleBytes := 0
	err := filepath.WalkDir(root, func(current string, item fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if current == root {
			return nil
		}
		if samePath(current, cursorPath) || strings.HasPrefix(item.Name(), ".enterprise-control-state-") || strings.HasPrefix(item.Name(), ".pilot-fleet-mutation-") {
			if item.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if len(entries) >= authority.MaxFleetStateEntries {
			return fmt.Errorf("enterprise control: fleet state entry limit exceeded")
		}
		relative, err := filepath.Rel(root, current)
		if err != nil || relative == "." || strings.HasPrefix(relative, "..") {
			return fmt.Errorf("enterprise control: invalid fleet state path")
		}
		relative = filepath.ToSlash(relative)
		info, err := item.Info()
		if err != nil {
			return err
		}
		modified := info.ModTime().UTC().Unix()
		if modified <= 0 {
			modified = 1
		}
		entry := authority.FleetStateEntry{Path: relative, Mode: uint32(info.Mode().Perm()), ModifiedAt: modified}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			target, readErr := os.Readlink(current)
			if readErr != nil {
				return readErr
			}
			sum := sha256.Sum256([]byte(target))
			entry.Kind, entry.Size, entry.Hash = authority.FleetStateSymlink, uint64(len(target)), hex.EncodeToString(sum[:])
			entry.Protected, entry.ProtectionReason = true, "symlink_target_hidden"
		case info.IsDir():
			entry.Kind = authority.FleetStateDirectory
		case info.Mode().IsRegular():
			fileEntry, readErr := scanFleetStateFile(current, entry, authority.MaxFleetStateVisibleBytes-visibleBytes)
			if readErr != nil {
				return readErr
			}
			entry = fileEntry
			visibleBytes += len(entry.Content)
		default:
			entry.Kind, entry.Protected, entry.ProtectionReason = authority.FleetStateFile, true, "special_file_hidden"
			sum := sha256.Sum256([]byte(info.Mode().String()))
			entry.Hash = hex.EncodeToString(sum[:])
		}
		entries = append(entries, entry)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, nil
}

func scanFleetStateFile(filename string, entry authority.FleetStateEntry, budget int) (authority.FleetStateEntry, error) {
	entry.Kind = authority.FleetStateFile
	file, err := os.Open(filename)
	if err != nil {
		return entry, err
	}
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	_ = file.Close()
	if err != nil || size < 0 {
		return entry, fmt.Errorf("enterprise control: hash fleet state file: %w", err)
	}
	entry.Size, entry.Hash = uint64(size), hex.EncodeToString(hash.Sum(nil))
	if protected, reason := fleetContentProtected(entry.Path); protected {
		entry.Protected, entry.ProtectionReason = true, reason
		return entry, nil
	}
	if budget <= 0 {
		entry.Protected, entry.ProtectionReason = true, "visibility_budget_exhausted"
		return entry, nil
	}
	want := int64(fleetStatePerFilePreviewBytes)
	if size < want {
		want = size
	}
	if int64(budget) < want {
		want = int64(budget)
	}
	contents := make([]byte, int(want))
	file, err = os.Open(filename)
	if err != nil {
		return entry, err
	}
	offset := int64(0)
	if size > want {
		offset = size - want
		_, err = file.Seek(offset, io.SeekStart)
	}
	if err == nil {
		_, err = io.ReadFull(file, contents)
	}
	_ = file.Close()
	if err != nil {
		return entry, fmt.Errorf("enterprise control: read fleet state preview: %w", err)
	}
	if bytes.IndexByte(contents, 0) >= 0 || !utf8.Valid(contents) {
		entry.Protected, entry.ProtectionReason = true, "binary_content_hidden"
		return entry, nil
	}
	if offset == 0 && strings.EqualFold(filepath.Ext(filename), ".json") {
		if sanitized, changed, ok := redactFleetJSON(contents); ok && changed {
			if len(sanitized) > budget || len(sanitized) > fleetStatePerFilePreviewBytes {
				entry.Protected, entry.ProtectionReason = true, "sanitized_content_exceeds_budget"
				return entry, nil
			}
			contents, entry.Redacted = sanitized, true
		}
	}
	entry.Content = contents
	entry.ContentOffset = uint64(offset)
	entry.Truncated = offset > 0
	contentHash := sha256.Sum256(contents)
	entry.ContentHash = hex.EncodeToString(contentHash[:])
	return entry, nil
}

func redactFleetJSON(contents []byte) ([]byte, bool, bool) {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, false, false
	}
	changed := redactFleetJSONValue(value)
	if !changed {
		return contents, false, true
	}
	sanitized, err := json.MarshalIndent(value, "", "  ")
	return sanitized, true, err == nil
}

func redactFleetJSONValue(value any) bool {
	changed := false
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if sensitiveFleetKey(key) {
				typed[key], changed = "[REDACTED]", true
				continue
			}
			changed = redactFleetJSONValue(child) || changed
		}
	case []any:
		for _, child := range typed {
			changed = redactFleetJSONValue(child) || changed
		}
	}
	return changed
}

func sensitiveFleetKey(value string) bool {
	normalized := strings.NewReplacer("-", "", "_", "", ".", "").Replace(strings.ToLower(value))
	for _, fragment := range []string{"password", "passwd", "secret", "token", "apikey", "privatekey", "seed", "credential", "bearer", "cookie"} {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	return false
}

func fleetContentProtected(relative string) (bool, string) {
	base := strings.ToLower(filepath.Base(relative))
	if base == ".env" || strings.HasSuffix(base, ".env") {
		return true, "environment_secrets_hidden"
	}
	for _, suffix := range []string{".key", ".pem", ".p12", ".pfx", ".keystore", ".jks"} {
		if strings.HasSuffix(base, suffix) {
			return true, "private_key_material_hidden"
		}
	}
	for _, fragment := range []string{"private-key", "private_key", "credential", "secret", "seed", "access-token", "refresh-token"} {
		if strings.Contains(base, fragment) {
			return true, "credential_material_hidden"
		}
	}
	return false, ""
}

func mutationDetailCode(err error) string {
	var rejection *fleetMutationRejection
	if errors.As(err, &rejection) {
		return rejection.code
	}
	return "mutation_invalid"
}

type fleetMutationRejection struct{ code string }

func (err *fleetMutationRejection) Error() string { return err.code }

type fleetMutationBackup struct {
	target      string
	backup      string
	hadOriginal bool
}

type fleetMutationTransaction struct {
	root        string
	backupRoot  string
	mutation    authority.FleetStateMutation
	backups     []fleetMutationBackup
	createdDirs []string
	applied     bool
}

func prepareFleetStateMutation(root string, mutation authority.FleetStateMutation) (*fleetMutationTransaction, error) {
	paths := make([]string, 0, len(mutation.Operations))
	for _, operation := range mutation.Operations {
		if fleetMutationPathProtected(operation.Path) {
			return nil, &fleetMutationRejection{code: "protected_path"}
		}
		target, err := confinedFleetPath(root, operation.Path)
		if err != nil {
			return nil, &fleetMutationRejection{code: "path_not_confined"}
		}
		for _, existing := range paths {
			if strings.HasPrefix(target, existing+string(os.PathSeparator)) || strings.HasPrefix(existing, target+string(os.PathSeparator)) {
				return nil, &fleetMutationRejection{code: "overlapping_paths"}
			}
		}
		paths = append(paths, target)
		info, statErr := os.Lstat(target)
		if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			return nil, &fleetMutationRejection{code: "path_unreadable"}
		}
		if statErr == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return nil, &fleetMutationRejection{code: "symlink_rejected"}
			}
			if operation.ExpectedHash != "" {
				if !info.Mode().IsRegular() {
					return nil, &fleetMutationRejection{code: "expected_hash_not_file"}
				}
				hash, hashErr := hashFleetFile(target)
				if hashErr != nil || hash != operation.ExpectedHash {
					return nil, &fleetMutationRejection{code: "expected_hash_mismatch"}
				}
			}
			if info.IsDir() {
				protected := false
				_ = filepath.WalkDir(target, func(child string, item fs.DirEntry, err error) error {
					if err == nil {
						relative, _ := filepath.Rel(root, child)
						protected = protected || fleetMutationPathProtected(filepath.ToSlash(relative))
					}
					return nil
				})
				if protected {
					return nil, &fleetMutationRejection{code: "protected_descendant"}
				}
			}
		} else if operation.Kind == authority.FleetStateDeletePath || operation.ExpectedHash != "" {
			return nil, &fleetMutationRejection{code: "target_not_found"}
		}
	}
	backupRoot, err := os.MkdirTemp(filepath.Dir(root), ".pilot-fleet-mutation-")
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(backupRoot, 0o700); err != nil {
		_ = os.RemoveAll(backupRoot)
		return nil, err
	}
	return &fleetMutationTransaction{root: root, backupRoot: backupRoot, mutation: mutation}, nil
}

func (transaction *fleetMutationTransaction) Apply() error {
	for index, operation := range transaction.mutation.Operations {
		target, err := confinedFleetPath(transaction.root, operation.Path)
		if err != nil {
			return err
		}
		backup := filepath.Join(transaction.backupRoot, fmt.Sprintf("%06d", index))
		item := fleetMutationBackup{target: target, backup: backup}
		if _, err := os.Lstat(target); err == nil {
			if err := os.Rename(target, backup); err != nil {
				return err
			}
			item.hadOriginal = true
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		transaction.backups = append(transaction.backups, item)
		switch operation.Kind {
		case authority.FleetStateDeletePath:
			continue
		case authority.FleetStateMakeDirectory:
			if err := transaction.mkdirParents(filepath.Dir(target)); err != nil {
				return err
			}
			mode := fs.FileMode(operation.Mode)
			if mode == 0 {
				mode = 0o700
			}
			if err := os.Mkdir(target, mode); err != nil {
				return err
			}
		case authority.FleetStatePutFile:
			if err := transaction.mkdirParents(filepath.Dir(target)); err != nil {
				return err
			}
			mode := fs.FileMode(operation.Mode)
			if mode == 0 {
				mode = 0o600
			}
			temporary, err := os.CreateTemp(filepath.Dir(target), ".pilot-state-put-")
			if err != nil {
				return err
			}
			temporaryPath := temporary.Name()
			if err = temporary.Chmod(mode); err == nil {
				_, err = temporary.Write(operation.Content)
			}
			if err == nil {
				err = temporary.Sync()
			}
			closeErr := temporary.Close()
			if err == nil {
				err = closeErr
			}
			if err == nil {
				err = os.Rename(temporaryPath, target)
			}
			_ = os.Remove(temporaryPath)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported operation")
		}
	}
	transaction.applied = true
	return nil
}

func (transaction *fleetMutationTransaction) mkdirParents(directory string) error {
	missing := []string{}
	current := directory
	for current != transaction.root {
		info, err := os.Lstat(current)
		if err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("unsafe parent")
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		missing = append(missing, current)
		current = filepath.Dir(current)
		if current == "." || !strings.HasPrefix(directory+string(os.PathSeparator), transaction.root+string(os.PathSeparator)) {
			return fmt.Errorf("parent escapes state root")
		}
	}
	for index := len(missing) - 1; index >= 0; index-- {
		if err := os.Mkdir(missing[index], 0o700); err != nil {
			return err
		}
		transaction.createdDirs = append(transaction.createdDirs, missing[index])
	}
	return nil
}

func (transaction *fleetMutationTransaction) Rollback() error {
	var first error
	for index := len(transaction.backups) - 1; index >= 0; index-- {
		backup := transaction.backups[index]
		if err := os.RemoveAll(backup.target); err != nil && first == nil {
			first = err
		}
		if backup.hadOriginal {
			if err := os.Rename(backup.backup, backup.target); err != nil && first == nil {
				first = err
			}
		}
	}
	for index := len(transaction.createdDirs) - 1; index >= 0; index-- {
		_ = os.Remove(transaction.createdDirs[index])
	}
	if err := os.RemoveAll(transaction.backupRoot); err != nil && first == nil {
		first = err
	}
	return first
}

func (transaction *fleetMutationTransaction) Commit() error {
	return os.RemoveAll(transaction.backupRoot)
}

func confinedFleetPath(root, relative string) (string, error) {
	cleaned := filepath.Clean(filepath.FromSlash(relative))
	if cleaned == "." || filepath.IsAbs(cleaned) || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("invalid path")
	}
	target := filepath.Join(root, cleaned)
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("path escapes state root")
	}
	current := root
	parts := strings.Split(cleaned, string(os.PathSeparator))
	for _, part := range parts[:len(parts)-1] {
		current = filepath.Join(current, part)
		if info, err := os.Lstat(current); err == nil && info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("symlink parent")
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
	}
	return target, nil
}

func fleetMutationPathProtected(relative string) bool {
	lower := strings.ToLower(filepath.ToSlash(relative))
	base := strings.ToLower(filepath.Base(lower))
	if base == ".enterprise-fleet-state-cursor.json" || base == ".enterprise-control-state.json" || base == ".enterprise-fleet-control.json" || base == "enterprise-control.json" {
		return true
	}
	if protected, _ := fleetContentProtected(relative); protected {
		return true
	}
	for _, fragment := range []string{"trust", "policy", "identity", "receipt", "continuation", "keyring", "authority"} {
		if strings.Contains(base, fragment) {
			return true
		}
	}
	return strings.Contains(lower, "/keys/") || strings.Contains(lower, "/identity/") || strings.Contains(lower, "/secrets/")
}

func hashFleetFile(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func lowerHexSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func samePath(left, right string) bool {
	return filepath.Clean(left) == filepath.Clean(right)
}
