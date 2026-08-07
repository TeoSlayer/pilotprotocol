// SPDX-License-Identifier: AGPL-3.0-or-later

// Package actioncontinuation stores local, payload-free approval suspension
// records and exact-once resume leases. The authority owns approval votes and
// certificates; this package owns only the node-side fact that a particular
// adapter action may be attempted at most once after approval.
package actioncontinuation

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/pilot-protocol/common/actionhook"
	"github.com/pilot-protocol/common/fsutil"
)

const (
	SchemaVersion  uint16 = 1
	MaxRecordBytes        = 64 << 10
)

var (
	ErrNotFound       = errors.New("actioncontinuation: continuation not found")
	ErrConflict       = errors.New("actioncontinuation: continuation conflict")
	ErrAlreadyClaimed = errors.New("actioncontinuation: continuation already claimed")
	ErrExpired        = errors.New("actioncontinuation: continuation expired")
)

type State string

const (
	StatePending   State = "pending"
	StateExecuting State = "executing"
	StateSucceeded State = "succeeded"
	StateFailed    State = "failed"
	StateInvalid   State = "invalid"
)

// Record contains no payload, prompt, secret, local path, or peer address.
// ResumeToken is adapter-local and never uploaded to the authority.
type Record struct {
	Version             uint16                       `json:"version"`
	ID                  string                       `json:"id"`
	Fingerprint         string                       `json:"fingerprint"`
	TenantID            string                       `json:"tenant_id"`
	AgentID             string                       `json:"agent_id"`
	ActionID            string                       `json:"action_id"`
	Action              string                       `json:"action"`
	Resource            string                       `json:"resource"`
	PayloadHash         string                       `json:"payload_hash"`
	AdapterID           string                       `json:"adapter_id"`
	ResumeToken         string                       `json:"resume_token"`
	InitialDecision     actionhook.DecisionReference `json:"initial_decision"`
	ApprovalTransaction string                       `json:"approval_transaction_id"`
	State               State                        `json:"state"`
	CreatedAt           int64                        `json:"created_at"`
	ExpiresAt           int64                        `json:"expires_at"`
	AttemptedAt         int64                        `json:"attempted_at,omitempty"`
	FinishedAt          int64                        `json:"finished_at,omitempty"`
	FailureCode         string                       `json:"failure_code,omitempty"`
}

type Store struct {
	directory string
	mu        sync.Mutex
	now       func() time.Time
}

func Open(directory string) (*Store, error) {
	if strings.TrimSpace(directory) == "" {
		return nil, fmt.Errorf("actioncontinuation: directory is required")
	}
	absolute, err := filepath.Abs(filepath.Clean(directory))
	if err != nil {
		return nil, err
	}
	if info, statErr := os.Lstat(absolute); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, fmt.Errorf("actioncontinuation: path must be a real directory")
		}
	} else if !os.IsNotExist(statErr) {
		return nil, statErr
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(absolute, 0o700); err != nil {
		return nil, err
	}
	return &Store{directory: absolute, now: time.Now}, nil
}

// NewPending constructs the canonical continuation identity. ActionID is the
// original hook action ID for trace correlation; it is not used for lookup,
// because a later process creates a new envelope ID when resuming.
func NewPending(tenantID, agentID string, envelope actionhook.Envelope, reference actionhook.DecisionReference, transactionID string, expiresAt time.Time) (Record, error) {
	record := Record{
		Version: SchemaVersion, TenantID: tenantID, AgentID: agentID, ActionID: envelope.ID,
		Action: envelope.Action, Resource: envelope.Resource, PayloadHash: envelope.PayloadHash,
		AdapterID: envelope.AdapterID, ResumeToken: envelope.ResumeToken,
		InitialDecision: reference, ApprovalTransaction: transactionID, State: StatePending,
		CreatedAt: envelope.CreatedAt, ExpiresAt: expiresAt.UTC().Unix(),
	}
	record.Fingerprint = Fingerprint(tenantID, agentID, envelope.Action, envelope.Resource, envelope.PayloadHash, envelope.AdapterID, envelope.ResumeToken)
	record.ID = RecordID(record.Fingerprint, transactionID)
	if err := record.Validate(); err != nil {
		return Record{}, err
	}
	return record, nil
}

// Fingerprint is deterministic for the exact side effect and local resume
// token. None of its inputs are recoverable from the resulting identifier.
func Fingerprint(tenantID, agentID, action, resource, payloadHash, adapterID, resumeToken string) string {
	hash := sha256.New()
	for _, value := range []string{tenantID, agentID, action, resource, payloadHash, adapterID, resumeToken} {
		var length [8]byte
		n := uint64(len(value))
		for index := 7; index >= 0; index-- {
			length[index] = byte(n)
			n >>= 8
		}
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(value))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// RecordID adds the authority transaction identity, allowing a later,
// intentional repetition of the same side effect to open a new workflow after
// the prior one completed without overwriting its evidence.
func RecordID(fingerprint, transactionID string) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(fingerprint))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(transactionID))
	return hex.EncodeToString(hash.Sum(nil))
}

func (record Record) Validate() error {
	if record.Version != SchemaVersion || !lowerHex(record.ID, 64) || !lowerHex(record.Fingerprint, 64) || !lowerHex(record.PayloadHash, 64) {
		return fmt.Errorf("actioncontinuation: invalid version or hash identity")
	}
	expectedFingerprint := Fingerprint(record.TenantID, record.AgentID, record.Action, record.Resource, record.PayloadHash, record.AdapterID, record.ResumeToken)
	if record.Fingerprint != expectedFingerprint || record.ID != RecordID(expectedFingerprint, record.ApprovalTransaction) {
		return fmt.Errorf("actioncontinuation: non-canonical continuation identity")
	}
	for _, value := range []string{record.TenantID, record.AgentID, record.ActionID, record.Action, record.AdapterID, record.ApprovalTransaction} {
		if !identifier(value, 128) {
			return fmt.Errorf("actioncontinuation: invalid identifier")
		}
	}
	if !text(record.Resource, 1024, false) || !text(record.ResumeToken, 1024, true) {
		return fmt.Errorf("actioncontinuation: invalid resource or resume token")
	}
	switch record.State {
	case StatePending:
		if record.AttemptedAt != 0 || record.FinishedAt != 0 || record.FailureCode != "" {
			return fmt.Errorf("actioncontinuation: pending continuation has terminal fields")
		}
	case StateExecuting:
		if record.AttemptedAt <= 0 || record.FinishedAt != 0 || record.FailureCode != "" {
			return fmt.Errorf("actioncontinuation: invalid executing continuation")
		}
	case StateSucceeded:
		if record.AttemptedAt <= 0 || record.FinishedAt < record.AttemptedAt || record.FailureCode != "" {
			return fmt.Errorf("actioncontinuation: invalid successful continuation")
		}
	case StateFailed, StateInvalid:
		if record.FinishedAt <= 0 || !identifier(record.FailureCode, 128) {
			return fmt.Errorf("actioncontinuation: invalid failed continuation")
		}
	default:
		return fmt.Errorf("actioncontinuation: invalid state %q", record.State)
	}
	if record.CreatedAt <= 0 || record.ExpiresAt <= record.CreatedAt || record.ExpiresAt-record.CreatedAt > int64((7*24*time.Hour)/time.Second) {
		return fmt.Errorf("actioncontinuation: invalid validity window")
	}
	return nil
}

// PutPending uses an exclusive create, so two CLI processes cannot replace
// each other's approval transaction for the same exact action.
func (store *Store) PutPending(ctx context.Context, candidate Record) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	if err := candidate.Validate(); err != nil || candidate.State != StatePending {
		if err != nil {
			return Record{}, err
		}
		return Record{}, ErrConflict
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	path := store.recordPath(candidate.ID)
	body, err := json.Marshal(candidate)
	if err != nil {
		return Record{}, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if os.IsExist(err) {
		existing, readErr := store.readLocked(candidate.ID)
		if readErr != nil {
			return Record{}, readErr
		}
		if sameImmutable(existing, candidate) {
			return existing, nil
		}
		return Record{}, ErrConflict
	}
	if err != nil {
		return Record{}, err
	}
	if _, err = file.Write(body); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		_ = os.Remove(path)
		return Record{}, err
	}
	if closeErr != nil {
		return Record{}, closeErr
	}
	return candidate, nil
}

func (store *Store) Get(ctx context.Context, id string) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, err := store.readLocked(id)
	if err != nil {
		return Record{}, err
	}
	if record.State == StatePending {
		if _, statErr := os.Lstat(store.leasePath(id)); statErr == nil {
			record.State = StateExecuting
			record.AttemptedAt = record.CreatedAt
		}
	}
	return record, nil
}

// FindActive returns the one continuation that still controls an exact side
// effect. Successful records are historical and do not prevent a deliberate
// later repetition. Pending, executing, and failed records remain active; a
// failed/ambiguous execution therefore needs a different adapter resume token
// before it can be attempted again.
func (store *Store) FindActive(ctx context.Context, fingerprint string) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	if !lowerHex(fingerprint, 64) {
		return Record{}, ErrNotFound
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	entries, err := os.ReadDir(store.directory)
	if err != nil {
		return Record{}, err
	}
	var found *Record
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		record, readErr := store.readLocked(id)
		if readErr != nil {
			return Record{}, readErr
		}
		if record.Fingerprint != fingerprint || record.State == StateSucceeded || record.State == StateInvalid {
			continue
		}
		if found != nil {
			return Record{}, ErrConflict
		}
		copy := record
		found = &copy
	}
	if found == nil {
		return Record{}, ErrNotFound
	}
	if found.State == StatePending {
		if _, statErr := os.Lstat(store.leasePath(found.ID)); statErr == nil {
			found.State = StateExecuting
			found.AttemptedAt = found.CreatedAt
		}
	}
	return *found, nil
}

// ClaimResume atomically publishes an exclusive lease before returning a
// permit. A crash after this point is fail-closed: the lease is intentionally
// never deleted, so the side effect cannot be attempted twice ambiguously.
func (store *Store) ClaimResume(ctx context.Context, id string) (Record, string, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, "", err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, err := store.readLocked(id)
	if err != nil {
		return Record{}, "", err
	}
	now := store.now().UTC()
	if now.Unix() >= record.ExpiresAt {
		return Record{}, "", ErrExpired
	}
	if record.State != StatePending {
		return Record{}, "", ErrAlreadyClaimed
	}
	var tokenBytes [32]byte
	if _, err := rand.Read(tokenBytes[:]); err != nil {
		return Record{}, "", err
	}
	token := hex.EncodeToString(tokenBytes[:])
	lease, err := os.OpenFile(store.leasePath(id), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if os.IsExist(err) {
		return Record{}, "", ErrAlreadyClaimed
	}
	if err != nil {
		return Record{}, "", err
	}
	if _, err = lease.WriteString(token); err == nil {
		err = lease.Sync()
	}
	closeErr := lease.Close()
	if err != nil {
		return Record{}, "", err
	}
	if closeErr != nil {
		return Record{}, "", closeErr
	}
	record.State = StateExecuting
	record.AttemptedAt = now.Unix()
	if err := store.writeLocked(record); err != nil {
		// Keep the lease on write failure: ambiguity must fail closed.
		return Record{}, "", err
	}
	return record, token, nil
}

func (store *Store) Finish(ctx context.Context, id, leaseToken string, succeeded bool, failureCode string) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	lease, err := os.ReadFile(store.leasePath(id))
	if err != nil || !bytes.Equal(lease, []byte(leaseToken)) {
		return Record{}, ErrConflict
	}
	record, err := store.readLocked(id)
	if err != nil {
		return Record{}, err
	}
	if record.State == StateSucceeded || record.State == StateFailed {
		return record, nil
	}
	if record.State != StateExecuting {
		return Record{}, ErrConflict
	}
	record.FinishedAt = store.now().UTC().Unix()
	if succeeded {
		record.State = StateSucceeded
		record.FailureCode = ""
	} else {
		if !identifier(failureCode, 128) {
			return Record{}, fmt.Errorf("actioncontinuation: failure code is required")
		}
		record.State = StateFailed
		record.FailureCode = failureCode
	}
	if err := store.writeLocked(record); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (store *Store) recordPath(id string) string { return filepath.Join(store.directory, id+".json") }
func (store *Store) leasePath(id string) string  { return filepath.Join(store.directory, id+".lease") }

func (store *Store) readLocked(id string) (Record, error) {
	if !lowerHex(id, 64) {
		return Record{}, ErrNotFound
	}
	path := store.recordPath(id)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return Record{}, ErrNotFound
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > MaxRecordBytes || info.Mode().Perm()&0o077 != 0 {
		return Record{}, fmt.Errorf("actioncontinuation: unsafe continuation record")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return Record{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var record Record
	if err := decoder.Decode(&record); err != nil {
		return Record{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Record{}, fmt.Errorf("actioncontinuation: trailing record data")
	}
	if err := record.Validate(); err != nil || record.ID != id {
		if err != nil {
			return Record{}, err
		}
		return Record{}, ErrConflict
	}
	return record, nil
}

func (store *Store) writeLocked(record Record) error {
	if err := record.Validate(); err != nil {
		return err
	}
	body, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return fsutil.AtomicWrite(store.recordPath(record.ID), body)
}

func sameImmutable(first, second Record) bool {
	return first.ID == second.ID && first.TenantID == second.TenantID && first.AgentID == second.AgentID &&
		first.Fingerprint == second.Fingerprint &&
		first.Action == second.Action && first.Resource == second.Resource && first.PayloadHash == second.PayloadHash &&
		first.AdapterID == second.AdapterID && first.ResumeToken == second.ResumeToken &&
		first.ApprovalTransaction == second.ApprovalTransaction
}

func lowerHex(value string, length int) bool {
	if len(value) != length || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func identifier(value string, max int) bool {
	if value == "" || len(value) > max || !utf8.ValidString(value) {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || (index > 0 && strings.ContainsRune("._:/@-", character)) {
			continue
		}
		return false
	}
	return true
}

func text(value string, max int, allowEmpty bool) bool {
	if (!allowEmpty && value == "") || len(value) > max || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}
