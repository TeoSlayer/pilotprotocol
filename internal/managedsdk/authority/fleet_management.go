// SPDX-License-Identifier: AGPL-3.0-or-later

package authority

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	FleetCommandCancellationVersion uint16 = 1
	FleetNodeLifecycleVersion       uint16 = 1
	FleetGroupVersion               uint16 = 1
	FleetEnrollmentControlVersion   uint16 = 1
	FleetCommandCancellationDomain         = "pilot-fleet-command-cancellation-v1"
	FleetNodeLifecycleDomain               = "pilot-fleet-node-lifecycle-v1"
	FleetGroupDomain                       = "pilot-fleet-group-v1"
	FleetEnrollmentControlDomain           = "pilot-fleet-enrollment-control-v1"
	FleetEnrollmentOpen                    = "open"
	FleetEnrollmentApproval                = "approval"
	FleetNodePending                       = "pending"
	FleetNodeActive                        = "active"
	FleetNodeRetired                       = "retired"
	FleetGroupActive                       = "active"
	FleetGroupRetired                      = "retired"
)

type FleetEnrollmentControl struct {
	Version   uint16 `json:"version"`
	TenantID  string `json:"tenant_id"`
	Revision  uint64 `json:"revision"`
	Mode      string `json:"mode"`
	Reason    string `json:"reason"`
	IssuedAt  int64  `json:"issued_at"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

func (control FleetEnrollmentControl) Validate() error {
	if control.Version != FleetEnrollmentControlVersion || control.Revision == 0 || control.IssuedAt <= 0 || validateIdentifier("tenant_id", control.TenantID) != nil || validateIdentifier("key_id", control.KeyID) != nil || control.Mode != FleetEnrollmentOpen && control.Mode != FleetEnrollmentApproval || !boundedFleetText(control.Reason, 256, false) || len(strings.TrimSpace(control.Reason)) < 8 {
		return fmt.Errorf("authority: invalid fleet enrollment control")
	}
	return nil
}

func (control FleetEnrollmentControl) Canonical() ([]byte, error) {
	if err := control.Validate(); err != nil {
		return nil, err
	}
	writer := canonicalWriter{}
	writer.string(FleetEnrollmentControlDomain)
	writer.u16(control.Version)
	writer.string(control.TenantID)
	writer.u64(control.Revision)
	writer.string(control.Mode)
	writer.string(control.Reason)
	writer.i64(control.IssuedAt)
	writer.string(control.KeyID)
	if writer.err != nil {
		return nil, writer.err
	}
	return writer.Buffer.Bytes(), nil
}

func (control *FleetEnrollmentControl) SignWith(signer func([]byte) ([]byte, error)) error {
	canonical, err := control.Canonical()
	if err != nil {
		return err
	}
	signature, err := signer(canonical)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("authority: fleet enrollment control signing failed")
	}
	control.Signature = base64.StdEncoding.EncodeToString(signature)
	return nil
}

func (control FleetEnrollmentControl) Verify(publicKey ed25519.PublicKey, now time.Time) error {
	canonical, err := control.Canonical()
	if err != nil {
		return err
	}
	if control.IssuedAt > now.Unix()+int64(MaxBundleClockSkew/time.Second) {
		return fmt.Errorf("authority: fleet enrollment control is from the future")
	}
	signature, err := base64.StdEncoding.DecodeString(control.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || len(publicKey) != ed25519.PublicKeySize || !ed25519.Verify(publicKey, canonical, signature) {
		return fmt.Errorf("authority: invalid fleet enrollment control signature")
	}
	return nil
}

type FleetCommandCancellation struct {
	Version   uint16 `json:"version"`
	ID        string `json:"id"`
	TenantID  string `json:"tenant_id"`
	CommandID string `json:"command_id"`
	Reason    string `json:"reason"`
	IssuedAt  int64  `json:"issued_at"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

func NewFleetCommandCancellation(command FleetCommand, reason string, issuedAt time.Time, keyID string) (FleetCommandCancellation, error) {
	cancellation := FleetCommandCancellation{Version: FleetCommandCancellationVersion, TenantID: command.TenantID, CommandID: command.ID, Reason: strings.TrimSpace(reason), IssuedAt: issuedAt.Unix(), KeyID: keyID}
	cancellation.ID = fleetCommandCancellationID(cancellation)
	if err := cancellation.Validate(); err != nil {
		return FleetCommandCancellation{}, err
	}
	if cancellation.IssuedAt < command.IssuedAt {
		return FleetCommandCancellation{}, fmt.Errorf("authority: fleet command cancellation predates command")
	}
	return cancellation, nil
}

func (cancellation FleetCommandCancellation) Validate() error {
	if cancellation.Version != FleetCommandCancellationVersion || !lowerHexIdentifier(cancellation.ID, 64) || cancellation.IssuedAt <= 0 {
		return fmt.Errorf("authority: invalid fleet command cancellation identity")
	}
	for name, value := range map[string]string{"tenant_id": cancellation.TenantID, "command_id": cancellation.CommandID, "key_id": cancellation.KeyID} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	if !boundedFleetText(cancellation.Reason, 256, false) || len(strings.TrimSpace(cancellation.Reason)) < 8 || cancellation.ID != fleetCommandCancellationID(cancellation) {
		return fmt.Errorf("authority: invalid fleet command cancellation state")
	}
	return nil
}

func (cancellation FleetCommandCancellation) Canonical() ([]byte, error) {
	if err := cancellation.Validate(); err != nil {
		return nil, err
	}
	writer := canonicalWriter{}
	writer.string(FleetCommandCancellationDomain)
	writer.u16(cancellation.Version)
	writer.string(cancellation.ID)
	writer.string(cancellation.TenantID)
	writer.string(cancellation.CommandID)
	writer.string(cancellation.Reason)
	writer.i64(cancellation.IssuedAt)
	writer.string(cancellation.KeyID)
	if writer.err != nil {
		return nil, writer.err
	}
	return writer.Buffer.Bytes(), nil
}

func (cancellation *FleetCommandCancellation) Sign(privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("authority: invalid fleet cancellation signing key")
	}
	return cancellation.SignWith(func(message []byte) ([]byte, error) { return ed25519.Sign(privateKey, message), nil })
}

func (cancellation *FleetCommandCancellation) SignWith(signer func([]byte) ([]byte, error)) error {
	canonical, err := cancellation.Canonical()
	if err != nil {
		return err
	}
	signature, err := signer(canonical)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("authority: fleet cancellation signing failed")
	}
	cancellation.Signature = base64.StdEncoding.EncodeToString(signature)
	return nil
}

func (cancellation FleetCommandCancellation) Verify(publicKey ed25519.PublicKey, now time.Time) error {
	canonical, err := cancellation.Canonical()
	if err != nil {
		return err
	}
	if cancellation.IssuedAt > now.Unix()+int64(MaxBundleClockSkew/time.Second) {
		return fmt.Errorf("authority: fleet cancellation is from the future")
	}
	signature, err := base64.StdEncoding.DecodeString(cancellation.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || len(publicKey) != ed25519.PublicKeySize || !ed25519.Verify(publicKey, canonical, signature) {
		return fmt.Errorf("authority: invalid fleet cancellation signature")
	}
	return nil
}

type FleetNodeLifecycle struct {
	Version   uint16 `json:"version"`
	TenantID  string `json:"tenant_id"`
	AgentID   string `json:"agent_id"`
	Revision  uint64 `json:"revision"`
	State     string `json:"state"`
	Reason    string `json:"reason"`
	IssuedAt  int64  `json:"issued_at"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

func (lifecycle FleetNodeLifecycle) Validate() error {
	if lifecycle.Version != FleetNodeLifecycleVersion || lifecycle.Revision == 0 || lifecycle.IssuedAt <= 0 {
		return fmt.Errorf("authority: invalid fleet node lifecycle version")
	}
	for name, value := range map[string]string{"tenant_id": lifecycle.TenantID, "agent_id": lifecycle.AgentID, "key_id": lifecycle.KeyID} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	if lifecycle.State != FleetNodePending && lifecycle.State != FleetNodeActive && lifecycle.State != FleetNodeRetired {
		return fmt.Errorf("authority: invalid fleet node lifecycle state")
	}
	if !boundedFleetText(lifecycle.Reason, 256, false) || len(strings.TrimSpace(lifecycle.Reason)) < 8 {
		return fmt.Errorf("authority: invalid fleet node lifecycle reason")
	}
	return nil
}

func (lifecycle FleetNodeLifecycle) Canonical() ([]byte, error) {
	if err := lifecycle.Validate(); err != nil {
		return nil, err
	}
	writer := canonicalWriter{}
	writer.string(FleetNodeLifecycleDomain)
	writer.u16(lifecycle.Version)
	writer.string(lifecycle.TenantID)
	writer.string(lifecycle.AgentID)
	writer.u64(lifecycle.Revision)
	writer.string(lifecycle.State)
	writer.string(lifecycle.Reason)
	writer.i64(lifecycle.IssuedAt)
	writer.string(lifecycle.KeyID)
	if writer.err != nil {
		return nil, writer.err
	}
	return writer.Buffer.Bytes(), nil
}

func (lifecycle *FleetNodeLifecycle) SignWith(signer func([]byte) ([]byte, error)) error {
	canonical, err := lifecycle.Canonical()
	if err != nil {
		return err
	}
	signature, err := signer(canonical)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("authority: fleet lifecycle signing failed")
	}
	lifecycle.Signature = base64.StdEncoding.EncodeToString(signature)
	return nil
}

func (lifecycle FleetNodeLifecycle) Verify(publicKey ed25519.PublicKey, now time.Time) error {
	canonical, err := lifecycle.Canonical()
	if err != nil {
		return err
	}
	if lifecycle.IssuedAt > now.Unix()+int64(MaxBundleClockSkew/time.Second) {
		return fmt.Errorf("authority: fleet lifecycle is from the future")
	}
	signature, err := base64.StdEncoding.DecodeString(lifecycle.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || len(publicKey) != ed25519.PublicKeySize || !ed25519.Verify(publicKey, canonical, signature) {
		return fmt.Errorf("authority: invalid fleet lifecycle signature")
	}
	return nil
}

type FleetGroup struct {
	Version      uint16   `json:"version"`
	TenantID     string   `json:"tenant_id"`
	ID           string   `json:"id"`
	Revision     uint64   `json:"revision"`
	DisplayName  string   `json:"display_name"`
	SelectorTags []string `json:"selector_tags,omitempty"`
	State        string   `json:"state"`
	Reason       string   `json:"reason"`
	IssuedAt     int64    `json:"issued_at"`
	KeyID        string   `json:"key_id"`
	Signature    string   `json:"signature"`
}

func (group FleetGroup) Validate() error {
	if group.Version != FleetGroupVersion || group.Revision == 0 || group.IssuedAt <= 0 {
		return fmt.Errorf("authority: invalid fleet group version")
	}
	for name, value := range map[string]string{"tenant_id": group.TenantID, "fleet group": group.ID, "key_id": group.KeyID} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	if group.State != FleetGroupActive && group.State != FleetGroupRetired || !boundedAuditText(group.DisplayName, 256, false) || !boundedFleetText(group.Reason, 256, false) || len(strings.TrimSpace(group.Reason)) < 8 {
		return fmt.Errorf("authority: invalid fleet group state")
	}
	if len(group.SelectorTags) > MaxFleetControlTags {
		return fmt.Errorf("authority: fleet group has too many selector tags")
	}
	tags := append([]string(nil), group.SelectorTags...)
	sort.Strings(tags)
	for index, tag := range tags {
		if err := validateIdentifier("fleet group selector tag", tag); err != nil {
			return err
		}
		if index > 0 && tags[index-1] == tag {
			return fmt.Errorf("authority: duplicate fleet group selector tag")
		}
	}
	return nil
}

func (group FleetGroup) Canonical() ([]byte, error) {
	if err := group.Validate(); err != nil {
		return nil, err
	}
	tags := append([]string(nil), group.SelectorTags...)
	sort.Strings(tags)
	writer := canonicalWriter{}
	writer.string(FleetGroupDomain)
	writer.u16(group.Version)
	writer.string(group.TenantID)
	writer.string(group.ID)
	writer.u64(group.Revision)
	writer.string(group.DisplayName)
	writer.u16(uint16(len(tags)))
	for _, tag := range tags {
		writer.string(tag)
	}
	writer.string(group.State)
	writer.string(group.Reason)
	writer.i64(group.IssuedAt)
	writer.string(group.KeyID)
	if writer.err != nil {
		return nil, writer.err
	}
	return writer.Buffer.Bytes(), nil
}

func (group *FleetGroup) SignWith(signer func([]byte) ([]byte, error)) error {
	canonical, err := group.Canonical()
	if err != nil {
		return err
	}
	signature, err := signer(canonical)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("authority: fleet group signing failed")
	}
	group.Signature = base64.StdEncoding.EncodeToString(signature)
	return nil
}

func (group FleetGroup) Verify(publicKey ed25519.PublicKey, now time.Time) error {
	canonical, err := group.Canonical()
	if err != nil {
		return err
	}
	if group.IssuedAt > now.Unix()+int64(MaxBundleClockSkew/time.Second) {
		return fmt.Errorf("authority: fleet group is from the future")
	}
	signature, err := base64.StdEncoding.DecodeString(group.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || len(publicKey) != ed25519.PublicKeySize || !ed25519.Verify(publicKey, canonical, signature) {
		return fmt.Errorf("authority: invalid fleet group signature")
	}
	return nil
}

type FleetCommandCancellationPersistence interface {
	SaveFleetCommandCancellation(context.Context, FleetCommandCancellation) error
	ListFleetCommandCancellations(context.Context, string) ([]FleetCommandCancellation, error)
}

type FleetNodeLifecyclePersistence interface {
	SaveFleetNodeLifecycle(context.Context, FleetNodeLifecycle) error
	ListFleetNodeLifecycles(context.Context, string) ([]FleetNodeLifecycle, error)
}

type FleetGroupPersistence interface {
	SaveFleetGroup(context.Context, FleetGroup) error
	ListFleetGroups(context.Context, string) ([]FleetGroup, error)
}

type FleetEnrollmentControlPersistence interface {
	SaveFleetEnrollmentControl(context.Context, FleetEnrollmentControl) error
	LoadFleetEnrollmentControl(context.Context, string) (FleetEnrollmentControl, bool, error)
}

func (manager *FleetManager) SetEnrollmentMode(mode string) error {
	if mode == "" {
		mode = FleetEnrollmentOpen
	}
	if mode != FleetEnrollmentOpen && mode != FleetEnrollmentApproval {
		return fmt.Errorf("authority: unsupported fleet enrollment mode %q", mode)
	}
	manager.enrollmentMu.Lock()
	manager.enrollmentMode = mode
	manager.enrollmentMu.Unlock()
	return nil
}

func (manager *FleetManager) EnrollmentMode() string {
	manager.enrollmentMu.RLock()
	defer manager.enrollmentMu.RUnlock()
	return manager.enrollmentMode
}

func (manager *FleetManager) ApplyEnrollmentControl(ctx context.Context, control FleetEnrollmentControl) error {
	persistence, ok := manager.persistence.(FleetEnrollmentControlPersistence)
	if !ok {
		return fmt.Errorf("authority: fleet enrollment control persistence is unavailable")
	}
	publicKey, err := manager.trust.DecisionKey(ctx, control.TenantID, control.KeyID)
	if err != nil {
		return err
	}
	if err := control.Verify(publicKey, manager.now()); err != nil {
		return err
	}
	current, found, err := manager.EnrollmentControl(ctx, control.TenantID)
	if err != nil {
		return err
	}
	if !found && control.Revision != 1 || found && control.Revision != current.Revision+1 {
		return fmt.Errorf("%w: fleet enrollment control revision", ErrStateConflict)
	}
	if err := persistence.SaveFleetEnrollmentControl(ctx, control); err != nil {
		return persistenceError("save fleet enrollment control", err)
	}
	return manager.SetEnrollmentMode(control.Mode)
}

func (manager *FleetManager) EnrollmentControl(ctx context.Context, tenantID string) (FleetEnrollmentControl, bool, error) {
	persistence, ok := manager.persistence.(FleetEnrollmentControlPersistence)
	if !ok {
		return FleetEnrollmentControl{}, false, nil
	}
	control, found, err := persistence.LoadFleetEnrollmentControl(ctx, tenantID)
	if err != nil || !found {
		return FleetEnrollmentControl{}, found, err
	}
	key, err := manager.trust.DecisionKey(ctx, tenantID, control.KeyID)
	if err != nil || control.Verify(key, manager.now()) != nil {
		return FleetEnrollmentControl{}, false, fmt.Errorf("authority: invalid stored fleet enrollment control")
	}
	return control, true, nil
}

func (manager *FleetManager) CancelCommand(ctx context.Context, cancellation FleetCommandCancellation) error {
	persistence, ok := manager.persistence.(FleetCommandCancellationPersistence)
	if !ok {
		return fmt.Errorf("authority: fleet command cancellation persistence is unavailable")
	}
	publicKey, err := manager.trust.DecisionKey(ctx, cancellation.TenantID, cancellation.KeyID)
	if err != nil {
		return err
	}
	if err := cancellation.Verify(publicKey, manager.now()); err != nil {
		return err
	}
	var command FleetCommand
	found := false
	if indexed, ok := manager.persistence.(IndexedFleetPersistence); ok {
		command, found, err = indexed.LoadFleetCommand(ctx, cancellation.TenantID, cancellation.CommandID)
		if err != nil {
			return persistenceError("load fleet command", err)
		}
	} else {
		commands, loadErr := manager.persistence.ListFleetCommands(ctx, cancellation.TenantID)
		if loadErr != nil {
			return persistenceError("load fleet commands", loadErr)
		}
		for _, candidate := range commands {
			if candidate.ID == cancellation.CommandID {
				command, found = candidate, true
				break
			}
		}
	}
	if !found {
		return fmt.Errorf("authority: fleet command is not available")
	}
	if cancellation.IssuedAt < command.IssuedAt || cancellation.IssuedAt > command.ExpiresAt+int64(MaxBundleClockSkew/time.Second) {
		return fmt.Errorf("authority: fleet cancellation is outside command validity")
	}
	if err := persistence.SaveFleetCommandCancellation(ctx, cancellation); err != nil {
		return persistenceError("save fleet command cancellation", err)
	}
	return nil
}

func (manager *FleetManager) Cancellations(ctx context.Context, tenantID string) ([]FleetCommandCancellation, error) {
	persistence, ok := manager.persistence.(FleetCommandCancellationPersistence)
	if !ok {
		return nil, nil
	}
	cancellations, err := persistence.ListFleetCommandCancellations(ctx, tenantID)
	if err != nil {
		return nil, persistenceError("load fleet command cancellations", err)
	}
	for _, cancellation := range cancellations {
		key, keyErr := manager.trust.DecisionKey(ctx, tenantID, cancellation.KeyID)
		if keyErr != nil || cancellation.Verify(key, manager.now()) != nil {
			return nil, fmt.Errorf("authority: invalid stored fleet command cancellation")
		}
	}
	return cancellations, nil
}

func (manager *FleetManager) SetNodeLifecycle(ctx context.Context, lifecycle FleetNodeLifecycle) error {
	persistence, ok := manager.persistence.(FleetNodeLifecyclePersistence)
	if !ok {
		return fmt.Errorf("authority: fleet node lifecycle persistence is unavailable")
	}
	publicKey, err := manager.trust.DecisionKey(ctx, lifecycle.TenantID, lifecycle.KeyID)
	if err != nil {
		return err
	}
	if err := lifecycle.Verify(publicKey, manager.now()); err != nil {
		return err
	}
	found := false
	if indexed, ok := manager.persistence.(IndexedFleetPersistence); ok {
		found, err = indexed.FleetNodeReportExists(ctx, lifecycle.TenantID, lifecycle.AgentID)
		if err != nil {
			return persistenceError("load fleet report", err)
		}
	} else {
		reports, loadErr := manager.persistence.ListFleetNodeReports(ctx, lifecycle.TenantID)
		if loadErr != nil {
			return persistenceError("load fleet reports", loadErr)
		}
		for _, report := range reports {
			if report.AgentID == lifecycle.AgentID {
				found = true
				break
			}
		}
	}
	if !found {
		return fmt.Errorf("authority: fleet lifecycle target has not presented a signed report")
	}
	existing, exists, err := manager.NodeLifecycle(ctx, lifecycle.TenantID, lifecycle.AgentID)
	if err != nil {
		return err
	}
	if exists && lifecycle.Revision <= existing.Revision {
		if lifecycle.Revision == existing.Revision && lifecycle.Signature == existing.Signature {
			return nil
		}
		return fmt.Errorf("%w: fleet node lifecycle revision", ErrStateConflict)
	}
	if !exists && lifecycle.Revision != 1 || exists && lifecycle.Revision != existing.Revision+1 {
		return fmt.Errorf("%w: fleet node lifecycle revision", ErrStateConflict)
	}
	if err := persistence.SaveFleetNodeLifecycle(ctx, lifecycle); err != nil {
		return persistenceError("save fleet node lifecycle", err)
	}
	manager.lifecycleCache.put(lifecycle)
	return nil
}

func (manager *FleetManager) NodeLifecycle(ctx context.Context, tenantID, agentID string) (FleetNodeLifecycle, bool, error) {
	persistence, ok := manager.persistence.(FleetNodeLifecyclePersistence)
	if !ok {
		return FleetNodeLifecycle{}, false, nil
	}
	lifecycles, err := persistence.ListFleetNodeLifecycles(ctx, tenantID)
	if err != nil {
		return FleetNodeLifecycle{}, false, persistenceError("load fleet node lifecycles", err)
	}
	for _, lifecycle := range lifecycles {
		if lifecycle.AgentID == agentID {
			return lifecycle, true, nil
		}
	}
	return FleetNodeLifecycle{}, false, nil
}

func (manager *FleetManager) NodeLifecycles(ctx context.Context, tenantID string) ([]FleetNodeLifecycle, error) {
	persistence, ok := manager.persistence.(FleetNodeLifecyclePersistence)
	if !ok {
		return nil, nil
	}
	lifecycles, err := persistence.ListFleetNodeLifecycles(ctx, tenantID)
	if err != nil {
		return nil, persistenceError("load fleet node lifecycles", err)
	}
	for _, lifecycle := range lifecycles {
		key, keyErr := manager.trust.DecisionKey(ctx, tenantID, lifecycle.KeyID)
		if keyErr != nil || lifecycle.Verify(key, manager.now()) != nil {
			return nil, fmt.Errorf("authority: invalid stored fleet node lifecycle")
		}
	}
	return lifecycles, nil
}

func (manager *FleetManager) SaveGroup(ctx context.Context, group FleetGroup) error {
	persistence, ok := manager.persistence.(FleetGroupPersistence)
	if !ok {
		return fmt.Errorf("authority: fleet group persistence is unavailable")
	}
	publicKey, err := manager.trust.DecisionKey(ctx, group.TenantID, group.KeyID)
	if err != nil {
		return err
	}
	if err := group.Verify(publicKey, manager.now()); err != nil {
		return err
	}
	groups, err := manager.Groups(ctx, group.TenantID)
	if err != nil {
		return err
	}
	var existing *FleetGroup
	for index := range groups {
		if groups[index].ID == group.ID {
			existing = &groups[index]
			break
		}
	}
	if existing == nil && group.Revision != 1 || existing != nil && group.Revision != existing.Revision+1 {
		return fmt.Errorf("%w: fleet group revision", ErrStateConflict)
	}
	if err := persistence.SaveFleetGroup(ctx, group); err != nil {
		return persistenceError("save fleet group", err)
	}
	return nil
}

func (manager *FleetManager) Groups(ctx context.Context, tenantID string) ([]FleetGroup, error) {
	persistence, ok := manager.persistence.(FleetGroupPersistence)
	if !ok {
		return nil, nil
	}
	groups, err := persistence.ListFleetGroups(ctx, tenantID)
	if err != nil {
		return nil, persistenceError("load fleet groups", err)
	}
	for _, group := range groups {
		key, keyErr := manager.trust.DecisionKey(ctx, tenantID, group.KeyID)
		if keyErr != nil || group.Verify(key, manager.now()) != nil {
			return nil, fmt.Errorf("authority: invalid stored fleet group")
		}
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].ID < groups[j].ID })
	return groups, nil
}

func (manager *FleetManager) nodeOperational(tenantID, agentID string) bool {
	state, found := manager.lifecycleCache.state(tenantID, agentID)
	if manager.EnrollmentMode() == FleetEnrollmentApproval {
		return found && state == FleetNodeActive
	}
	return !found || state == FleetNodeActive
}

type fleetLifecycleCache struct {
	mu     sync.RWMutex
	states map[string]string
}

func (cache *fleetLifecycleCache) replace(lifecycles []FleetNodeLifecycle) {
	states := make(map[string]string, len(lifecycles))
	for _, lifecycle := range lifecycles {
		states[lifecycle.TenantID+"\x00"+lifecycle.AgentID] = lifecycle.State
	}
	cache.mu.Lock()
	cache.states = states
	cache.mu.Unlock()
}

func (cache *fleetLifecycleCache) put(lifecycle FleetNodeLifecycle) {
	cache.mu.Lock()
	if cache.states == nil {
		cache.states = make(map[string]string)
	}
	cache.states[lifecycle.TenantID+"\x00"+lifecycle.AgentID] = lifecycle.State
	cache.mu.Unlock()
}

func (cache *fleetLifecycleCache) state(tenantID, agentID string) (string, bool) {
	cache.mu.RLock()
	state, found := cache.states[tenantID+"\x00"+agentID]
	cache.mu.RUnlock()
	return state, found
}

func fleetCommandCancellationID(cancellation FleetCommandCancellation) string {
	writer := canonicalWriter{}
	writer.string(FleetCommandCancellationDomain + "/id")
	writer.string(cancellation.TenantID)
	writer.string(cancellation.CommandID)
	writer.string(cancellation.Reason)
	writer.i64(cancellation.IssuedAt)
	writer.string(cancellation.KeyID)
	sum := sha256.Sum256(writer.Buffer.Bytes())
	return hex.EncodeToString(sum[:])
}
