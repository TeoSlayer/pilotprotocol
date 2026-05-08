// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"regexp"
	"sync"
	"time"

	acceptpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/accept"
	dirpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/directory"
	membpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/membership"
	trustpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/trust"
	webhookpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/webhook"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry/wire"
)

type (
	KeyInfo  = dirpkg.KeyInfo
	NodeInfo = dirpkg.NodeInfo
)

type (
	Role          = membpkg.Role
	NetworkPolicy = membpkg.NetworkPolicy
	NetworkInfo   = membpkg.NetworkInfo
	NetworkInvite = membpkg.NetworkInvite
)

const (
	RoleOwner  = membpkg.RoleOwner
	RoleAdmin  = membpkg.RoleAdmin
	RoleMember = membpkg.RoleMember
)

const maxInviteInbox = membpkg.MaxInviteInbox
const inviteTTL = membpkg.InviteTTL

type (
	HandshakeRelayMsg    = trustpkg.HandshakeRelayMsg
	HandshakeResponseMsg = trustpkg.HandshakeResponseMsg
)

type RegistryWebhookEvent = webhookpkg.Event

// Blueprint types — canonical definitions live in pkg/registry/wire.
type (
	NetworkBlueprint          = wire.NetworkBlueprint
	BlueprintPolicy           = wire.BlueprintPolicy
	BlueprintRole             = wire.BlueprintRole
	BlueprintIdentityProvider = wire.BlueprintIdentityProvider
	BlueprintWebhooks         = wire.BlueprintWebhooks
	BlueprintAuditExport      = wire.BlueprintAuditExport
)

var (
	LoadBlueprint     = wire.LoadBlueprint
	ValidateBlueprint = wire.ValidateBlueprint
)

type RateLimiter = acceptpkg.RateLimiter

func NewRateLimiter(rate int, window time.Duration, maxBuckets int) *RateLimiter {
	return acceptpkg.NewRateLimiter(rate, window, maxBuckets)
}

// ShouldLog delegates log-sampling to s.accept. Returns true if this
// occurrence of key should be logged, plus the suppressed count.
func (s *Server) ShouldLog(key string) (bool, int64) {
	return s.accept.ShouldLog(key)
}

// nodeShard returns the shard lock for the given node ID.
func (s *Server) nodeShard(nodeID uint32) *sync.RWMutex {
	return &s.nodeShards[nodeID%numNodeShards]
}

// StaleNodeThreshold returns the current configured stale-node threshold.
// Hot path on online-count read sites; uses an atomic load.
func (s *Server) StaleNodeThreshold() time.Duration {
	if ns := s.staleNodeThresholdNs.Load(); ns > 0 {
		return time.Duration(ns)
	}
	return defaultStaleNodeThreshold
}

// SetStaleNodeThreshold updates the threshold. Zero or negative values are
// ignored to prevent accidentally disabling staleness detection. Intended
// for one-time configuration at startup; safe to call concurrently with
// readers.
func (s *Server) SetStaleNodeThreshold(d time.Duration) {
	if d <= 0 {
		return
	}
	s.staleNodeThresholdNs.Store(int64(d))
}

// hostnameRegex validates hostname format: lowercase alphanumeric + hyphens, 1-63 chars.
var hostnameRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// tagRegex validates tag format: lowercase alphanumeric + hyphens, 1-32 chars.
var tagRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)

// reservedHostnames are not allowed as node hostnames.
var reservedHostnames = map[string]bool{
	"localhost": true,
	"backbone":  true,
	"broadcast": true,
}

// validateHostname checks that a hostname is valid for registration.
func validateHostname(name string) error {
	if len(name) == 0 {
		return nil // empty clears hostname
	}
	if len(name) > 63 {
		return fmt.Errorf("hostname too long (max 63 chars)")
	}
	if !hostnameRegex.MatchString(name) {
		return fmt.Errorf("hostname must be lowercase alphanumeric with hyphens, start/end with alphanumeric")
	}
	if reservedHostnames[name] {
		return fmt.Errorf("hostname %q is reserved", name)
	}
	return nil
}

// validateNetworkName delegates to the membership sub-package (R4.1).
func validateNetworkName(name string) error {
	return membpkg.ValidateNetworkName(name)
}

// Wire helpers: 4-byte big-endian length prefix + JSON body

func readMessage(r io.Reader) (map[string]interface{}, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length > wire.MaxMessageSize { // 64KB max
		return nil, fmt.Errorf("message too large: %d bytes (max %d)", length, wire.MaxMessageSize)
	}

	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}

	var msg map[string]interface{}
	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, fmt.Errorf("json decode: %w", err)
	}
	return msg, nil
}

// writeMessageDeadline bounds how long a single response write can take.
// If a client is slow to drain (overloaded host, kernel buffer pressure)
// we'd otherwise hold the request goroutine + response payload in memory
// indefinitely, magnifying contention back-pressure on the registry.
// The previous symptom: thousands of "connection reset by peer" errors
// because write blocked waiting for a slow client whose TCP stack RST'd
// before draining. After this deadline expires, w.Write returns an error
// and we drop the connection cleanly.
const writeMessageDeadline = 5 * time.Second

func writeMessage(w io.Writer, msg map[string]interface{}) error {
	// Fast path: handler signals "I already produced the full response
	// bytes — skip json.Marshal entirely". Used by list_nodes cache hits
	// to avoid the encoder's appendCompact pass over already-valid bytes.
	if raw, ok := msg[rawResponseKey].([]byte); ok && raw != nil {
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(raw)))
		if c, ok := w.(net.Conn); ok {
			_ = c.SetWriteDeadline(time.Now().Add(writeMessageDeadline))
			defer c.SetWriteDeadline(time.Time{})
		}
		if _, err := w.Write(lenBuf[:]); err != nil {
			return err
		}
		if _, err := w.Write(raw); err != nil {
			return err
		}
		return nil
	}

	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("json encode: %w", err)
	}

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))

	// If the underlying writer is a net.Conn, set a write deadline so a
	// stuck/overloaded client can't pin a response goroutine forever.
	// (io.Writer is the parameter type for unit-test friendliness; in
	// production this is always a *net.TCPConn.)
	if c, ok := w.(net.Conn); ok {
		_ = c.SetWriteDeadline(time.Now().Add(writeMessageDeadline))
		defer c.SetWriteDeadline(time.Time{}) // clear after this call
	}

	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := w.Write(body); err != nil {
		return err
	}
	return nil
}

// JSON number helpers (json.Unmarshal uses float64 for numbers)

func jsonUint32(msg map[string]interface{}, key string) uint32 {
	if v, ok := msg[key].(float64); ok {
		if v < 0 || v > float64(^uint32(0)) {
			return 0
		}
		return uint32(v)
	}
	return 0
}

func jsonUint16(msg map[string]interface{}, key string) uint16 {
	if v, ok := msg[key].(float64); ok {
		if v < 0 || v > float64(^uint16(0)) {
			return 0
		}
		return uint16(v)
	}
	return 0
}

func base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
