package nameserver

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"web4/pkg/protocol"
)

// atomicWrite writes data to a file with fsync to ensure durability.
func atomicWrite(path string, data []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Record types
const (
	RecordA = "A" // Name → Virtual Address
	RecordN = "N" // Network name → Network ID
	RecordS = "S" // Service discovery
)

// Record is a name record in the nameserver.
type Record struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Address string `json:"address,omitempty"`    // for A records
	NetID   uint16 `json:"network_id,omitempty"` // for N records
	Port    uint16 `json:"port,omitempty"`       // for S records
	NodeID  uint32 `json:"node_id,omitempty"`    // for S records (who registered it)
}

// Default TTL for nameserver records.
const DefaultRecordTTL = 5 * time.Minute

// aEntry wraps an A record with creation time for TTL expiry.
type aEntry struct {
	Addr      protocol.Addr
	CreatedAt time.Time
}

// nEntry wraps an N record with creation time for TTL expiry.
type nEntry struct {
	NetID     uint16
	CreatedAt time.Time
}

// RecordStore holds all nameserver records in memory.
type RecordStore struct {
	mu        sync.RWMutex
	aRecords  map[string]*aEntry        // name → addr entry
	nRecords  map[string]*nEntry        // network name → network ID entry
	sRecords  map[svcKey][]ServiceEntry // (network_id, port) → providers
	storePath string                    // path to persist records (empty = no persistence)
	ttl       time.Duration
	done      chan struct{}
}

type svcKey struct {
	NetworkID uint16
	Port      uint16
}

// ServiceEntry is a provider of a service.
type ServiceEntry struct {
	Name      string        `json:"name"`
	Address   protocol.Addr `json:"address"`
	Port      uint16        `json:"port"`
	CreatedAt time.Time     `json:"-"` // for TTL expiry (L6 fix)
}

func NewRecordStore() *RecordStore {
	rs := &RecordStore{
		aRecords: make(map[string]*aEntry),
		nRecords: make(map[string]*nEntry),
		sRecords: make(map[svcKey][]ServiceEntry),
		ttl:      DefaultRecordTTL,
		done:     make(chan struct{}),
	}
	go rs.reapLoop()
	return rs
}

// Close stops the reaper goroutine.
func (rs *RecordStore) Close() {
	select {
	case <-rs.done:
	default:
		close(rs.done)
	}
}

// reapLoop periodically removes expired records.
func (rs *RecordStore) reapLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rs.reapExpired()
		case <-rs.done:
			return
		}
	}
}

func (rs *RecordStore) reapExpired() {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	now := time.Now()
	reaped := false
	for name, e := range rs.aRecords {
		if now.Sub(e.CreatedAt) > rs.ttl {
			delete(rs.aRecords, name)
			reaped = true
		}
	}
	for name, e := range rs.nRecords {
		if now.Sub(e.CreatedAt) > rs.ttl {
			delete(rs.nRecords, name)
			reaped = true
		}
	}
	// L6 fix: also reap expired S records
	for key, entries := range rs.sRecords {
		alive := entries[:0]
		for _, e := range entries {
			if !e.CreatedAt.IsZero() && now.Sub(e.CreatedAt) > rs.ttl {
				reaped = true
				continue
			}
			alive = append(alive, e)
		}
		if len(alive) == 0 {
			delete(rs.sRecords, key)
		} else {
			rs.sRecords[key] = alive
		}
	}
	if reaped {
		rs.save()
	}
}

// SetStorePath enables persistence to the given file path and loads existing data.
func (rs *RecordStore) SetStorePath(path string) {
	rs.mu.Lock()
	rs.storePath = path
	rs.mu.Unlock()
	rs.load()
}

// --- Persistence ---

type recordSnapshot struct {
	ARecords []snapshotA `json:"a_records"`
	NRecords []snapshotN `json:"n_records"`
	SRecords []snapshotS `json:"s_records"`
}

type snapshotA struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

type snapshotN struct {
	Name      string `json:"name"`
	NetworkID uint16 `json:"network_id"`
}

type snapshotS struct {
	Name      string `json:"name"`
	Address   string `json:"address"`
	NetworkID uint16 `json:"network_id"`
	Port      uint16 `json:"port"`
}

func (rs *RecordStore) save() {
	if rs.storePath == "" {
		return
	}

	snap := recordSnapshot{}
	for name, e := range rs.aRecords {
		snap.ARecords = append(snap.ARecords, snapshotA{Name: name, Address: e.Addr.String()})
	}
	for name, e := range rs.nRecords {
		snap.NRecords = append(snap.NRecords, snapshotN{Name: name, NetworkID: e.NetID})
	}
	for key, entries := range rs.sRecords {
		for _, e := range entries {
			snap.SRecords = append(snap.SRecords, snapshotS{
				Name:      e.Name,
				Address:   e.Address.String(),
				NetworkID: key.NetworkID,
				Port:      e.Port,
			})
		}
	}

	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		slog.Error("save nameserver state", "err", err)
		return
	}

	dir := filepath.Dir(rs.storePath)
	os.MkdirAll(dir, 0700)

	tmpPath := rs.storePath + ".tmp"
	if err := atomicWrite(tmpPath, data); err != nil {
		slog.Error("write nameserver state", "err", err)
		return
	}
	if err := os.Rename(tmpPath, rs.storePath); err != nil {
		slog.Error("rename nameserver state", "err", err)
		return
	}
	slog.Debug("nameserver state saved", "a_records", len(rs.aRecords), "n_records", len(rs.nRecords))
}

func (rs *RecordStore) load() {
	if rs.storePath == "" {
		return
	}

	data, err := os.ReadFile(rs.storePath)
	if err != nil {
		return // no file yet
	}

	var snap recordSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		slog.Warn("load nameserver state", "err", err)
		return
	}

	for _, a := range snap.ARecords {
		addr, err := protocol.ParseAddr(a.Address)
		if err != nil {
			continue
		}
		rs.aRecords[a.Name] = &aEntry{Addr: addr, CreatedAt: time.Now()}
	}
	for _, n := range snap.NRecords {
		rs.nRecords[n.Name] = &nEntry{NetID: n.NetworkID, CreatedAt: time.Now()}
	}
	for _, s := range snap.SRecords {
		addr, err := protocol.ParseAddr(s.Address)
		if err != nil {
			continue
		}
		key := svcKey{NetworkID: s.NetworkID, Port: s.Port}
		rs.sRecords[key] = append(rs.sRecords[key], ServiceEntry{
			Name:      s.Name,
			Address:   addr,
			Port:      s.Port,
			CreatedAt: time.Now(),
		})
	}
	slog.Info("loaded nameserver state", "a_records", len(rs.aRecords), "n_records", len(rs.nRecords))
}

// RegisterA adds or updates an A record (name → address).
func (rs *RecordStore) RegisterA(name string, addr protocol.Addr) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.aRecords[name] = &aEntry{Addr: addr, CreatedAt: time.Now()}
	rs.save()
}

// LookupA resolves a name to an address.
func (rs *RecordStore) LookupA(name string) (protocol.Addr, error) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	e, ok := rs.aRecords[name]
	if !ok {
		return protocol.AddrZero, fmt.Errorf("name %q not found", name)
	}
	return e.Addr, nil
}

// RegisterN adds a network name record.
func (rs *RecordStore) RegisterN(name string, netID uint16) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.nRecords[name] = &nEntry{NetID: netID, CreatedAt: time.Now()}
	rs.save()
}

// LookupN resolves a network name to a network ID.
func (rs *RecordStore) LookupN(name string) (uint16, error) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	e, ok := rs.nRecords[name]
	if !ok {
		return 0, fmt.Errorf("network %q not found", name)
	}
	return e.NetID, nil
}

// RegisterS registers a service provider.
func (rs *RecordStore) RegisterS(name string, addr protocol.Addr, networkID, port uint16) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	key := svcKey{NetworkID: networkID, Port: port}
	entry := ServiceEntry{Name: name, Address: addr, Port: port, CreatedAt: time.Now()}
	// Avoid duplicates — refresh TTL if already present
	for i, e := range rs.sRecords[key] {
		if e.Address == addr && e.Port == port {
			rs.sRecords[key][i].CreatedAt = time.Now()
			return
		}
	}
	rs.sRecords[key] = append(rs.sRecords[key], entry)
	rs.save()
}

// LookupS finds service providers on a network+port.
func (rs *RecordStore) LookupS(networkID, port uint16) []ServiceEntry {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	key := svcKey{NetworkID: networkID, Port: port}
	result := make([]ServiceEntry, len(rs.sRecords[key]))
	copy(result, rs.sRecords[key])
	return result
}

// UnregisterA removes an A record.
func (rs *RecordStore) UnregisterA(name string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	delete(rs.aRecords, name)
	rs.save()
}

// AllA returns all A records.
func (rs *RecordStore) AllA() map[string]protocol.Addr {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	result := make(map[string]protocol.Addr, len(rs.aRecords))
	for k, e := range rs.aRecords {
		result[k] = e.Addr
	}
	return result
}
