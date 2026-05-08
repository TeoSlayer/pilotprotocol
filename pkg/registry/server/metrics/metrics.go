// SPDX-License-Identifier: AGPL-3.0-or-later

// Package metrics provides the lightweight Prometheus text-format metrics
// types and the Store that aggregates them for the registry server.
package metrics

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// --- Lightweight Prometheus text-format metrics (zero external deps) ---

// Counter is a monotonically increasing atomic counter.
type Counter struct {
	val atomic.Int64
}

func (c *Counter) Inc() { c.val.Add(1) }

func (c *Counter) Get() float64 { return float64(c.val.Load()) }

// Gauge is a numeric value that can go up and down.
type Gauge struct {
	mu  sync.Mutex
	val float64
}

func (g *Gauge) Set(v float64) {
	g.mu.Lock()
	g.val = v
	g.mu.Unlock()
}

func (g *Gauge) Get() float64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.val
}

// Histogram tracks the distribution of observed values in predefined buckets.
type Histogram struct {
	mu      sync.Mutex
	buckets []float64 // upper bounds (sorted)
	counts  []uint64  // counts[i] = observations <= buckets[i]
	sum     float64
	count   uint64
}

func NewHistogram(buckets []float64) *Histogram {
	sorted := make([]float64, len(buckets))
	copy(sorted, buckets)
	sort.Float64s(sorted)
	return &Histogram{
		buckets: sorted,
		counts:  make([]uint64, len(sorted)),
	}
}

func (h *Histogram) Observe(v float64) {
	h.mu.Lock()
	for i, b := range h.buckets {
		if v <= b {
			h.counts[i]++
		}
	}
	h.sum += v
	h.count++
	h.mu.Unlock()
}

// Snapshot returns a copy; callers must not hold h.mu (deadlock) or retain
// pointers into the returned slices after mutation.
func (h *Histogram) Snapshot() (buckets []float64, counts []uint64, sum float64, count uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	buckets = make([]float64, len(h.buckets))
	counts = make([]uint64, len(h.counts))
	copy(buckets, h.buckets)
	copy(counts, h.counts)
	return buckets, counts, h.sum, h.count
}

// CounterVec is a set of Counters keyed by a single label value.
type CounterVec struct {
	mu       sync.RWMutex
	counters map[string]*Counter
}

func NewCounterVec() *CounterVec {
	return &CounterVec{counters: make(map[string]*Counter)}
}

func (cv *CounterVec) WithLabel(val string) *Counter {
	cv.mu.RLock()
	c, ok := cv.counters[val]
	cv.mu.RUnlock()
	if ok {
		return c
	}
	cv.mu.Lock()
	defer cv.mu.Unlock()
	if c, ok = cv.counters[val]; ok {
		return c
	}
	c = &Counter{}
	cv.counters[val] = c
	return c
}

func (cv *CounterVec) Snapshot() []LabelValue {
	cv.mu.RLock()
	defer cv.mu.RUnlock()
	out := make([]LabelValue, 0, len(cv.counters))
	for k, c := range cv.counters {
		out = append(out, LabelValue{Label: k, Value: c.Get()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out
}

// HistogramVec is a set of Histograms keyed by a single label value.
type HistogramVec struct {
	mu         sync.RWMutex
	histograms map[string]*Histogram
	buckets    []float64
}

func NewHistogramVec(buckets []float64) *HistogramVec {
	return &HistogramVec{
		histograms: make(map[string]*Histogram),
		buckets:    buckets,
	}
}

func (hv *HistogramVec) WithLabel(val string) *Histogram {
	hv.mu.RLock()
	h, ok := hv.histograms[val]
	hv.mu.RUnlock()
	if ok {
		return h
	}
	hv.mu.Lock()
	defer hv.mu.Unlock()
	if h, ok = hv.histograms[val]; ok {
		return h
	}
	h = NewHistogram(hv.buckets)
	hv.histograms[val] = h
	return h
}

func (hv *HistogramVec) Snapshot() []LabelHistogram {
	hv.mu.RLock()
	defer hv.mu.RUnlock()
	out := make([]LabelHistogram, 0, len(hv.histograms))
	for k, h := range hv.histograms {
		buckets, counts, sum, count := h.Snapshot()
		out = append(out, LabelHistogram{Label: k, Buckets: buckets, Counts: counts, Sum: sum, Count: count})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out
}

type LabelValue struct {
	Label string
	Value float64
}

type LabelHistogram struct {
	Label   string
	Buckets []float64
	Counts  []uint64
	Sum     float64
	Count   uint64
}

// --- Store ---

// DefaultDurationBuckets are the default histogram buckets for request duration (seconds).
var DefaultDurationBuckets = []float64{
	0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0,
}

// NetworkMetricSnapshot holds per-network metrics computed on each scrape.
type NetworkMetricSnapshot struct {
	Name       string
	Members    int
	Owners     int
	Admins     int
	Enterprise bool
	PolicySet  bool
}

// Store aggregates all Prometheus metrics for the registry server.
// It is intentionally zero-external-dependency.
type Store struct {
	// Request metrics (labeled by message type)
	RequestsTotal   *CounterVec   // pilot_requests_total{type="..."}
	RequestDuration *HistogramVec // pilot_request_duration_seconds{type="..."}
	ErrorsTotal     *CounterVec   // pilot_errors_total{type="..."}

	// Gauge metrics (updated on each scrape)
	NodesOnline   Gauge // pilot_nodes_online
	NodesTotal    Gauge // pilot_nodes_total
	TrustLinks    Gauge // pilot_trust_links
	TaskExecutors Gauge // pilot_task_executors
	UptimeSeconds Gauge // pilot_uptime_seconds

	// Lifecycle counters
	Registrations     Counter // pilot_registrations_total
	Deregistrations   Counter // pilot_deregistrations_total
	TrustReports      Counter // pilot_trust_reports_total
	TrustRevocations  Counter // pilot_trust_revocations_total
	HandshakeRequests Counter // pilot_handshake_requests_total

	// Network gauges (updated on each scrape)
	NetworksTotal      Gauge // pilot_networks_total
	NetworksEnterprise Gauge // pilot_networks_enterprise
	InvitesPending     Gauge // pilot_invites_pending

	// Enterprise counters
	AuditEventsTotal Counter     // pilot_audit_events_total
	InvitesSent      Counter     // pilot_invites_sent_total
	InvitesAccepted  Counter     // pilot_invites_accepted_total
	InvitesRejected  Counter     // pilot_invites_rejected_total
	RbacOps          *CounterVec // pilot_rbac_operations_total{op="..."}
	PolicyChanges    Counter     // pilot_policy_changes_total
	KeyRotations     Counter     // pilot_key_rotations_total

	// Provisioning counters
	ProvisionsTotal    Counter // pilot_provisions_total
	AuditExportsTotal  Counter // pilot_audit_exports_total
	AuditExportErrors  Counter // pilot_audit_export_errors_total
	IdpVerifications   Counter // pilot_idp_verifications_total
	RbacPreAssignments Counter // pilot_rbac_pre_assignments_total

	// Reliability counters (Phase 3 wiring)
	WalFull      Counter // pilot_wal_full_total
	WalErrors    Counter // pilot_wal_errors_total
	SaveFailures Counter // pilot_save_failures_total

	// Per-network metrics (computed on scrape, for Grafana dashboards)
	networkMetricsMu sync.Mutex
	NetworkMetrics   []NetworkMetricSnapshot

	// Enterprise status gauges
	IdpConfigured     Gauge // pilot_idp_configured (0 or 1)
	WebhookConfigured Gauge // pilot_webhook_configured (0 or 1)
	AuditExportActive Gauge // pilot_audit_export_active (0 or 1)
	DirectorySynced   Gauge // pilot_directory_synced_networks

	// Runtime / saturation observability
	RuntimeGoroutines     Gauge // pilot_runtime_goroutines
	RuntimeConnectionsTCP Gauge // pilot_registry_tcp_connections
	HandshakeInboxSize    Gauge // pilot_handshake_inbox_size
	HandshakeRespSize     Gauge // pilot_handshake_responses_size

	// list_nodes cache observability
	ListNodesCacheHits     Gauge // pilot_list_nodes_cache_hits
	ListNodesCacheWaits    Gauge // pilot_list_nodes_cache_waits
	ListNodesCacheRebuilds Gauge // pilot_list_nodes_cache_rebuilds

	// PanicCountFn returns the total recovered-panic count since process start.
	// Injected at construction so WriteTo can surface it without importing server.
	PanicCountFn func() uint64
}

// SetNetworkMetrics replaces the per-network snapshot slice (thread-safe).
func (st *Store) SetNetworkMetrics(snaps []NetworkMetricSnapshot) {
	st.networkMetricsMu.Lock()
	st.NetworkMetrics = snaps
	st.networkMetricsMu.Unlock()
}

// GetNetworkMetrics returns a copy of the per-network snapshot slice (thread-safe).
func (st *Store) GetNetworkMetrics() []NetworkMetricSnapshot {
	st.networkMetricsMu.Lock()
	defer st.networkMetricsMu.Unlock()
	return st.NetworkMetrics
}

// NewStore creates a new Store with all vecs initialized.
func NewStore(panicCountFn func() uint64) *Store {
	return &Store{
		RequestsTotal:   NewCounterVec(),
		RequestDuration: NewHistogramVec(DefaultDurationBuckets),
		ErrorsTotal:     NewCounterVec(),
		RbacOps:         NewCounterVec(),
		PanicCountFn:    panicCountFn,
	}
}

func (st *Store) WriteTo(w io.Writer) (int64, error) {
	var b strings.Builder

	// --- Request counters (labeled) ---
	writeHelp(&b, "pilot_requests_total", "Total number of registry requests by type.")
	writeType(&b, "pilot_requests_total", "counter")
	for _, lv := range st.RequestsTotal.Snapshot() {
		writeLabeledMetric(&b, "pilot_requests_total", "type", lv.Label, lv.Value)
	}

	// --- Error counters (labeled) ---
	writeHelp(&b, "pilot_errors_total", "Total number of registry errors by type.")
	writeType(&b, "pilot_errors_total", "counter")
	for _, lv := range st.ErrorsTotal.Snapshot() {
		writeLabeledMetric(&b, "pilot_errors_total", "type", lv.Label, lv.Value)
	}

	// --- Request duration histograms (labeled) ---
	writeHelp(&b, "pilot_request_duration_seconds", "Histogram of request durations in seconds.")
	writeType(&b, "pilot_request_duration_seconds", "histogram")
	for _, lh := range st.RequestDuration.Snapshot() {
		for i, bound := range lh.Buckets {
			writeBucketMetric(&b, "pilot_request_duration_seconds", "type", lh.Label, bound, lh.Counts[i])
		}
		writeBucketInf(&b, "pilot_request_duration_seconds", "type", lh.Label, lh.Count)
		writeLabeledMetric(&b, "pilot_request_duration_seconds_sum", "type", lh.Label, lh.Sum)
		writeLabeledMetric(&b, "pilot_request_duration_seconds_count", "type", lh.Label, float64(lh.Count))
	}

	// --- Gauges ---
	writeHelp(&b, "pilot_nodes_online", "Number of nodes currently online.")
	writeType(&b, "pilot_nodes_online", "gauge")
	writeMetric(&b, "pilot_nodes_online", st.NodesOnline.Get())

	writeHelp(&b, "pilot_nodes_total", "Total number of registered nodes.")
	writeType(&b, "pilot_nodes_total", "gauge")
	writeMetric(&b, "pilot_nodes_total", st.NodesTotal.Get())

	writeHelp(&b, "pilot_trust_links", "Number of active trust pairs.")
	writeType(&b, "pilot_trust_links", "gauge")
	writeMetric(&b, "pilot_trust_links", st.TrustLinks.Get())

	writeHelp(&b, "pilot_task_executors", "Number of nodes advertising task execution.")
	writeType(&b, "pilot_task_executors", "gauge")
	writeMetric(&b, "pilot_task_executors", st.TaskExecutors.Get())

	writeHelp(&b, "pilot_uptime_seconds", "Registry server uptime in seconds.")
	writeType(&b, "pilot_uptime_seconds", "gauge")
	writeMetric(&b, "pilot_uptime_seconds", st.UptimeSeconds.Get())

	// --- Saturation gauges (lock contention / queue depth) ---
	writeHelp(&b, "pilot_runtime_goroutines", "Total live goroutines (runtime.NumGoroutine). Spike indicates lock pile-up.")
	writeType(&b, "pilot_runtime_goroutines", "gauge")
	writeMetric(&b, "pilot_runtime_goroutines", st.RuntimeGoroutines.Get())

	writeHelp(&b, "pilot_registry_tcp_connections", "Active TCP connections to the registry listener.")
	writeType(&b, "pilot_registry_tcp_connections", "gauge")
	writeMetric(&b, "pilot_registry_tcp_connections", st.RuntimeConnectionsTCP.Get())

	writeHelp(&b, "pilot_handshake_inbox_size", "Sum of pending handshake-request entries across all node inboxes.")
	writeType(&b, "pilot_handshake_inbox_size", "gauge")
	writeMetric(&b, "pilot_handshake_inbox_size", st.HandshakeInboxSize.Get())

	writeHelp(&b, "pilot_handshake_responses_size", "Sum of pending handshake-response entries across all node inboxes.")
	writeType(&b, "pilot_handshake_responses_size", "gauge")
	writeMetric(&b, "pilot_handshake_responses_size", st.HandshakeRespSize.Get())

	writeHelp(&b, "pilot_list_nodes_cache_hits", "list_nodes admin cache: served from fresh cache.")
	writeType(&b, "pilot_list_nodes_cache_hits", "counter")
	writeMetric(&b, "pilot_list_nodes_cache_hits", st.ListNodesCacheHits.Get())

	writeHelp(&b, "pilot_list_nodes_cache_waits", "list_nodes admin cache: waited for in-flight rebuild.")
	writeType(&b, "pilot_list_nodes_cache_waits", "counter")
	writeMetric(&b, "pilot_list_nodes_cache_waits", st.ListNodesCacheWaits.Get())

	writeHelp(&b, "pilot_list_nodes_cache_rebuilds", "list_nodes admin cache: this goroutine rebuilt the cache.")
	writeType(&b, "pilot_list_nodes_cache_rebuilds", "counter")
	writeMetric(&b, "pilot_list_nodes_cache_rebuilds", st.ListNodesCacheRebuilds.Get())

	// --- Lifecycle counters ---
	writeHelp(&b, "pilot_registrations_total", "Total number of successful registrations.")
	writeType(&b, "pilot_registrations_total", "counter")
	writeMetric(&b, "pilot_registrations_total", st.Registrations.Get())

	writeHelp(&b, "pilot_deregistrations_total", "Total number of successful deregistrations.")
	writeType(&b, "pilot_deregistrations_total", "counter")
	writeMetric(&b, "pilot_deregistrations_total", st.Deregistrations.Get())

	writeHelp(&b, "pilot_trust_reports_total", "Total number of trust reports.")
	writeType(&b, "pilot_trust_reports_total", "counter")
	writeMetric(&b, "pilot_trust_reports_total", st.TrustReports.Get())

	writeHelp(&b, "pilot_trust_revocations_total", "Total number of trust revocations.")
	writeType(&b, "pilot_trust_revocations_total", "counter")
	writeMetric(&b, "pilot_trust_revocations_total", st.TrustRevocations.Get())

	writeHelp(&b, "pilot_handshake_requests_total", "Total number of handshake requests relayed.")
	writeType(&b, "pilot_handshake_requests_total", "counter")
	writeMetric(&b, "pilot_handshake_requests_total", st.HandshakeRequests.Get())

	// --- Reliability counters (alert targets) ---
	writeHelp(&b, "pilot_wal_full_total", "WAL appends dropped because WAL hit its size cap. Non-zero rate means the snapshot is failing AND the WAL has saturated — investigate disk health.")
	writeType(&b, "pilot_wal_full_total", "counter")
	writeMetric(&b, "pilot_wal_full_total", st.WalFull.Get())

	writeHelp(&b, "pilot_wal_errors_total", "WAL append failures other than size cap (disk I/O errors). Non-zero rate indicates a hardware or filesystem issue.")
	writeType(&b, "pilot_wal_errors_total", "counter")
	writeMetric(&b, "pilot_wal_errors_total", st.WalErrors.Get())

	writeHelp(&b, "pilot_save_failures_total", "flushSave() returned an error. With Phase 2.4 retry-on-error in place, sustained non-zero rate means snapshots are not being persisted — both WAL truncation AND replica push depend on flushSave succeeding.")
	writeType(&b, "pilot_save_failures_total", "counter")
	writeMetric(&b, "pilot_save_failures_total", st.SaveFailures.Get())

	writeHelp(&b, "pilot_recovered_panics_total", "Panics swallowed by recoverHandler since process start. Any non-zero value is a bug — alert on rate(.[5m]) > 0.")
	writeType(&b, "pilot_recovered_panics_total", "counter")
	panicCount := float64(0)
	if st.PanicCountFn != nil {
		panicCount = float64(st.PanicCountFn())
	}
	writeMetric(&b, "pilot_recovered_panics_total", panicCount)

	// --- Network gauges ---
	writeHelp(&b, "pilot_networks_total", "Total number of networks (excluding backbone).")
	writeType(&b, "pilot_networks_total", "gauge")
	writeMetric(&b, "pilot_networks_total", st.NetworksTotal.Get())

	writeHelp(&b, "pilot_networks_enterprise", "Number of enterprise networks.")
	writeType(&b, "pilot_networks_enterprise", "gauge")
	writeMetric(&b, "pilot_networks_enterprise", st.NetworksEnterprise.Get())

	writeHelp(&b, "pilot_invites_pending", "Number of pending network invites.")
	writeType(&b, "pilot_invites_pending", "gauge")
	writeMetric(&b, "pilot_invites_pending", st.InvitesPending.Get())

	// --- Enterprise counters ---
	writeHelp(&b, "pilot_audit_events_total", "Total number of audit events emitted.")
	writeType(&b, "pilot_audit_events_total", "counter")
	writeMetric(&b, "pilot_audit_events_total", st.AuditEventsTotal.Get())

	writeHelp(&b, "pilot_invites_sent_total", "Total number of network invites sent.")
	writeType(&b, "pilot_invites_sent_total", "counter")
	writeMetric(&b, "pilot_invites_sent_total", st.InvitesSent.Get())

	writeHelp(&b, "pilot_invites_accepted_total", "Total number of network invites accepted.")
	writeType(&b, "pilot_invites_accepted_total", "counter")
	writeMetric(&b, "pilot_invites_accepted_total", st.InvitesAccepted.Get())

	writeHelp(&b, "pilot_invites_rejected_total", "Total number of network invites rejected.")
	writeType(&b, "pilot_invites_rejected_total", "counter")
	writeMetric(&b, "pilot_invites_rejected_total", st.InvitesRejected.Get())

	writeHelp(&b, "pilot_rbac_operations_total", "Total number of RBAC operations by type.")
	writeType(&b, "pilot_rbac_operations_total", "counter")
	for _, lv := range st.RbacOps.Snapshot() {
		writeLabeledMetric(&b, "pilot_rbac_operations_total", "op", lv.Label, lv.Value)
	}

	writeHelp(&b, "pilot_policy_changes_total", "Total number of network policy changes.")
	writeType(&b, "pilot_policy_changes_total", "counter")
	writeMetric(&b, "pilot_policy_changes_total", st.PolicyChanges.Get())

	writeHelp(&b, "pilot_key_rotations_total", "Total number of key rotations.")
	writeType(&b, "pilot_key_rotations_total", "counter")
	writeMetric(&b, "pilot_key_rotations_total", st.KeyRotations.Get())

	writeHelp(&b, "pilot_provisions_total", "Total number of network provisions.")
	writeType(&b, "pilot_provisions_total", "counter")
	writeMetric(&b, "pilot_provisions_total", st.ProvisionsTotal.Get())

	writeHelp(&b, "pilot_audit_exports_total", "Total audit events exported to external systems.")
	writeType(&b, "pilot_audit_exports_total", "counter")
	writeMetric(&b, "pilot_audit_exports_total", st.AuditExportsTotal.Get())

	writeHelp(&b, "pilot_audit_export_errors_total", "Total audit export errors.")
	writeType(&b, "pilot_audit_export_errors_total", "counter")
	writeMetric(&b, "pilot_audit_export_errors_total", st.AuditExportErrors.Get())

	writeHelp(&b, "pilot_idp_verifications_total", "Total identity provider verifications.")
	writeType(&b, "pilot_idp_verifications_total", "counter")
	writeMetric(&b, "pilot_idp_verifications_total", st.IdpVerifications.Get())

	writeHelp(&b, "pilot_rbac_pre_assignments_total", "Total RBAC pre-assignment applications.")
	writeType(&b, "pilot_rbac_pre_assignments_total", "counter")
	writeMetric(&b, "pilot_rbac_pre_assignments_total", st.RbacPreAssignments.Get())

	// --- Enterprise status gauges ---
	writeHelp(&b, "pilot_idp_configured", "Whether an identity provider is configured (0 or 1).")
	writeType(&b, "pilot_idp_configured", "gauge")
	writeMetric(&b, "pilot_idp_configured", st.IdpConfigured.Get())

	writeHelp(&b, "pilot_webhook_configured", "Whether audit webhook is configured (0 or 1).")
	writeType(&b, "pilot_webhook_configured", "gauge")
	writeMetric(&b, "pilot_webhook_configured", st.WebhookConfigured.Get())

	writeHelp(&b, "pilot_audit_export_active", "Whether audit export is active (0 or 1).")
	writeType(&b, "pilot_audit_export_active", "gauge")
	writeMetric(&b, "pilot_audit_export_active", st.AuditExportActive.Get())

	writeHelp(&b, "pilot_directory_synced_networks", "Number of networks with directory sync configured.")
	writeType(&b, "pilot_directory_synced_networks", "gauge")
	writeMetric(&b, "pilot_directory_synced_networks", st.DirectorySynced.Get())

	// --- Per-network metrics (for Grafana dashboards) ---
	nets := st.GetNetworkMetrics()

	if len(nets) > 0 {
		writeHelp(&b, "pilot_network_members", "Number of members per network.")
		writeType(&b, "pilot_network_members", "gauge")
		for _, n := range nets {
			writeLabeledMetric(&b, "pilot_network_members", "network", n.Name, float64(n.Members))
		}

		writeHelp(&b, "pilot_network_admins", "Number of admins per network.")
		writeType(&b, "pilot_network_admins", "gauge")
		for _, n := range nets {
			writeLabeledMetric(&b, "pilot_network_admins", "network", n.Name, float64(n.Admins))
		}

		writeHelp(&b, "pilot_network_owners", "Number of owners per network.")
		writeType(&b, "pilot_network_owners", "gauge")
		for _, n := range nets {
			writeLabeledMetric(&b, "pilot_network_owners", "network", n.Name, float64(n.Owners))
		}

		writeHelp(&b, "pilot_network_enterprise", "Whether network has enterprise flag (0 or 1).")
		writeType(&b, "pilot_network_enterprise", "gauge")
		for _, n := range nets {
			v := float64(0)
			if n.Enterprise {
				v = 1
			}
			writeLabeledMetric(&b, "pilot_network_enterprise", "network", n.Name, v)
		}

		writeHelp(&b, "pilot_network_policy_set", "Whether network has a policy configured (0 or 1).")
		writeType(&b, "pilot_network_policy_set", "gauge")
		for _, n := range nets {
			v := float64(0)
			if n.PolicySet {
				v = 1
			}
			writeLabeledMetric(&b, "pilot_network_policy_set", "network", n.Name, v)
		}
	}

	n, err := io.WriteString(w, b.String())
	return int64(n), err
}

// --- text format helpers ---

func writeHelp(b *strings.Builder, name, help string) {
	fmt.Fprintf(b, "# HELP %s %s\n", name, help)
}

func writeType(b *strings.Builder, name, typ string) {
	fmt.Fprintf(b, "# TYPE %s %s\n", name, typ)
}

func writeMetric(b *strings.Builder, name string, val float64) {
	fmt.Fprintf(b, "%s %s\n", name, FormatFloat(val))
}

func writeLabeledMetric(b *strings.Builder, name, labelKey, labelVal string, val float64) {
	fmt.Fprintf(b, "%s{%s=%q} %s\n", name, labelKey, labelVal, FormatFloat(val))
}

func writeBucketMetric(b *strings.Builder, name, labelKey, labelVal string, le float64, count uint64) {
	fmt.Fprintf(b, "%s_bucket{%s=%q,le=%q} %d\n", name, labelKey, labelVal, FormatFloat(le), count)
}

func writeBucketInf(b *strings.Builder, name, labelKey, labelVal string, count uint64) {
	fmt.Fprintf(b, "%s_bucket{%s=%q,le=\"+Inf\"} %d\n", name, labelKey, labelVal, count)
}

// FormatFloat formats a float64 for Prometheus output.
// Integers are printed without decimal point for cleaner output.
func FormatFloat(v float64) string {
	if math.IsInf(v, 1) {
		return "+Inf"
	}
	if math.IsInf(v, -1) {
		return "-Inf"
	}
	if math.IsNaN(v) {
		return "NaN"
	}
	if v == float64(int64(v)) && !math.IsInf(v, 0) {
		return fmt.Sprintf("%d", int64(v))
	}
	return fmt.Sprintf("%g", v)
}
