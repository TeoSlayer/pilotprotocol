package registry

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// --- Lightweight Prometheus text-format metrics (zero external deps) ---

// counter is a monotonically increasing atomic counter.
type counter struct {
	val atomic.Int64
}

func (c *counter) Inc()         { c.val.Add(1) }
func (c *counter) Get() float64 { return float64(c.val.Load()) }

// gauge is a numeric value that can go up and down.
type gauge struct {
	mu  sync.Mutex
	val float64
}

func (g *gauge) Set(v float64) {
	g.mu.Lock()
	g.val = v
	g.mu.Unlock()
}

func (g *gauge) Get() float64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.val
}

// histogram tracks the distribution of observed values in predefined buckets.
type histogram struct {
	mu      sync.Mutex
	buckets []float64 // upper bounds (sorted)
	counts  []uint64  // counts[i] = observations <= buckets[i]
	sum     float64
	count   uint64
}

func newHistogram(buckets []float64) *histogram {
	sorted := make([]float64, len(buckets))
	copy(sorted, buckets)
	sort.Float64s(sorted)
	return &histogram{
		buckets: sorted,
		counts:  make([]uint64, len(sorted)),
	}
}

func (h *histogram) Observe(v float64) {
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

// snapshot returns a copy of the histogram state for safe iteration.
func (h *histogram) snapshot() (buckets []float64, counts []uint64, sum float64, count uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	buckets = make([]float64, len(h.buckets))
	counts = make([]uint64, len(h.counts))
	copy(buckets, h.buckets)
	copy(counts, h.counts)
	return buckets, counts, h.sum, h.count
}

// counterVec is a set of counters keyed by a single label value.
type counterVec struct {
	mu       sync.RWMutex
	counters map[string]*counter
}

func newCounterVec() *counterVec {
	return &counterVec{counters: make(map[string]*counter)}
}

func (cv *counterVec) WithLabel(val string) *counter {
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
	c = &counter{}
	cv.counters[val] = c
	return c
}

// snapshot returns a sorted copy of label→value pairs.
func (cv *counterVec) snapshot() []labelValue {
	cv.mu.RLock()
	defer cv.mu.RUnlock()
	out := make([]labelValue, 0, len(cv.counters))
	for k, c := range cv.counters {
		out = append(out, labelValue{label: k, value: c.Get()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].label < out[j].label })
	return out
}

// histogramVec is a set of histograms keyed by a single label value.
type histogramVec struct {
	mu         sync.RWMutex
	histograms map[string]*histogram
	buckets    []float64
}

func newHistogramVec(buckets []float64) *histogramVec {
	return &histogramVec{
		histograms: make(map[string]*histogram),
		buckets:    buckets,
	}
}

func (hv *histogramVec) WithLabel(val string) *histogram {
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
	h = newHistogram(hv.buckets)
	hv.histograms[val] = h
	return h
}

// snapshot returns sorted label keys and their histogram snapshots.
func (hv *histogramVec) snapshot() []labelHistogram {
	hv.mu.RLock()
	defer hv.mu.RUnlock()
	out := make([]labelHistogram, 0, len(hv.histograms))
	for k, h := range hv.histograms {
		buckets, counts, sum, count := h.snapshot()
		out = append(out, labelHistogram{label: k, buckets: buckets, counts: counts, sum: sum, count: count})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].label < out[j].label })
	return out
}

type labelValue struct {
	label string
	value float64
}

type labelHistogram struct {
	label   string
	buckets []float64
	counts  []uint64
	sum     float64
	count   uint64
}

// --- registryMetrics ---

// Default histogram buckets for request duration (seconds).
var defaultDurationBuckets = []float64{
	0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0,
}

type registryMetrics struct {
	// Request metrics (labeled by message type)
	requestsTotal   *counterVec   // pilot_requests_total{type="..."}
	requestDuration *histogramVec // pilot_request_duration_seconds{type="..."}
	errorsTotal     *counterVec   // pilot_errors_total{type="..."}

	// Gauge metrics (updated on each scrape)
	nodesOnline   gauge // pilot_nodes_online
	nodesTotal    gauge // pilot_nodes_total
	trustLinks    gauge // pilot_trust_links
	taskExecutors gauge // pilot_task_executors
	uptimeSeconds gauge // pilot_uptime_seconds

	// Lifecycle counters
	registrations     counter // pilot_registrations_total
	deregistrations   counter // pilot_deregistrations_total
	trustReports      counter // pilot_trust_reports_total
	trustRevocations  counter // pilot_trust_revocations_total
	handshakeRequests counter // pilot_handshake_requests_total
}

func newRegistryMetrics() *registryMetrics {
	return &registryMetrics{
		requestsTotal:   newCounterVec(),
		requestDuration: newHistogramVec(defaultDurationBuckets),
		errorsTotal:     newCounterVec(),
	}
}

// updateGauges reads current server state and sets gauge values.
func (m *registryMetrics) updateGauges(s *Server) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	onlineThreshold := now.Add(-staleNodeThreshold)

	total := len(s.nodes)
	online := 0
	taskExec := 0
	for _, node := range s.nodes {
		if node.LastSeen.After(onlineThreshold) {
			online++
		}
		if node.TaskExec {
			taskExec++
		}
	}

	m.nodesTotal.Set(float64(total))
	m.nodesOnline.Set(float64(online))
	m.trustLinks.Set(float64(len(s.trustPairs)))
	m.taskExecutors.Set(float64(taskExec))
	m.uptimeSeconds.Set(now.Sub(s.startTime).Seconds())
}

// WriteTo writes all metrics in Prometheus text exposition format.
func (m *registryMetrics) WriteTo(w io.Writer) (int64, error) {
	var b strings.Builder

	// --- Request counters (labeled) ---
	writeHelp(&b, "pilot_requests_total", "Total number of registry requests by type.")
	writeType(&b, "pilot_requests_total", "counter")
	for _, lv := range m.requestsTotal.snapshot() {
		writeLabeledMetric(&b, "pilot_requests_total", "type", lv.label, lv.value)
	}

	// --- Error counters (labeled) ---
	writeHelp(&b, "pilot_errors_total", "Total number of registry errors by type.")
	writeType(&b, "pilot_errors_total", "counter")
	for _, lv := range m.errorsTotal.snapshot() {
		writeLabeledMetric(&b, "pilot_errors_total", "type", lv.label, lv.value)
	}

	// --- Request duration histograms (labeled) ---
	writeHelp(&b, "pilot_request_duration_seconds", "Histogram of request durations in seconds.")
	writeType(&b, "pilot_request_duration_seconds", "histogram")
	for _, lh := range m.requestDuration.snapshot() {
		cumulative := uint64(0)
		for i, bound := range lh.buckets {
			cumulative += lh.counts[i]
			writeBucketMetric(&b, "pilot_request_duration_seconds", "type", lh.label, bound, cumulative)
		}
		writeBucketInf(&b, "pilot_request_duration_seconds", "type", lh.label, lh.count)
		writeLabeledMetric(&b, "pilot_request_duration_seconds_sum", "type", lh.label, lh.sum)
		writeLabeledMetric(&b, "pilot_request_duration_seconds_count", "type", lh.label, float64(lh.count))
	}

	// --- Gauges ---
	writeHelp(&b, "pilot_nodes_online", "Number of nodes currently online.")
	writeType(&b, "pilot_nodes_online", "gauge")
	writeMetric(&b, "pilot_nodes_online", m.nodesOnline.Get())

	writeHelp(&b, "pilot_nodes_total", "Total number of registered nodes.")
	writeType(&b, "pilot_nodes_total", "gauge")
	writeMetric(&b, "pilot_nodes_total", m.nodesTotal.Get())

	writeHelp(&b, "pilot_trust_links", "Number of active trust pairs.")
	writeType(&b, "pilot_trust_links", "gauge")
	writeMetric(&b, "pilot_trust_links", m.trustLinks.Get())

	writeHelp(&b, "pilot_task_executors", "Number of nodes advertising task execution.")
	writeType(&b, "pilot_task_executors", "gauge")
	writeMetric(&b, "pilot_task_executors", m.taskExecutors.Get())

	writeHelp(&b, "pilot_uptime_seconds", "Registry server uptime in seconds.")
	writeType(&b, "pilot_uptime_seconds", "gauge")
	writeMetric(&b, "pilot_uptime_seconds", m.uptimeSeconds.Get())

	// --- Lifecycle counters ---
	writeHelp(&b, "pilot_registrations_total", "Total number of successful registrations.")
	writeType(&b, "pilot_registrations_total", "counter")
	writeMetric(&b, "pilot_registrations_total", m.registrations.Get())

	writeHelp(&b, "pilot_deregistrations_total", "Total number of successful deregistrations.")
	writeType(&b, "pilot_deregistrations_total", "counter")
	writeMetric(&b, "pilot_deregistrations_total", m.deregistrations.Get())

	writeHelp(&b, "pilot_trust_reports_total", "Total number of trust reports.")
	writeType(&b, "pilot_trust_reports_total", "counter")
	writeMetric(&b, "pilot_trust_reports_total", m.trustReports.Get())

	writeHelp(&b, "pilot_trust_revocations_total", "Total number of trust revocations.")
	writeType(&b, "pilot_trust_revocations_total", "counter")
	writeMetric(&b, "pilot_trust_revocations_total", m.trustRevocations.Get())

	writeHelp(&b, "pilot_handshake_requests_total", "Total number of handshake requests relayed.")
	writeType(&b, "pilot_handshake_requests_total", "counter")
	writeMetric(&b, "pilot_handshake_requests_total", m.handshakeRequests.Get())

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
	fmt.Fprintf(b, "%s %s\n", name, formatFloat(val))
}

func writeLabeledMetric(b *strings.Builder, name, labelKey, labelVal string, val float64) {
	fmt.Fprintf(b, "%s{%s=%q} %s\n", name, labelKey, labelVal, formatFloat(val))
}

func writeBucketMetric(b *strings.Builder, name, labelKey, labelVal string, le float64, count uint64) {
	fmt.Fprintf(b, "%s_bucket{%s=%q,le=%q} %d\n", name, labelKey, labelVal, formatFloat(le), count)
}

func writeBucketInf(b *strings.Builder, name, labelKey, labelVal string, count uint64) {
	fmt.Fprintf(b, "%s_bucket{%s=%q,le=\"+Inf\"} %d\n", name, labelKey, labelVal, count)
}

// formatFloat formats a float64 for Prometheus output.
// Integers are printed without decimal point for cleaner output.
func formatFloat(v float64) string {
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
