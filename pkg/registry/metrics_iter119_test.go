// SPDX-License-Identifier: AGPL-3.0-or-later

package registry

import (
	"bytes"
	"math"
	"strings"
	"sync"
	"testing"
)

// --- counter / gauge ------------------------------------------------------

func TestCounterIncGet(t *testing.T) {
	var c counter
	if got := c.Get(); got != 0 {
		t.Fatalf("initial: %v", got)
	}
	for i := 0; i < 5; i++ {
		c.Inc()
	}
	if got := c.Get(); got != 5 {
		t.Fatalf("after 5 Inc: %v", got)
	}
}

func TestCounterIncConcurrent(t *testing.T) {
	var c counter
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				c.Inc()
			}
		}()
	}
	wg.Wait()
	if got := c.Get(); got != 1000 {
		t.Fatalf("concurrent: got %v, want 1000", got)
	}
}

func TestGaugeSetGet(t *testing.T) {
	var g gauge
	g.Set(3.14)
	if got := g.Get(); got != 3.14 {
		t.Fatalf("got %v", got)
	}
	g.Set(-1)
	if got := g.Get(); got != -1 {
		t.Fatalf("neg: %v", got)
	}
}

// --- histogram ------------------------------------------------------------

func TestNewHistogramSortsBuckets(t *testing.T) {
	h := newHistogram([]float64{0.5, 0.1, 1.0, 0.25})
	if len(h.counts) != 4 {
		t.Fatalf("counts len: %d", len(h.counts))
	}
	want := []float64{0.1, 0.25, 0.5, 1.0}
	for i, b := range h.buckets {
		if b != want[i] {
			t.Fatalf("buckets[%d]: %v want %v", i, b, want[i])
		}
	}
}

func TestHistogramObserveCountsAndSum(t *testing.T) {
	h := newHistogram([]float64{0.1, 1.0, 10.0})
	// 0.05 → buckets 0,1,2; 0.5 → buckets 1,2; 5 → bucket 2; 100 → none
	for _, v := range []float64{0.05, 0.5, 5, 100} {
		h.Observe(v)
	}
	buckets, counts, sum, count := h.snapshot()
	if len(buckets) != 3 {
		t.Fatalf("buckets: %v", buckets)
	}
	if counts[0] != 1 || counts[1] != 2 || counts[2] != 3 {
		t.Fatalf("counts: %v", counts)
	}
	if sum != 105.55 {
		t.Fatalf("sum: %v", sum)
	}
	if count != 4 {
		t.Fatalf("count: %v", count)
	}
}

func TestHistogramSnapshotIsACopy(t *testing.T) {
	h := newHistogram([]float64{0.1, 1.0})
	h.Observe(0.5)
	buckets, counts, _, _ := h.snapshot()
	buckets[0] = 999
	counts[0] = 999
	// Original state unaffected.
	if h.buckets[0] != 0.1 {
		t.Fatalf("snapshot() should return a copy of buckets; mutation leaked: %v", h.buckets[0])
	}
	if h.counts[0] != 0 {
		t.Fatalf("snapshot() should return a copy of counts; mutation leaked: %v", h.counts[0])
	}
}

// --- counterVec -----------------------------------------------------------

func TestCounterVecWithLabelReturnsSameInstance(t *testing.T) {
	cv := newCounterVec()
	c1 := cv.WithLabel("register")
	c1.Inc()
	c2 := cv.WithLabel("register")
	if c1 != c2 {
		t.Fatalf("WithLabel should memoize")
	}
	if c2.Get() != 1 {
		t.Fatalf("second retrieval should see prior Inc: %v", c2.Get())
	}
}

func TestCounterVecSnapshotSorted(t *testing.T) {
	cv := newCounterVec()
	cv.WithLabel("zebra").Inc()
	cv.WithLabel("apple").Inc()
	cv.WithLabel("apple").Inc()
	cv.WithLabel("mango").Inc()

	snap := cv.snapshot()
	if len(snap) != 3 {
		t.Fatalf("snap len: %d", len(snap))
	}
	want := []struct {
		label string
		value float64
	}{{"apple", 2}, {"mango", 1}, {"zebra", 1}}
	for i, w := range want {
		if snap[i].label != w.label || snap[i].value != w.value {
			t.Fatalf("snap[%d]: %+v want %+v", i, snap[i], w)
		}
	}
}

func TestCounterVecRaceFree(t *testing.T) {
	cv := newCounterVec()
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				cv.WithLabel("concurrent").Inc()
			}
		}()
	}
	wg.Wait()
	if got := cv.WithLabel("concurrent").Get(); got != 500 {
		t.Fatalf("race test: got %v, want 500", got)
	}
}

// --- histogramVec ---------------------------------------------------------

func TestHistogramVecWithLabelMemoizes(t *testing.T) {
	hv := newHistogramVec([]float64{0.1, 1.0})
	h1 := hv.WithLabel("register")
	h1.Observe(0.05)
	h2 := hv.WithLabel("register")
	if h1 != h2 {
		t.Fatalf("WithLabel should memoize")
	}
	_, _, _, count := h2.snapshot()
	if count != 1 {
		t.Fatalf("observe should survive: %v", count)
	}
}

func TestHistogramVecSnapshotSorted(t *testing.T) {
	hv := newHistogramVec([]float64{0.1, 1.0})
	hv.WithLabel("zebra").Observe(0.05)
	hv.WithLabel("apple").Observe(0.5)

	snap := hv.snapshot()
	if len(snap) != 2 {
		t.Fatalf("snap len: %d", len(snap))
	}
	if snap[0].label != "apple" || snap[1].label != "zebra" {
		t.Fatalf("snap order: %+v", snap)
	}
}

// --- newRegistryMetrics + WriteTo ----------------------------------------

func TestNewRegistryMetricsInitializesVecs(t *testing.T) {
	m := newRegistryMetrics()
	if m.requestsTotal == nil || m.errorsTotal == nil || m.rbacOps == nil {
		t.Fatalf("counter vecs should be initialized")
	}
	if m.requestDuration == nil {
		t.Fatalf("requestDuration vec should be initialized")
	}
	// Buckets pinned to defaults.
	if len(m.requestDuration.buckets) != len(defaultDurationBuckets) {
		t.Fatalf("default buckets not wired")
	}
}

func TestWriteToRendersPrometheusText(t *testing.T) {
	m := newRegistryMetrics()
	// Seed a few metrics so WriteTo exercises every branch.
	m.requestsTotal.WithLabel("register").Inc()
	m.errorsTotal.WithLabel("resolve").Inc()
	m.requestDuration.WithLabel("register").Observe(0.002)
	m.registrations.Inc()
	m.nodesOnline.Set(3)
	m.nodesTotal.Set(4)
	m.networkMetrics = []networkMetricSnapshot{
		{Name: "net-a", Members: 10, Admins: 2, Owners: 1, Enterprise: true, PolicySet: false},
		{Name: "net-b", Members: 5, Admins: 0, Owners: 1, Enterprise: false, PolicySet: true},
	}

	var buf bytes.Buffer
	n, err := m.WriteTo(&buf)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n <= 0 {
		t.Fatalf("n should be > 0, got %d", n)
	}
	out := buf.String()

	mustContain := []string{
		"# HELP pilot_requests_total",
		"# TYPE pilot_requests_total counter",
		`pilot_requests_total{type="register"} 1`,
		"# TYPE pilot_errors_total counter",
		`pilot_errors_total{type="resolve"} 1`,
		"# TYPE pilot_request_duration_seconds histogram",
		`pilot_request_duration_seconds_bucket{type="register",le="+Inf"} 1`,
		"pilot_nodes_online 3",
		"pilot_nodes_total 4",
		"pilot_registrations_total 1",
		// per-network metrics (len(nets)>0 branch)
		`pilot_network_members{network="net-a"} 10`,
		`pilot_network_enterprise{network="net-a"} 1`,
		`pilot_network_enterprise{network="net-b"} 0`,
		`pilot_network_policy_set{network="net-b"} 1`,
	}
	for _, s := range mustContain {
		if !strings.Contains(out, s) {
			t.Fatalf("output missing %q\n--- output ---\n%s", s, out)
		}
	}
}

func TestWriteToSkipsPerNetworkBlockWhenEmpty(t *testing.T) {
	m := newRegistryMetrics()
	var buf bytes.Buffer
	if _, err := m.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "pilot_network_members") {
		t.Fatalf("per-network block should be absent when networkMetrics is empty")
	}
	// But global metrics should still be there.
	if !strings.Contains(out, "pilot_nodes_total") {
		t.Fatalf("expected pilot_nodes_total")
	}
}

// --- text helpers ---------------------------------------------------------

func TestWriteHelpAndTypeAndMetric(t *testing.T) {
	var b strings.Builder
	writeHelp(&b, "foo", "the foo")
	writeType(&b, "foo", "counter")
	writeMetric(&b, "foo", 42)
	writeLabeledMetric(&b, "foo", "kind", "bar", 7)
	writeBucketMetric(&b, "dur", "op", "x", 0.5, 3)
	writeBucketInf(&b, "dur", "op", "x", 9)
	out := b.String()

	wants := []string{
		"# HELP foo the foo\n",
		"# TYPE foo counter\n",
		"foo 42\n",
		`foo{kind="bar"} 7` + "\n",
		`dur_bucket{op="x",le="0.5"} 3` + "\n",
		`dur_bucket{op="x",le="+Inf"} 9` + "\n",
	}
	for _, s := range wants {
		if !strings.Contains(out, s) {
			t.Fatalf("missing line: %q\n%s", s, out)
		}
	}
}

// --- formatFloat ---------------------------------------------------------

func TestFormatFloatSpecialAndIntegerAndFloat(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{0, "0"},
		{1, "1"},
		{-7, "-7"},
		{1.5, "1.5"},
		{0.0001, "0.0001"},
		{math.Inf(1), "+Inf"},
		{math.Inf(-1), "-Inf"},
		{math.NaN(), "NaN"},
	}
	for _, tc := range cases {
		got := formatFloat(tc.in)
		if got != tc.want {
			t.Fatalf("formatFloat(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
