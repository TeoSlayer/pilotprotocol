// SPDX-License-Identifier: AGPL-3.0-or-later

package dashboard_test

import (
	"io"
	"sync"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/registry/server/dashboard"
)

// minCallbacks returns a Callbacks with all required non-nil functions wired
// to safe no-ops / trivial stubs. Tests override individual fields as needed.
func minCallbacks(done <-chan struct{}, ready <-chan struct{}) dashboard.Callbacks {
	return dashboard.Callbacks{
		GetDashboardToken: func() string { return "" },
		GetAdminToken:     func() string { return "" },
		BuildStatsPayload: func(_ bool) map[string]interface{} { return map[string]interface{}{} },
		GetNodes:          func() []dashboard.NodeSnapshot { return nil },
		RequestCount:      func() int64 { return 0 },
		StartTime:         func() time.Time { return time.Now() },
		NodeCount:         func() int { return 0 },
		OnlineCount:       func(_ time.Time) int { return 0 },
		StaleThreshold:    func() time.Duration { return time.Minute },
		TriggerSnapshot:   func() error { return nil },
		UpdateGauges:      func() {},
		WriteMetrics:      func(_ io.Writer) {},
		ListenerAddr:      func() string { return "" },
		BeaconAddr:        func() string { return "" },
		ReadyCh:           func() <-chan struct{} { return ready },
		Done:              func() <-chan struct{} { return done },
		Save:              func() {},
	}
}

// TestMaintenanceBanner checks that SetMaintenanceBanner, MaintenanceBanner,
// and SetBannerPath round-trip correctly on the Handler.
func TestMaintenanceBanner(t *testing.T) {
	t.Parallel()
	done := make(chan struct{})
	defer close(done)
	ready := make(chan struct{})
	close(ready) // immediately ready

	h := dashboard.NewHandler(minCallbacks(done, ready))

	// Initial state: empty.
	if got := h.MaintenanceBanner(); got != "" {
		t.Fatalf("expected empty initial banner, got %q", got)
	}

	// Set a banner message.
	const msg = "Maintenance in progress"
	h.SetMaintenanceBanner(msg)
	if got := h.MaintenanceBanner(); got != msg {
		t.Fatalf("expected banner %q, got %q", msg, got)
	}

	// Clear the banner.
	h.SetMaintenanceBanner("")
	if got := h.MaintenanceBanner(); got != "" {
		t.Fatalf("expected empty banner after clear, got %q", got)
	}
}

// TestProbeStateRoundtrip verifies that SetProbeStates persists all fields and
// GetProbeStates returns a deep copy (not the same pointer).
func TestProbeStateRoundtrip(t *testing.T) {
	t.Parallel()
	done := make(chan struct{})
	defer close(done)
	ready := make(chan struct{})
	close(ready)

	h := dashboard.NewHandler(minCallbacks(done, ready))

	// Initially nil.
	if got := h.GetProbeStates(); got != nil {
		t.Fatalf("expected nil probe states initially, got %v", got)
	}

	now := time.Now().UnixMilli()
	input := map[string]*dashboard.ProbeState{
		"registry": {
			LastSuccess:       now,
			DowntimeIntervals: [][2]int64{{now - 5000, now - 1000}},
			CurrentDownStart:  0,
		},
		"beacon": {
			LastSuccess:      0,
			CurrentDownStart: now - 2000,
		},
	}
	h.SetProbeStates(input)

	got := h.GetProbeStates()
	if got == nil {
		t.Fatal("expected non-nil probe states after SetProbeStates")
	}
	if len(got) != len(input) {
		t.Fatalf("expected %d probe states, got %d", len(input), len(got))
	}

	// Verify registry probe.
	reg := got["registry"]
	if reg == nil {
		t.Fatal("missing 'registry' probe state")
	}
	if reg.LastSuccess != now {
		t.Fatalf("registry LastSuccess: want %d, got %d", now, reg.LastSuccess)
	}
	if len(reg.DowntimeIntervals) != 1 {
		t.Fatalf("registry DowntimeIntervals: want 1, got %d", len(reg.DowntimeIntervals))
	}

	// Verify beacon probe.
	beacon := got["beacon"]
	if beacon == nil {
		t.Fatal("missing 'beacon' probe state")
	}
	if beacon.CurrentDownStart == 0 {
		t.Fatal("beacon CurrentDownStart should be non-zero")
	}

	// GetProbeStates must return a deep copy — mutating the returned map must
	// not affect the next call.
	got["registry"].LastSuccess = 0
	got2 := h.GetProbeStates()
	if got2["registry"].LastSuccess != now {
		t.Fatal("GetProbeStates returned a shallow copy — mutation propagated")
	}
}

// TestSetHTTPProbeAddr verifies that SetHTTPProbeAddr is safe to call
// concurrently from multiple goroutines (races would be caught by -race).
func TestSetHTTPProbeAddr(t *testing.T) {
	t.Parallel()
	done := make(chan struct{})
	defer close(done)
	ready := make(chan struct{})
	close(ready)

	h := dashboard.NewHandler(minCallbacks(done, ready))

	var wg sync.WaitGroup
	addrs := []string{":8080", ":8081", ":8082", ":8083"}
	for _, addr := range addrs {
		wg.Add(1)
		go func(a string) {
			defer wg.Done()
			h.SetHTTPProbeAddr(a)
		}(addr)
	}
	wg.Wait()
	// No assertion needed — the test passes if there's no data race or panic.
}

// TestPulseSamplesOrdering verifies that GetPulseSamples returns samples
// in chronological order (oldest first) when the ring buffer has not wrapped.
func TestPulseSamplesOrdering(t *testing.T) {
	t.Parallel()
	done := make(chan struct{})
	defer close(done)
	ready := make(chan struct{})
	close(ready)

	counter := int64(0)
	cb := minCallbacks(done, ready)
	cb.RequestCount = func() int64 {
		counter++
		return counter
	}
	h := dashboard.NewHandler(cb)

	// Manually invoke PulseLoop in background; let it tick a few times.
	go h.PulseLoop()

	// Wait for at least 3 samples (3 seconds) with a generous timeout.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		samples := h.GetPulseSamples()
		if len(samples) >= 3 {
			// Verify monotonically increasing timestamps.
			for i := 1; i < len(samples); i++ {
				if samples[i].Ts < samples[i-1].Ts {
					t.Fatalf("samples not in chronological order at index %d: %d < %d",
						i, samples[i].Ts, samples[i-1].Ts)
				}
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("timed out waiting for 3 pulse samples")
}
