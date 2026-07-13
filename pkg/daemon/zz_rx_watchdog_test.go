// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"sync/atomic"
	"testing"
	"time"
)

// newRxWatchdogTestDaemon builds the minimal Daemon the tick needs:
// a TunnelManager for the counters and a startTime old enough that
// rxWedgeMinUptime does not gate the escalation under test.
func newRxWatchdogTestDaemon(t *testing.T) *Daemon {
	t.Helper()
	return &Daemon{
		tunnels:   NewTunnelManager(),
		startTime: time.Now().Add(-2 * rxWedgeMinUptime),
		stopCh:    make(chan struct{}),
	}
}

// wedgeState returns a state that has already burned all soft attempts:
// silence beyond threshold, tx active, next tick evaluates the hard exit.
func wedgeState(d *Daemon, now time.Time) *rxWatchdogState {
	atomic.StoreUint64(&d.tunnels.PktsRecv, 100)
	atomic.StoreUint64(&d.tunnels.PktsSent, 100+2*rxSilenceMinSentDelta)
	return &rxWatchdogState{
		lastProgress:   now.Add(-2 * rxSilenceThreshold),
		recvSeen:       100,
		sentAtProgress: 100,
		softAttempts:   rxWatchdogSoftMax,
	}
}

// swapExitForTest stubs the global rxWatchdogExit. Tests that call it
// must NOT use t.Parallel(): a parallel sibling's Cleanup could restore
// the real os.Exit while this test still fires the escalation, killing
// the whole test binary.
func swapExitForTest(t *testing.T) *int {
	t.Helper()
	var exitCode int
	prev := rxWatchdogExit
	rxWatchdogExit = func(code int) { exitCode = code }
	t.Cleanup(func() { rxWatchdogExit = prev })
	return &exitCode
}

func TestRxWatchdogNoActionWhileHealthy(t *testing.T) {
	t.Parallel()
	d := newRxWatchdogTestDaemon(t)
	now := time.Now()

	// Progress on every tick: recv counter keeps moving.
	st := &rxWatchdogState{lastProgress: now.Add(-time.Hour), recvSeen: 5}
	atomic.StoreUint64(&d.tunnels.PktsRecv, 6)
	if got := d.rxWatchdogTick(st, now); got != rxActionProgress {
		t.Fatalf("action = %q, want %q", got, rxActionProgress)
	}
	if st.softAttempts != 0 || !st.lastProgress.Equal(now) {
		t.Fatalf("progress must reset state: %+v", st)
	}

	// Silent but idle (tx below rxSilenceMinSentDelta): no action.
	st = &rxWatchdogState{
		lastProgress:   now.Add(-2 * rxSilenceThreshold),
		recvSeen:       6,
		sentAtProgress: atomic.LoadUint64(&d.tunnels.PktsSent),
	}
	if got := d.rxWatchdogTick(st, now); got != rxActionNone {
		t.Fatalf("idle-silent action = %q, want %q", got, rxActionNone)
	}

	// Silent + tx active but under the silence threshold: no action.
	atomic.StoreUint64(&d.tunnels.PktsSent, 10*rxSilenceMinSentDelta)
	st = &rxWatchdogState{lastProgress: now.Add(-rxSilenceThreshold / 2), recvSeen: 6}
	if got := d.rxWatchdogTick(st, now); got != rxActionNone {
		t.Fatalf("short-silence action = %q, want %q", got, rxActionNone)
	}
}

func TestRxWatchdogSoftRecoveryThenReset(t *testing.T) {
	t.Parallel()
	d := newRxWatchdogTestDaemon(t)
	now := time.Now()

	atomic.StoreUint64(&d.tunnels.PktsRecv, 50)
	atomic.StoreUint64(&d.tunnels.PktsSent, 50+2*rxSilenceMinSentDelta)
	st := &rxWatchdogState{
		lastProgress:   now.Add(-2 * rxSilenceThreshold),
		recvSeen:       50,
		sentAtProgress: 50,
	}

	for i := 1; i <= rxWatchdogSoftMax; i++ {
		if got := d.rxWatchdogTick(st, now); got != rxActionSoftRecover {
			t.Fatalf("tick %d action = %q, want %q", i, got, rxActionSoftRecover)
		}
		if st.softAttempts != i {
			t.Fatalf("tick %d softAttempts = %d, want %d", i, st.softAttempts, i)
		}
	}

	// Inbound comes back: state resets and the recovery event path runs.
	atomic.StoreUint64(&d.tunnels.PktsRecv, 51)
	if got := d.rxWatchdogTick(st, now); got != rxActionProgress {
		t.Fatalf("post-recovery action = %q, want %q", got, rxActionProgress)
	}
	if st.softAttempts != 0 {
		t.Fatalf("softAttempts = %d after recovery, want 0", st.softAttempts)
	}
}

func TestRxWatchdogHardExitRequiresFreshRegistry(t *testing.T) {
	d := newRxWatchdogTestDaemon(t)
	exitCode := swapExitForTest(t)
	now := time.Now()

	// Registry never succeeded (lastRegistryOKNano zero): withhold.
	st := wedgeState(d, now)
	if got := d.rxWatchdogTick(st, now); got != rxActionExitWithheld {
		t.Fatalf("no-registry action = %q, want %q", got, rxActionExitWithheld)
	}
	if *exitCode != 0 {
		t.Fatalf("exit fired with unreachable registry (code %d)", *exitCode)
	}
	if st.softAttempts != 0 {
		t.Fatalf("withheld exit must reset softAttempts, got %d", st.softAttempts)
	}

	// Registry stale: still withhold.
	d.lastRegistryOKNano.Store(now.Add(-2 * rxWedgeRegistryFresh).UnixNano())
	st = wedgeState(d, now)
	if got := d.rxWatchdogTick(st, now); got != rxActionExitWithheld {
		t.Fatalf("stale-registry action = %q, want %q", got, rxActionExitWithheld)
	}

	// Registry fresh: the wedge signature — exit fires.
	d.lastRegistryOKNano.Store(now.UnixNano())
	st = wedgeState(d, now)
	if got := d.rxWatchdogTick(st, now); got != rxActionExit {
		t.Fatalf("fresh-registry action = %q, want %q", got, rxActionExit)
	}
	if *exitCode != rxWedgeExitCode {
		t.Fatalf("exit code = %d, want %d", *exitCode, rxWedgeExitCode)
	}
}

func TestRxWatchdogHardExitWithheldWhenNeverProgressedOrYoung(t *testing.T) {
	d := newRxWatchdogTestDaemon(t)
	exitCode := swapExitForTest(t)
	now := time.Now()
	d.lastRegistryOKNano.Store(now.UnixNano())

	// Never received a tunnel packet this process: withhold (boot-loop guard).
	st := wedgeState(d, now)
	st.recvSeen = 0
	atomic.StoreUint64(&d.tunnels.PktsRecv, 0)
	if got := d.rxWatchdogTick(st, now); got != rxActionExitWithheld {
		t.Fatalf("never-progressed action = %q, want %q", got, rxActionExitWithheld)
	}

	// Young process: withhold (restart-churn guard).
	d2 := newRxWatchdogTestDaemon(t)
	d2.startTime = now.Add(-rxWedgeMinUptime / 2)
	d2.lastRegistryOKNano.Store(now.UnixNano())
	st = wedgeState(d2, now)
	if got := d2.rxWatchdogTick(st, now); got != rxActionExitWithheld {
		t.Fatalf("young-process action = %q, want %q", got, rxActionExitWithheld)
	}

	if *exitCode != 0 {
		t.Fatalf("exit fired despite guards (code %d)", *exitCode)
	}
}
