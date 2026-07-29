// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"sync/atomic"
	"testing"
	"time"
)

// TestSuspendUnlocksNeverProgressedGuard reproduces the field failure: a
// laptop resumes from sleep, inbound is dead, and the watchdog refuses to
// escalate forever because PktsRecv never advanced this process.
//
// On one laptop's daemon.log, 301 of 344 withheld restarts were this guard
// ("never progressed"); only 4 were the registry check. The operator had to
// restart the daemon by hand every time.
//
// The guard is correct for a host whose inbound never worked — restarting
// would boot-loop. It is wrong after a host suspend, where the transport
// worked before the gap and a restart is exactly what recovers it.
func TestSuspendUnlocksNeverProgressedGuard(t *testing.T) {
	// Must not be parallel: this stubs the global rxWatchdogExit, and the
	// escalation path below really would call os.Exit(86) otherwise.
	exitCode := swapExitForTest(t)
	now := time.Now()

	// No inbound has ever been delivered this process, but we are
	// transmitting hard — the post-resume signature.
	newWedged := func() (*Daemon, *rxWatchdogState) {
		d := newRxWatchdogTestDaemon(t)
		atomic.StoreUint64(&d.tunnels.PktsRecv, 0)
		atomic.StoreUint64(&d.tunnels.PktsSent, 5000)
		d.lastRegistryOKNano.Store(now.UnixNano())
		d.startTime = now.Add(-2 * rxWedgeMinUptime)

		st := &rxWatchdogState{
			lastProgress:   now.Add(-10 * rxSilenceThreshold),
			recvSeen:       0,
			sentAtProgress: 0,
		}
		return d, st
	}

	// Without a suspend the guard must still hold — a genuinely broken
	// host must not boot-loop.
	d, st := newWedged()
	var action rxWatchdogAction
	for i := 0; i < rxWatchdogSoftMax+1; i++ {
		action = d.rxWatchdogTick(st, now)
	}
	if action == rxActionExit {
		t.Fatal("exited despite never having received inbound and no suspend — " +
			"this is the boot-loop the guard exists to prevent")
	}

	// After a suspend, the same state must escalate to the restart.
	d, st = newWedged()
	st.suspendSeen = true
	for i := 0; i < rxWatchdogSoftMax+1; i++ {
		action = d.rxWatchdogTick(st, now)
	}
	if action != rxActionExit {
		t.Fatalf("post-suspend wedge did not escalate to restart: got %q — "+
			"this is the bug that forced a manual `pilotctl daemon restart` after every lid-close", action)
	}
	if *exitCode != rxWedgeExitCode {
		t.Fatalf("exit code = %d, want %d (the value launchd/systemd respawn on)", *exitCode, rxWedgeExitCode)
	}
}

// TestResumeReBaselinesAndMarksSuspend pins what the resume handler does:
// it re-baselines the wedge counters (the pre-suspend epoch is meaningless)
// and records that a suspend happened so the guard above unlocks.
func TestResumeReBaselinesAndMarksSuspend(t *testing.T) {
	d := newRxWatchdogTestDaemon(t)
	atomic.StoreUint64(&d.tunnels.PktsRecv, 4242)
	atomic.StoreUint64(&d.tunnels.PktsSent, 9999)

	now := time.Now()
	st := &rxWatchdogState{
		lastProgress:   now.Add(-8 * time.Hour), // slept overnight
		recvSeen:       10,
		sentAtProgress: 20,
		softAttempts:   2,
	}

	d.rxWatchdogResume(st, now, 8*time.Hour)

	if !st.suspendSeen {
		t.Error("suspendSeen not set — the never-progressed guard stays locked")
	}
	if st.softAttempts != 0 {
		t.Errorf("softAttempts = %d, want 0: the pre-suspend attempts describe a different epoch", st.softAttempts)
	}
	if !st.lastProgress.Equal(now) {
		t.Error("lastProgress not re-baselined — the first post-resume tick would read as an 8h rx silence")
	}
	if st.recvSeen != 4242 || st.sentAtProgress != 9999 {
		t.Errorf("counters not re-baselined: recvSeen=%d sentAtProgress=%d", st.recvSeen, st.sentAtProgress)
	}
}

// TestSuspendGapThresholdIgnoresOrdinaryJitter guards the detector against
// firing on a merely-late tick. Recovery is cheap but not free — it
// re-punches NAT and forces a fresh registry connection.
func TestSuspendGapThresholdIgnoresOrdinaryJitter(t *testing.T) {
	if suspendGapThreshold <= rxWatchdogTickInterval {
		t.Fatal("threshold must exceed the tick interval or every tick is a suspend")
	}
	// A tick arriving at 2x the interval is slow, not a suspend.
	if 2*rxWatchdogTickInterval >= suspendGapThreshold {
		t.Errorf("threshold %v too tight: a merely slow tick (2x interval) would be read as a host suspend",
			suspendGapThreshold)
	}
	// A lid-close is minutes at least; the threshold must be well under it.
	if suspendGapThreshold > 5*time.Minute {
		t.Errorf("threshold %v too loose: short suspends would go undetected", suspendGapThreshold)
	}
}
