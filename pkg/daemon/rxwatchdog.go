// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"log/slog"
	"math/rand"
	"os"
	"sync/atomic"
	"time"
)

// Inbound-path watchdog (L4).
//
// Failure mode this exists for (2026-07-13 incident): a daemon with days
// of uptime keeps transmitting — keepalives, beacon registrations, sends —
// while the inbound UDP path is silently dead (stale NAT / relay mapping
// the transport never re-establishes). Control plane stays healthy: the
// registry heartbeat is TCP and keeps succeeding, so trustRepublishLoop
// never re-registers, and every peer/service-agent contact fails with
// "cannot connect (data exchange port 1001)" until an operator restarts
// the daemon. Observed signature: 43.5 MB / 572K pkts sent vs 102 KB /
// 1443 pkts received over 2d19h, 0 direct connections.
//
// Detection: PktsRecv (delivered tunnel packets — peer keepalives bump it,
// so any live mutual peer feeds it) stalls for rxSilenceThreshold while
// PktsSent keeps growing. TunnelManager.LastRecvNano (any raw datagram,
// including beacon replies) is read alongside to tell a dead socket path
// from a dead session layer in the logs.
//
// Recovery escalates:
//  1. Soft (up to rxWatchdogSoftMax ticks): RegisterWithBeacon — the
//     MsgDiscover reply doubles as an active inbound probe — plus
//     reRegister with the registry. Heals transient beacon endpoint
//     staleness without touching the transport.
//  2. Hard: exit with rxWedgeExitCode. launchd (KeepAlive
//     SuccessfulExit=false) and systemd (Restart=always) respawn the
//     daemon with a fresh socket + registration — the remedy that is
//     known to clear the wedge. Guarded so it cannot flap:
//     only after PktsRecv has progressed at least once this process
//     (a never-worked config soft-recovers forever instead of
//     boot-looping), only when the registry was reachable within
//     rxWedgeRegistryFresh (otherwise the whole network is down and a
//     restart fixes nothing), and only after rxWedgeMinUptime.
const (
	// rxWatchdogTickInterval is how often the watchdog samples counters.
	rxWatchdogTickInterval = 30 * time.Second

	// rxSilenceThreshold is how long PktsRecv must stall (with tx active)
	// before the first soft recovery fires.
	rxSilenceThreshold = 3 * time.Minute

	// rxSilenceMinSentDelta gates on tx activity: at least this many
	// packets sent since the last rx progress. An idle daemon (no peers,
	// nothing to send) never triggers.
	rxSilenceMinSentDelta = 30

	// rxWatchdogSoftMax is how many consecutive soft recoveries run
	// before the watchdog considers the hard exit.
	rxWatchdogSoftMax = 3

	// rxWedgeMinUptime: never hard-exit a young process. Caps worst-case
	// restart churn if a wedge reappears immediately after respawn.
	rxWedgeMinUptime = 30 * time.Minute

	// rxWedgeRegistryFresh: hard exit requires a successful registry
	// interaction within this window — the wedge signature is data plane
	// dead + control plane alive.
	rxWedgeRegistryFresh = 5 * time.Minute

	// rxWedgeExitCode is the non-zero exit status for the hard escalation.
	// Non-zero so launchd KeepAlive/SuccessfulExit=false respawns; a
	// distinctive value so `pilotctl`/operators can attribute the restart.
	rxWedgeExitCode = 86
)

// rxWatchdogExit is swapped by tests to observe the hard escalation
// without killing the test process.
var rxWatchdogExit = func(code int) { os.Exit(code) }

// rxWatchdogState carries the loop's tick-to-tick memory. Kept as a
// struct (not loop locals) so tests can drive rxWatchdogTick directly,
// mirroring the beaconRefreshTick pattern.
type rxWatchdogState struct {
	lastProgress   time.Time // when recvSeen last advanced
	recvSeen       uint64    // PktsRecv at lastProgress
	sentAtProgress uint64    // PktsSent at lastProgress
	softAttempts   int       // consecutive soft recoveries this silence
}

// rxWatchdogAction names what a tick did — returned for tests and logs.
type rxWatchdogAction string

const (
	rxActionNone         rxWatchdogAction = ""
	rxActionProgress     rxWatchdogAction = "progress"
	rxActionSoftRecover  rxWatchdogAction = "soft-recover"
	rxActionExitWithheld rxWatchdogAction = "exit-withheld"
	rxActionExit         rxWatchdogAction = "exit"
)

func (d *Daemon) rxWatchdogLoop() {
	if d.config.DisableRxWatchdog {
		return
	}
	// Independent jitter so this loop does not align with the others.
	time.Sleep(time.Duration(rand.Int63n(int64(5 * time.Second))))

	st := &rxWatchdogState{
		lastProgress:   time.Now(),
		recvSeen:       atomic.LoadUint64(&d.tunnels.PktsRecv),
		sentAtProgress: atomic.LoadUint64(&d.tunnels.PktsSent),
	}
	ticker := time.NewTicker(rxWatchdogTickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.rxWatchdogTick(st, time.Now())
		}
	}
}

// rxWatchdogTick runs one watchdog iteration. Extracted for testability —
// production drives it from rxWatchdogLoop; tests drive it directly.
//
// L4 panic boundary (architecture-notes/03-INVARIANTS.md §8): the tick
// calls into beacon/registry re-registration; a panic drops this tick and
// the next one retries from clean state.
func (d *Daemon) rxWatchdogTick(st *rxWatchdogState, now time.Time) (action rxWatchdogAction) {
	defer recoverLayer("L4", "rxWatchdogTick", d.bus, nil)

	recv := atomic.LoadUint64(&d.tunnels.PktsRecv)
	sent := atomic.LoadUint64(&d.tunnels.PktsSent)

	if recv != st.recvSeen {
		if st.softAttempts > 0 {
			slog.Info("inbound path recovered",
				"silent_for", now.Sub(st.lastProgress).Truncate(time.Second).String(),
				"soft_attempts", st.softAttempts)
			d.publishEvent("tunnel.rx_recovered", map[string]any{
				"silent_for_seconds": int64(now.Sub(st.lastProgress).Seconds()),
				"soft_attempts":      st.softAttempts,
			})
		}
		st.recvSeen = recv
		st.sentAtProgress = sent
		st.lastProgress = now
		st.softAttempts = 0
		return rxActionProgress
	}

	silence := now.Sub(st.lastProgress)
	sentDelta := sent - st.sentAtProgress
	if silence < rxSilenceThreshold || sentDelta < rxSilenceMinSentDelta {
		return rxActionNone
	}

	// rawRxAge separates "socket path dead" (old) from "session layer
	// dead" (fresh — datagrams arrive but nothing decrypts/delivers).
	rawRxAge := time.Duration(0)
	if last := d.tunnels.LastRecvTime(); !last.IsZero() {
		rawRxAge = now.Sub(last)
	}

	if st.softAttempts < rxWatchdogSoftMax {
		st.softAttempts++
		slog.Warn("inbound path silent while transmitting — attempting soft recovery",
			"silent_for", silence.Truncate(time.Second).String(),
			"pkts_sent_during_silence", sentDelta,
			"raw_rx_age", rawRxAge.Truncate(time.Second).String(),
			"attempt", st.softAttempts,
			"max_soft_attempts", rxWatchdogSoftMax)
		d.publishEvent("tunnel.rx_silence", map[string]any{
			"silent_for_seconds":       int64(silence.Seconds()),
			"pkts_sent_during_silence": sentDelta,
			"raw_rx_age_seconds":       int64(rawRxAge.Seconds()),
			"attempt":                  st.softAttempts,
		})
		// The beacon's discover reply is itself an inbound datagram, so
		// this doubles as an active probe of the rx path.
		d.tunnels.RegisterWithBeacon()
		if d.regConn != nil {
			d.reRegister()
		}
		return rxActionSoftRecover
	}

	registryAge := time.Duration(-1)
	if ok := d.lastRegistryOKNano.Load(); ok > 0 {
		registryAge = now.Sub(time.Unix(0, ok))
	}
	uptime := now.Sub(d.startTime)
	switch {
	case st.recvSeen == 0:
		// Never received a tunnel packet this process — a restart would
		// reproduce the same state (boot loop). Keep soft-recovering.
		slog.Warn("inbound path silent and never progressed — withholding restart, will keep soft-recovering",
			"silent_for", silence.Truncate(time.Second).String())
	case registryAge < 0 || registryAge > rxWedgeRegistryFresh:
		// Registry unreachable too — likely the machine/network is
		// offline, not a wedged transport. Restarting fixes nothing.
		slog.Warn("inbound path silent but registry also unreachable — withholding restart",
			"silent_for", silence.Truncate(time.Second).String(),
			"registry_ok_age", registryAge.Truncate(time.Second).String())
	case uptime < rxWedgeMinUptime:
		slog.Warn("inbound path silent but process too young — withholding restart",
			"silent_for", silence.Truncate(time.Second).String(),
			"uptime", uptime.Truncate(time.Second).String())
	default:
		slog.Error("inbound path wedged — exiting for supervisor respawn",
			"silent_for", silence.Truncate(time.Second).String(),
			"pkts_sent_during_silence", sentDelta,
			"raw_rx_age", rawRxAge.Truncate(time.Second).String(),
			"soft_attempts", st.softAttempts,
			"exit_code", rxWedgeExitCode)
		d.publishEvent("tunnel.rx_wedged_exit", map[string]any{
			"silent_for_seconds":       int64(silence.Seconds()),
			"pkts_sent_during_silence": sentDelta,
			"soft_attempts":            st.softAttempts,
			"exit_code":                rxWedgeExitCode,
		})
		rxWatchdogExit(rxWedgeExitCode)
		return rxActionExit
	}
	// Withheld: reset the soft counter so recovery attempts continue on
	// later ticks instead of re-evaluating the exit every 30s.
	st.softAttempts = 0
	return rxActionExitWithheld
}
