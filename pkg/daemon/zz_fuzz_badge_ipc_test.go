// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/pilot-protocol/common/badgeverify"
)

// drainConn reads and discards everything written to the server side of an IPC
// pipe so a handler's writeReply never blocks on a full pipe. Returns a stop
// func bound to the fuzz lifetime.
func drainConn(tb testing.TB) (*ipcConn, func()) {
	tb.Helper()
	server, client := net.Pipe()
	ic := newIPCConn(server, 0, false)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			_ = client.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := client.Read(buf); err != nil {
				if err == io.EOF || err == io.ErrClosedPipe {
					return
				}
				// net.Pipe deadline timeout: loop again until closed.
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					select {
					case <-done:
						return
					default:
						continue
					}
				}
				return
			}
		}
	}()
	stop := func() {
		_ = ic.Close()
		_ = client.Close()
	}
	return ic, stop
}

// FuzzHandleSubmitBadgePayload throws arbitrary bytes at the submit_badge IPC
// payload parser. Contract: never panic on malformed JSON, and fail closed —
// with no registry connection the handler must always error out before any
// submission, so a fuzzed payload can never be silently accepted. The handler
// writes its reply over the pipe; drainConn keeps that from blocking.
func FuzzHandleSubmitBadgePayload(f *testing.F) {
	d := New(Config{})
	d.nodeID = 7
	// regConn deliberately nil: the handler must reject before any network I/O.
	s := NewIPCServer("", d)

	f.Add([]byte(``))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"badge":"","badge_sig":""}`))
	f.Add([]byte(`{"badge":"b","badge_sig":"s"}`))
	f.Add([]byte(`{"badge":123,"badge_sig":true}`))
	f.Add([]byte("{\"badge\":\"\\u0000\\uffff\",\"badge_sig\":\"\\ud800\"}"))

	f.Fuzz(func(t *testing.T, payload []byte) {
		ic, stop := drainConn(t)
		defer stop()
		// Must not panic. With regConn==nil the handler always fails closed;
		// it never reaches SubmitBadge, so there is nothing to over-trust.
		s.handleSubmitBadge(ic, 0, payload)
	})
}

// FuzzHandleEnrollRecoveryPayload throws arbitrary bytes at the enroll_recovery
// IPC payload parser, which additionally runs badgeverify.ParseEnrollment on
// attacker-influenced input. Contract: never panic; fail closed.
func FuzzHandleEnrollRecoveryPayload(f *testing.F) {
	d := New(Config{})
	d.nodeID = 7
	s := NewIPCServer("", d)

	f.Add([]byte(``))
	f.Add([]byte(`garbage`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"enrollment":"","enrollment_sig":""}`))
	f.Add([]byte(`{"enrollment":"garbage","enrollment_sig":"s"}`))
	f.Add([]byte(`{"enrollment":"pilotenroll:v1:7:github::1781827200:bdg-v1","enrollment_sig":"s"}`))
	f.Add([]byte(`{"enrollment":":::::::::::::","enrollment_sig":"x"}`))

	f.Fuzz(func(t *testing.T, payload []byte) {
		ic, stop := drainConn(t)
		defer stop()
		s.handleEnrollRecovery(ic, 0, payload)
	})
}

// FuzzParseBadgeCredentials fuzzes the three badgeverify parsers the daemon
// and pilotctl feed untrusted strings into (registry-returned badges, verifier
// sidecar enrollments / recovery authorizations). Pure no-panic contract; the
// parsers must reject malformed input with an error, never crash.
func FuzzParseBadgeCredentials(f *testing.F) {
	f.Add("")
	f.Add("pilotbadge:v1:7:github:1781827200:0:bdg-v1:")
	f.Add("pilotbadge:v1:notanumber:github:x:y:z:")
	f.Add(":::::::")
	f.Add("pilotbadge:v1:" + "9999999999999999999999999" + ":github:0:0:k:")

	f.Fuzz(func(t *testing.T, s string) {
		_, _ = badgeverify.Parse(s)
		_, _ = badgeverify.ParseEnrollment(s)
		_, _ = badgeverify.ParseRecovery(s)
	})
}
