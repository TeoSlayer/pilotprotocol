// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/pilot-protocol/dataexchange"
)

// TestSaveReplyToInbox asserts the sender-side reply-on-connection helper writes
// an inbox entry in the EXACT shape the daemon's dataexchange service uses, so a
// reply read off the connection is indistinguishable from a dial-back reply.
func TestSaveReplyToInbox(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	payload := []byte(`{"source":"list-agents","tiers":{}}`)
	path, err := saveReplyToInbox("0:0000.0003.9ECE", dataexchange.TypeText, payload)
	if err != nil {
		t.Fatalf("saveReplyToInbox: %v", err)
	}
	if want := filepath.Join(tmp, ".pilot", "inbox"); filepath.Dir(path) != want {
		t.Fatalf("wrote to %q, want under %q", path, want)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	var msg map[string]interface{}
	if err := json.Unmarshal(b, &msg); err != nil {
		t.Fatalf("inbox entry is not valid JSON: %v", err)
	}
	for _, k := range []string{"type", "from", "data", "bytes", "received_at"} {
		if _, ok := msg[k]; !ok {
			t.Errorf("inbox entry missing %q (daemon-format mismatch)", k)
		}
	}
	if msg["type"] != "TEXT" {
		t.Errorf("type = %v, want TEXT", msg["type"])
	}
	if msg["from"] != "0:0000.0003.9ECE" {
		t.Errorf("from = %v", msg["from"])
	}
	if msg["data"] != string(payload) {
		t.Errorf("data = %v", msg["data"])
	}
	if int(msg["bytes"].(float64)) != len(payload) {
		t.Errorf("bytes = %v, want %d", msg["bytes"], len(payload))
	}
}

// TestSaveReplyToInbox_UniqueFilenames: two replies in quick succession must not
// collide on filename.
func TestSaveReplyToInbox_UniqueFilenames(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	p1, err1 := saveReplyToInbox("0:0000.0000.0001", dataexchange.TypeText, []byte("a"))
	p2, err2 := saveReplyToInbox("0:0000.0000.0001", dataexchange.TypeText, []byte("b"))
	if err1 != nil || err2 != nil {
		t.Fatalf("errs: %v %v", err1, err2)
	}
	if p1 == p2 {
		t.Fatalf("filenames collided: %q", p1)
	}
}

// frameTypesSent decodes every frame the fake daemon captured and returns the
// set of dataexchange frame types observed (the captured bytes are whole frames:
// [type(4)][len(4)][payload]).
func frameTypesSent(sd *streamDaemon) map[uint32]bool {
	types := map[uint32]bool{}
	sd.capturedMu.Lock()
	defer sd.capturedMu.Unlock()
	for _, frames := range sd.captured {
		for _, f := range frames {
			if len(f) >= 8 {
				types[binary.BigEndian.Uint32(f[0:4])] = true
			}
		}
	}
	return types
}

// TestCmdSendMessage_ReplyOnConn_SendsAutoAnswerFrame is the sender-side
// integration test: --reply-on-conn must put a TypeAutoAnswer frame on the wire
// (the opt-in that an --auto-answer receiver keys on), where a plain send puts a
// TypeText frame. This is what gates the new loop to opted-in requests.
func TestCmdSendMessage_ReplyOnConn_SendsAutoAnswerFrame(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	captureStdout(t, func() {
		withJSON(func() {
			cmdSendMessage([]string{"0:0000.0000.002A", "--data", `/data {}`, "--reply-on-conn"})
		})
	})
	if types := frameTypesSent(sd); !types[dataexchange.TypeAutoAnswer] {
		t.Fatalf("--reply-on-conn did not send a TypeAutoAnswer frame; saw types %v", types)
	}
}

// TestReplyOnConnOutcome covers the decision at the heart of the "always safe"
// guarantee: classify the receiver's ack into read / delivered / resend.
func TestReplyOnConnOutcome(t *testing.T) {
	cases := []struct {
		name, ack, want string
	}{
		{"auto-answer reply", "ACK+REPLY AUTOANSWER 29 bytes", replyOnConnRead},
		{"updated saved for dial-back", "ACK AUTOANSWER 29 bytes", replyOnConnDelivered},
		{"old/stock unknown type", "ACK UNKNOWN(6) 29 bytes", replyOnConnResend},
		{"plain text ack", "ACK TEXT 29 bytes", replyOnConnResend},
		{"empty", "", replyOnConnResend},
	}
	for _, c := range cases {
		if got := replyOnConnOutcome(c.ack); got != c.want {
			t.Errorf("%s: replyOnConnOutcome(%q) = %q, want %q", c.name, c.ack, got, c.want)
		}
	}
}

// TestCmdSendMessage_ReplyOnConn_FallsBackToText is the always-safe integration
// test: the fake daemon echoes the request as its "ack", so it never returns
// ACK+REPLY or names the AUTOANSWER type — i.e. it stands in for an OLD/stock
// receiver. --reply-on-conn must then ALSO put a plain TypeText frame on the
// wire (the dial-back fallback), so the request is delivered no matter what.
func TestCmdSendMessage_ReplyOnConn_FallsBackToText(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	captureStdout(t, func() {
		withJSON(func() {
			cmdSendMessage([]string{"0:0000.0000.002A", "--data", `/data {}`, "--reply-on-conn"})
		})
	})
	types := frameTypesSent(sd)
	if !types[dataexchange.TypeAutoAnswer] {
		t.Fatalf("expected the initial TypeAutoAnswer frame; saw %v", types)
	}
	if !types[dataexchange.TypeText] {
		t.Fatalf("--reply-on-conn against an un-understanding receiver did NOT fall back to a TypeText send; saw %v", types)
	}
}

// TestCmdSendMessage_PlainSendsTextFrame is the control: no flag → TypeText, and
// crucially NOT TypeAutoAnswer (current senders must never opt in by accident).
func TestCmdSendMessage_PlainSendsTextFrame(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	captureStdout(t, func() {
		withJSON(func() {
			cmdSendMessage([]string{"0:0000.0000.002A", "--data", "hello"})
		})
	})
	types := frameTypesSent(sd)
	if !types[dataexchange.TypeText] {
		t.Fatalf("plain send did not put a TypeText frame on the wire; saw %v", types)
	}
	if types[dataexchange.TypeAutoAnswer] {
		t.Fatalf("plain send put a TypeAutoAnswer frame on the wire — current senders must not opt in")
	}
}
