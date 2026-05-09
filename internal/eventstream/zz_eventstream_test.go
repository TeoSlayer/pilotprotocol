// SPDX-License-Identifier: AGPL-3.0-or-later

package eventstream_test

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/internal/eventstream"
)

func TestWriteReadRoundTrip(t *testing.T) {
	t.Parallel()
	cases := []struct {
		topic   string
		payload []byte
	}{
		{"ping", []byte("pong")},
		{"empty payload", nil},
		{"binary", []byte{0x00, 0xFF, 0x7F}},
		{strings.Repeat("t", 1024), []byte("max topic")},
	}
	for _, tc := range cases {
		var buf bytes.Buffer
		orig := &eventstream.Event{Topic: tc.topic, Payload: tc.payload}
		if err := eventstream.WriteEvent(&buf, orig); err != nil {
			t.Fatalf("WriteEvent: %v", err)
		}
		got, err := eventstream.ReadEvent(&buf)
		if err != nil {
			t.Fatalf("ReadEvent: %v", err)
		}
		if got.Topic != tc.topic {
			t.Errorf("topic: got %q want %q", got.Topic, tc.topic)
		}
		if !bytes.Equal(got.Payload, tc.payload) {
			t.Errorf("payload mismatch")
		}
	}
}

func TestReadEventTopicTooLong(t *testing.T) {
	t.Parallel()
	// Craft a frame with topic length = 1025.
	var buf bytes.Buffer
	buf.Write([]byte{0x04, 0x01}) // topic len = 1025
	_, err := eventstream.ReadEvent(&buf)
	if err == nil || !strings.Contains(err.Error(), "too long") {
		t.Errorf("expected topic too long error, got %v", err)
	}
}

func TestReadEventPayloadTooLarge(t *testing.T) {
	t.Parallel()
	// Write a valid topic then a payload length that exceeds 16MiB.
	var buf bytes.Buffer
	buf.Write([]byte{0x00, 0x01, 'x'})        // topic len=1, topic="x"
	buf.Write([]byte{0x01, 0x00, 0x00, 0x01}) // payload len = 16MiB+1
	_, err := eventstream.ReadEvent(&buf)
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Errorf("expected payload too large error, got %v", err)
	}
}

func TestReadEventTruncated(t *testing.T) {
	t.Parallel()
	_, err := eventstream.ReadEvent(strings.NewReader(""))
	if err != io.EOF && err == nil {
		t.Error("expected error on empty reader")
	}
}

func TestWriteReadMultiple(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	events := []*eventstream.Event{
		{Topic: "a", Payload: []byte("1")},
		{Topic: "b", Payload: []byte("22")},
		{Topic: "c", Payload: []byte("333")},
	}
	for _, e := range events {
		if err := eventstream.WriteEvent(&buf, e); err != nil {
			t.Fatalf("WriteEvent: %v", err)
		}
	}
	for _, want := range events {
		got, err := eventstream.ReadEvent(&buf)
		if err != nil {
			t.Fatalf("ReadEvent: %v", err)
		}
		if got.Topic != want.Topic || !bytes.Equal(got.Payload, want.Payload) {
			t.Errorf("mismatch: got {%s %v} want {%s %v}", got.Topic, got.Payload, want.Topic, want.Payload)
		}
	}
}
