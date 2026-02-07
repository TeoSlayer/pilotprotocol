package tests

import (
	"bytes"
	"encoding/binary"
	"testing"

	"web4/pkg/eventstream"
)

func TestEventRoundTrip(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer

	original := &eventstream.Event{
		Topic:   "sensor-data",
		Payload: []byte("temperature=22.5"),
	}

	if err := eventstream.WriteEvent(&buf, original); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := eventstream.ReadEvent(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if got.Topic != original.Topic {
		t.Fatalf("topic: expected %q, got %q", original.Topic, got.Topic)
	}
	if !bytes.Equal(got.Payload, original.Payload) {
		t.Fatalf("payload: expected %q, got %q", original.Payload, got.Payload)
	}
}

func TestEventEmptyPayload(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer

	original := &eventstream.Event{
		Topic:   "heartbeat",
		Payload: []byte{},
	}

	if err := eventstream.WriteEvent(&buf, original); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := eventstream.ReadEvent(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if got.Topic != "heartbeat" {
		t.Fatalf("topic: expected %q, got %q", "heartbeat", got.Topic)
	}
	if len(got.Payload) != 0 {
		t.Fatalf("expected empty payload, got %d bytes", len(got.Payload))
	}
}

func TestEventWildcardTopic(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer

	original := &eventstream.Event{
		Topic:   "*",
		Payload: []byte("subscribe-all"),
	}

	if err := eventstream.WriteEvent(&buf, original); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := eventstream.ReadEvent(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if got.Topic != "*" {
		t.Fatalf("expected wildcard topic, got %q", got.Topic)
	}
}

func TestEventMultipleSequential(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer

	events := []*eventstream.Event{
		{Topic: "topic-a", Payload: []byte("msg1")},
		{Topic: "topic-b", Payload: []byte("msg2")},
		{Topic: "topic-a", Payload: []byte("msg3")},
	}

	for _, e := range events {
		if err := eventstream.WriteEvent(&buf, e); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	for i, expected := range events {
		got, err := eventstream.ReadEvent(&buf)
		if err != nil {
			t.Fatalf("read event %d: %v", i, err)
		}
		if got.Topic != expected.Topic {
			t.Fatalf("event %d topic: expected %q, got %q", i, expected.Topic, got.Topic)
		}
		if !bytes.Equal(got.Payload, expected.Payload) {
			t.Fatalf("event %d payload mismatch", i)
		}
	}
}

func TestEventTopicTooLong(t *testing.T) {
	t.Parallel()
	// Craft a header with topic length > 1024
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint16(2000))
	buf.Write(make([]byte, 2000)) // topic data
	binary.Write(&buf, binary.BigEndian, uint32(0))

	_, err := eventstream.ReadEvent(&buf)
	if err == nil {
		t.Fatal("expected error for oversized topic, got nil")
	}
}

func TestEventPayloadTooLarge(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	// Valid topic
	binary.Write(&buf, binary.BigEndian, uint16(4))
	buf.Write([]byte("test"))
	// Oversized payload length (>16MB)
	binary.Write(&buf, binary.BigEndian, uint32(0x02000000))

	_, err := eventstream.ReadEvent(&buf)
	if err == nil {
		t.Fatal("expected error for oversized payload, got nil")
	}
}
