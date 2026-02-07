package eventstream

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Event is a typed message published to the event stream.
// Wire format: [2-byte topic length][topic][4-byte payload length][payload]
type Event struct {
	Topic   string
	Payload []byte
}

// WriteEvent writes an event to a writer.
func WriteEvent(w io.Writer, e *Event) error {
	topic := []byte(e.Topic)
	// [2-byte topic len][topic][4-byte payload len][payload]
	buf := make([]byte, 2+len(topic)+4+len(e.Payload))
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(topic)))
	copy(buf[2:], topic)
	binary.BigEndian.PutUint32(buf[2+len(topic):], uint32(len(e.Payload)))
	copy(buf[2+len(topic)+4:], e.Payload)
	_, err := w.Write(buf)
	return err
}

// ReadEvent reads an event from a reader.
func ReadEvent(r io.Reader) (*Event, error) {
	var topicLen [2]byte
	if _, err := io.ReadFull(r, topicLen[:]); err != nil {
		return nil, err
	}
	tl := binary.BigEndian.Uint16(topicLen[:])
	if tl > 1024 {
		return nil, fmt.Errorf("topic too long: %d", tl)
	}

	topic := make([]byte, tl)
	if _, err := io.ReadFull(r, topic); err != nil {
		return nil, err
	}

	var payloadLen [4]byte
	if _, err := io.ReadFull(r, payloadLen[:]); err != nil {
		return nil, err
	}
	pl := binary.BigEndian.Uint32(payloadLen[:])
	if pl > 1<<24 {
		return nil, fmt.Errorf("payload too large: %d", pl)
	}

	payload := make([]byte, pl)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}

	return &Event{Topic: string(topic), Payload: payload}, nil
}
