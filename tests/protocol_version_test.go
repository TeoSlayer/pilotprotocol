package tests

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

// TestPacketVersionValidation verifies that Unmarshal rejects packets with a
// wrong protocol version in the header.
func TestPacketVersionValidation(t *testing.T) {
	t.Parallel()

	// Build a valid packet, then tamper with the version nibble.
	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagSYN,
		Protocol: protocol.ProtoStream,
		Src:      protocol.Addr{Network: 0, Node: 1},
		Dst:      protocol.Addr{Network: 0, Node: 2},
		SrcPort:  49152,
		DstPort:  1000,
		Payload:  []byte("hello"),
	}

	data, err := pkt.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	// Tamper: set version nibble to 0xF (15) — different from Version (1).
	badVersion := uint8(0xF)
	data[0] = (badVersion << 4) | (data[0] & 0x0F)

	// Recompute checksum so the version check is reached (not blocked by checksum).
	binary.BigEndian.PutUint32(data[30:34], 0)
	binary.BigEndian.PutUint32(data[30:34], protocol.Checksum(data))

	_, err = protocol.Unmarshal(data)
	if err == nil {
		t.Fatal("expected error for wrong protocol version, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported protocol version") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

// TestPacketVersionCorrect verifies that marshal/unmarshal round-trips
// succeed when using the correct protocol version.
func TestPacketVersionCorrect(t *testing.T) {
	t.Parallel()

	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagACK,
		Protocol: protocol.ProtoStream,
		Src:      protocol.Addr{Network: 0, Node: 1},
		Dst:      protocol.Addr{Network: 0, Node: 2},
		SrcPort:  49152,
		DstPort:  7,
		Seq:      100,
		Ack:      50,
		Payload:  []byte("version check"),
	}

	data, err := pkt.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	got, err := protocol.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.Version != protocol.Version {
		t.Errorf("Version = %d, want %d", got.Version, protocol.Version)
	}
	if string(got.Payload) != "version check" {
		t.Errorf("Payload = %q, want %q", got.Payload, "version check")
	}
}

// TestRegistryProtocolVersion registers a node and verifies that the
// register_ok response includes a protocol_version field.
func TestRegistryProtocolVersion(t *testing.T) {
	t.Parallel()

	reg := registry.New(":0")
	go reg.ListenAndServe(":0")

	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	defer reg.Close()

	client, err := registry.Dial(reg.Addr().String())
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer client.Close()

	id, _ := crypto.GenerateIdentity()
	resp, err := client.RegisterWithKey("version-test.local", crypto.EncodePublicKey(id.PublicKey), "127.0.0.1:9000", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	// Verify register_ok response contains protocol_version
	pvRaw, ok := resp["protocol_version"]
	if !ok {
		t.Fatal("register_ok response missing protocol_version field")
	}

	pv, ok := pvRaw.(float64)
	if !ok {
		t.Fatalf("protocol_version is not a number: %T", pvRaw)
	}

	if int(pv) != int(protocol.Version) {
		t.Errorf("protocol_version = %d, want %d", int(pv), int(protocol.Version))
	}
}

// TestSnapshotVersion triggers a snapshot save, reloads it from disk,
// and verifies the version field is present and set to 1.
func TestSnapshotVersion(t *testing.T) {
	t.Parallel()

	snapDir := t.TempDir()
	snapPath := filepath.Join(snapDir, "registry-snapshot.json")

	reg := registry.NewWithStore(":0", snapPath)
	go reg.ListenAndServe(":0")

	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	defer reg.Close()

	// Register a node so the snapshot has some data.
	client, err := registry.Dial(reg.Addr().String())
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer client.Close()

	id, _ := crypto.GenerateIdentity()
	if _, err := client.RegisterWithKey("snap-version.local", crypto.EncodePublicKey(id.PublicKey), "127.0.0.1:9001", nil); err != nil {
		t.Fatalf("register: %v", err)
	}

	// Trigger snapshot save.
	if err := reg.TriggerSnapshot(); err != nil {
		t.Fatalf("trigger snapshot: %v", err)
	}

	// Read and parse the snapshot file.
	data, err := os.ReadFile(snapPath)
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}

	var snap map[string]interface{}
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}

	vRaw, ok := snap["version"]
	if !ok {
		t.Fatal("snapshot missing version field")
	}

	v, ok := vRaw.(float64)
	if !ok {
		t.Fatalf("version is not a number: %T", vRaw)
	}

	if int(v) != 1 {
		t.Errorf("snapshot version = %d, want 1", int(v))
	}
}
