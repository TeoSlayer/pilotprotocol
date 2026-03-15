package tests

import (
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/nameserver"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// ---------------------------------------------------------------------------
// RecordStore: A records
// ---------------------------------------------------------------------------

func TestRecordStoreRegisterLookupA(t *testing.T) {
	rs := nameserver.NewRecordStore()
	defer rs.Close()

	addr := protocol.Addr{Network: 1, Node: 42}
	rs.RegisterA("mynode", addr)

	got, err := rs.LookupA("mynode")
	if err != nil {
		t.Fatalf("LookupA: %v", err)
	}
	if got != addr {
		t.Fatalf("expected %v, got %v", addr, got)
	}
}

func TestRecordStoreLookupANotFound(t *testing.T) {
	rs := nameserver.NewRecordStore()
	defer rs.Close()

	_, err := rs.LookupA("nonexistent")
	if err == nil {
		t.Fatal("expected error for non-existent A record")
	}
}

func TestRecordStoreRegisterAOverwrite(t *testing.T) {
	rs := nameserver.NewRecordStore()
	defer rs.Close()

	rs.RegisterA("test", protocol.Addr{Network: 1, Node: 1})
	rs.RegisterA("test", protocol.Addr{Network: 1, Node: 2})

	got, err := rs.LookupA("test")
	if err != nil {
		t.Fatalf("LookupA: %v", err)
	}
	if got.Node != 2 {
		t.Fatalf("expected node 2 after overwrite, got %d", got.Node)
	}
}

func TestRecordStoreUnregisterA(t *testing.T) {
	rs := nameserver.NewRecordStore()
	defer rs.Close()

	rs.RegisterA("test", protocol.Addr{Network: 1, Node: 1})
	rs.UnregisterA("test")

	_, err := rs.LookupA("test")
	if err == nil {
		t.Fatal("expected error after unregister")
	}
}

func TestRecordStoreUnregisterANonExistent(t *testing.T) {
	rs := nameserver.NewRecordStore()
	defer rs.Close()

	// Should not panic
	rs.UnregisterA("nonexistent")
}

func TestRecordStoreAllA(t *testing.T) {
	rs := nameserver.NewRecordStore()
	defer rs.Close()

	rs.RegisterA("a", protocol.Addr{Network: 1, Node: 1})
	rs.RegisterA("b", protocol.Addr{Network: 1, Node: 2})

	all := rs.AllA()
	if len(all) != 2 {
		t.Fatalf("expected 2 A records, got %d", len(all))
	}
	if all["a"].Node != 1 || all["b"].Node != 2 {
		t.Fatal("AllA content mismatch")
	}
}

// ---------------------------------------------------------------------------
// RecordStore: N records
// ---------------------------------------------------------------------------

func TestRecordStoreRegisterLookupN(t *testing.T) {
	rs := nameserver.NewRecordStore()
	defer rs.Close()

	rs.RegisterN("mynet", 42)

	got, err := rs.LookupN("mynet")
	if err != nil {
		t.Fatalf("LookupN: %v", err)
	}
	if got != 42 {
		t.Fatalf("expected 42, got %d", got)
	}
}

func TestRecordStoreLookupNNotFound(t *testing.T) {
	rs := nameserver.NewRecordStore()
	defer rs.Close()

	_, err := rs.LookupN("nonexistent")
	if err == nil {
		t.Fatal("expected error for non-existent N record")
	}
}

func TestRecordStoreRegisterNOverwrite(t *testing.T) {
	rs := nameserver.NewRecordStore()
	defer rs.Close()

	rs.RegisterN("net", 1)
	rs.RegisterN("net", 2)

	got, _ := rs.LookupN("net")
	if got != 2 {
		t.Fatalf("expected 2 after overwrite, got %d", got)
	}
}

func TestRecordStoreRegisterNBoundary(t *testing.T) {
	rs := nameserver.NewRecordStore()
	defer rs.Close()

	rs.RegisterN("min", 0)
	rs.RegisterN("max", 0xFFFF)

	got0, _ := rs.LookupN("min")
	if got0 != 0 {
		t.Fatalf("expected 0, got %d", got0)
	}
	gotMax, _ := rs.LookupN("max")
	if gotMax != 0xFFFF {
		t.Fatalf("expected 0xFFFF, got %d", gotMax)
	}
}

// ---------------------------------------------------------------------------
// RecordStore: S records
// ---------------------------------------------------------------------------

func TestRecordStoreRegisterLookupS(t *testing.T) {
	rs := nameserver.NewRecordStore()
	defer rs.Close()

	addr := protocol.Addr{Network: 1, Node: 10}
	rs.RegisterS("svc", addr, 1, 80)

	entries := rs.LookupS(1, 80)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Name != "svc" || entries[0].Port != 80 {
		t.Fatal("S record content mismatch")
	}
}

func TestRecordStoreLookupSEmpty(t *testing.T) {
	rs := nameserver.NewRecordStore()
	defer rs.Close()

	entries := rs.LookupS(999, 80)
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}
}

func TestRecordStoreRegisterSMultipleProviders(t *testing.T) {
	rs := nameserver.NewRecordStore()
	defer rs.Close()

	rs.RegisterS("svc-a", protocol.Addr{Network: 1, Node: 1}, 1, 80)
	rs.RegisterS("svc-b", protocol.Addr{Network: 1, Node: 2}, 1, 80)

	entries := rs.LookupS(1, 80)
	if len(entries) != 2 {
		t.Fatalf("expected 2 providers, got %d", len(entries))
	}
}

func TestRecordStoreRegisterSDuplicate(t *testing.T) {
	rs := nameserver.NewRecordStore()
	defer rs.Close()

	addr := protocol.Addr{Network: 1, Node: 1}
	rs.RegisterS("svc", addr, 1, 80)
	rs.RegisterS("svc", addr, 1, 80) // duplicate — should refresh TTL, not add

	entries := rs.LookupS(1, 80)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry (duplicate refreshed), got %d", len(entries))
	}
}

func TestRecordStoreRegisterSDifferentPorts(t *testing.T) {
	rs := nameserver.NewRecordStore()
	defer rs.Close()

	addr := protocol.Addr{Network: 1, Node: 1}
	rs.RegisterS("http", addr, 1, 80)
	rs.RegisterS("https", addr, 1, 443)

	if len(rs.LookupS(1, 80)) != 1 {
		t.Fatal("expected 1 entry for port 80")
	}
	if len(rs.LookupS(1, 443)) != 1 {
		t.Fatal("expected 1 entry for port 443")
	}
}

// ---------------------------------------------------------------------------
// RecordStore: Persistence
// ---------------------------------------------------------------------------

func TestRecordStorePersistence(t *testing.T) {
	dir := t.TempDir()
	storePath := dir + "/ns-records.json"

	// Create and populate
	rs1 := nameserver.NewRecordStore()
	rs1.SetStorePath(storePath)
	rs1.RegisterA("myhost", protocol.Addr{Network: 1, Node: 42})
	rs1.RegisterN("mynet", 5)
	rs1.RegisterS("mysvc", protocol.Addr{Network: 1, Node: 10}, 5, 80)
	rs1.Close()

	// Load in a new store
	rs2 := nameserver.NewRecordStore()
	rs2.SetStorePath(storePath)
	defer rs2.Close()

	addr, err := rs2.LookupA("myhost")
	if err != nil {
		t.Fatalf("LookupA after reload: %v", err)
	}
	if addr.Node != 42 {
		t.Fatalf("expected node 42, got %d", addr.Node)
	}

	netID, err := rs2.LookupN("mynet")
	if err != nil {
		t.Fatalf("LookupN after reload: %v", err)
	}
	if netID != 5 {
		t.Fatalf("expected netID 5, got %d", netID)
	}

	entries := rs2.LookupS(5, 80)
	if len(entries) != 1 || entries[0].Name != "mysvc" {
		t.Fatal("S record not persisted correctly")
	}
}

func TestRecordStoreNoStorePath(t *testing.T) {
	rs := nameserver.NewRecordStore()
	defer rs.Close()

	// Operations should work without persistence
	rs.RegisterA("test", protocol.Addr{Network: 1, Node: 1})
	_, err := rs.LookupA("test")
	if err != nil {
		t.Fatalf("LookupA without persistence: %v", err)
	}
}

func TestRecordStoreLoadNonExistent(t *testing.T) {
	rs := nameserver.NewRecordStore()
	defer rs.Close()

	// Should not panic or error — just silently skip
	rs.SetStorePath("/nonexistent/path/records.json")
}

// ---------------------------------------------------------------------------
// RecordStore: TTL
// ---------------------------------------------------------------------------

func TestRecordStoreDefaultTTL(t *testing.T) {
	// Just verify the constant is reasonable
	if nameserver.DefaultRecordTTL.Minutes() < 1 || nameserver.DefaultRecordTTL.Minutes() > 60 {
		t.Fatalf("DefaultRecordTTL seems unreasonable: %v", nameserver.DefaultRecordTTL)
	}
}
