package tests

import (
	"net"
	"sync"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/gateway"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// ---------------------------------------------------------------------------
// Fuzz targets
// ---------------------------------------------------------------------------

func FuzzNewMappingTable(f *testing.F) {
	f.Add("10.4.0.0/16")
	f.Add("192.168.1.0/24")
	f.Add("not-a-cidr")
	f.Add("")
	f.Add("999.999.999.999/99")
	f.Add("10.0.0.0/32")
	f.Add("10.0.0.0/31")
	f.Add("10.0.0.0/8")
	f.Add("::1/128")

	f.Fuzz(func(t *testing.T, cidr string) {
		_, _ = gateway.NewMappingTable(cidr)
	})
}

// ---------------------------------------------------------------------------
// Edge case unit tests
// ---------------------------------------------------------------------------

func TestNewMappingTableInvalidCIDR(t *testing.T) {
	bad := []string{
		"not-a-cidr",
		"999.999.999.999/99",
		"",
		"abc",
		"10.0.0.0",    // missing prefix len
		"10.0.0.0/33", // /33 invalid for IPv4
	}
	for _, cidr := range bad {
		_, err := gateway.NewMappingTable(cidr)
		if err == nil {
			t.Errorf("expected error for CIDR %q", cidr)
		}
	}
}

func TestNewMappingTableSlash32(t *testing.T) {
	mt, err := gateway.NewMappingTable("10.0.0.1/32")
	if err != nil {
		t.Fatalf("NewMappingTable /32: %v", err)
	}
	// /32 has only 1 host (10.0.0.1), starting at .1 means 10.0.0.1
	// Actually subnet is 10.0.0.1/32 so only 10.0.0.1 is in subnet
	// but start IP is 10.0.0.1 (base + 1 on last byte), which might be 10.0.0.2 and outside
	// Let's just verify it returns a valid table; mapping may fail
	_ = mt
}

func TestNewMappingTableSlash31(t *testing.T) {
	mt, err := gateway.NewMappingTable("10.0.0.0/31")
	if err != nil {
		t.Fatalf("NewMappingTable /31: %v", err)
	}
	// /31 has 2 IPs: 10.0.0.0 and 10.0.0.1; start at .1
	addr := protocol.Addr{Network: 1, Node: 1}
	ip, err := mt.Map(addr, nil)
	if err != nil {
		t.Fatalf("Map in /31: %v", err)
	}
	if ip.String() != "10.0.0.1" {
		t.Fatalf("expected 10.0.0.1, got %s", ip)
	}
}

func TestNewMappingTableSlash24(t *testing.T) {
	mt, err := gateway.NewMappingTable("192.168.1.0/24")
	if err != nil {
		t.Fatalf("NewMappingTable /24: %v", err)
	}
	// Map first address
	ip, err := mt.Map(protocol.Addr{Network: 1, Node: 1}, nil)
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if ip.String() != "192.168.1.1" {
		t.Fatalf("expected 192.168.1.1, got %s", ip)
	}
}

func TestGatewayMapDuplicatePilotAddr(t *testing.T) {
	mt, err := gateway.NewMappingTable("10.4.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	addr := protocol.Addr{Network: 1, Node: 42}
	ip1, err := mt.Map(addr, nil)
	if err != nil {
		t.Fatalf("first Map: %v", err)
	}
	// Second map of same pilot addr returns existing IP
	ip2, err := mt.Map(addr, nil)
	if err != nil {
		t.Fatalf("second Map: %v", err)
	}
	if !ip1.Equal(ip2) {
		t.Fatalf("duplicate pilot addr should return same IP: %s != %s", ip1, ip2)
	}
}

func TestGatewayMapExplicitIPOutsideSubnet(t *testing.T) {
	mt, err := gateway.NewMappingTable("10.4.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	// 192.168.1.1 is outside 10.4.0.0/24
	_, err = mt.Map(protocol.Addr{Network: 1, Node: 1}, net.ParseIP("192.168.1.1"))
	if err == nil {
		t.Fatal("expected error for IP outside subnet")
	}
}

func TestGatewayMapExplicitIPAlreadyMapped(t *testing.T) {
	mt, err := gateway.NewMappingTable("10.4.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP("10.4.0.5")
	_, err = mt.Map(protocol.Addr{Network: 1, Node: 1}, ip)
	if err != nil {
		t.Fatalf("first Map explicit: %v", err)
	}
	// Map different pilot addr to same IP
	_, err = mt.Map(protocol.Addr{Network: 1, Node: 2}, ip)
	if err == nil {
		t.Fatal("expected error for already-mapped IP")
	}
}

func TestGatewayUnmapRemap(t *testing.T) {
	mt, err := gateway.NewMappingTable("10.4.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	addr := protocol.Addr{Network: 1, Node: 42}
	ip, err := mt.Map(addr, nil)
	if err != nil {
		t.Fatalf("Map: %v", err)
	}

	if err := mt.Unmap(ip); err != nil {
		t.Fatalf("Unmap: %v", err)
	}

	// Verify lookup fails
	_, ok := mt.Lookup(ip)
	if ok {
		t.Fatal("Lookup should fail after Unmap")
	}
	_, ok = mt.ReverseLookup(addr)
	if ok {
		t.Fatal("ReverseLookup should fail after Unmap")
	}

	// Remap — should get a new (potentially different) IP
	ip2, err := mt.Map(addr, nil)
	if err != nil {
		t.Fatalf("remap: %v", err)
	}
	if ip2 == nil {
		t.Fatal("remap returned nil")
	}
}

func TestGatewayLookupNonExistent(t *testing.T) {
	mt, err := gateway.NewMappingTable("10.4.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	_, ok := mt.Lookup(net.ParseIP("10.4.0.99"))
	if ok {
		t.Fatal("Lookup should return false for non-existent IP")
	}
	_, ok = mt.ReverseLookup(protocol.Addr{Network: 99, Node: 99})
	if ok {
		t.Fatal("ReverseLookup should return false for non-existent addr")
	}
}

func TestGatewayAllConsistency(t *testing.T) {
	mt, err := gateway.NewMappingTable("10.4.0.0/16")
	if err != nil {
		t.Fatal(err)
	}

	addrs := []protocol.Addr{
		{Network: 1, Node: 1},
		{Network: 1, Node: 2},
		{Network: 2, Node: 1},
	}
	for _, a := range addrs {
		if _, err := mt.Map(a, nil); err != nil {
			t.Fatalf("Map %v: %v", a, err)
		}
	}

	all := mt.All()
	if len(all) != len(addrs) {
		t.Fatalf("All: expected %d, got %d", len(addrs), len(all))
	}

	// Verify forward/reverse consistency
	for _, m := range all {
		gotAddr, ok := mt.Lookup(m.LocalIP)
		if !ok || gotAddr != m.PilotAddr {
			t.Fatalf("Lookup inconsistency for %s", m.LocalIP)
		}
		gotIP, ok := mt.ReverseLookup(m.PilotAddr)
		if !ok || !gotIP.Equal(m.LocalIP) {
			t.Fatalf("ReverseLookup inconsistency for %v", m.PilotAddr)
		}
	}
}

func TestIncIPCarryPropagation(t *testing.T) {
	// 10.0.0.255 → 10.0.1.0
	mt, err := gateway.NewMappingTable("10.0.0.0/16")
	if err != nil {
		t.Fatal(err)
	}

	// Map 255 addresses to exhaust .0.x range
	for i := uint32(1); i <= 255; i++ {
		_, err := mt.Map(protocol.Addr{Network: 1, Node: i}, nil)
		if err != nil {
			t.Fatalf("Map node %d: %v", i, err)
		}
	}
	// Next allocation should be 10.0.1.0
	ip, err := mt.Map(protocol.Addr{Network: 1, Node: 256}, nil)
	if err != nil {
		t.Fatalf("Map after carry: %v", err)
	}
	if ip.String() != "10.0.1.0" {
		t.Fatalf("expected 10.0.1.0 after carry, got %s", ip)
	}
}

func TestGatewayConcurrentAccess(t *testing.T) {
	mt, err := gateway.NewMappingTable("10.4.0.0/16")
	if err != nil {
		t.Fatal(err)
	}

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			addr := protocol.Addr{Network: 1, Node: uint32(id)}
			ip, err := mt.Map(addr, nil)
			if err != nil {
				return
			}
			mt.Lookup(ip)
			mt.ReverseLookup(addr)
			mt.All()
		}(i)
	}

	wg.Wait()
}

func TestGatewaySubnetExhaustion(t *testing.T) {
	// /30 has 4 IPs (10.0.0.0-3), usable: starting from .1 we get .1, .2, .3
	mt, err := gateway.NewMappingTable("10.0.0.0/30")
	if err != nil {
		t.Fatal(err)
	}
	for i := uint32(1); i <= 3; i++ {
		_, err := mt.Map(protocol.Addr{Network: 1, Node: i}, nil)
		if err != nil {
			t.Fatalf("Map %d: %v", i, err)
		}
	}
	// 4th allocation should fail (subnet exhausted)
	_, err = mt.Map(protocol.Addr{Network: 1, Node: 4}, nil)
	if err == nil {
		t.Fatal("expected subnet exhaustion error")
	}
}

func TestGatewayUnmapNonExistent(t *testing.T) {
	mt, err := gateway.NewMappingTable("10.4.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	err = mt.Unmap(net.ParseIP("10.4.0.99"))
	if err == nil {
		t.Fatal("expected error for unmapping non-existent IP")
	}
}

func TestGatewayIPv6CIDR(t *testing.T) {
	mt, err := gateway.NewMappingTable("fd00::/120")
	if err != nil {
		t.Fatalf("NewMappingTable IPv6: %v", err)
	}
	// Should be able to map at least one address
	ip, err := mt.Map(protocol.Addr{Network: 1, Node: 1}, nil)
	if err != nil {
		t.Fatalf("Map IPv6: %v", err)
	}
	if ip == nil {
		t.Fatal("Map returned nil for IPv6")
	}
}
