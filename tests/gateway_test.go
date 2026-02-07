package tests

import (
	"net"
	"testing"

	"web4/pkg/gateway"
	"web4/pkg/protocol"
)

func TestMappingTableAutoAssign(t *testing.T) {
	t.Parallel()
	mt, err := gateway.NewMappingTable("10.4.0.0/16")
	if err != nil {
		t.Fatalf("create mapping table: %v", err)
	}

	addr1 := protocol.Addr{Network: 1, Node: 100}
	addr2 := protocol.Addr{Network: 1, Node: 200}

	ip1, err := mt.Map(addr1, nil)
	if err != nil {
		t.Fatalf("map addr1: %v", err)
	}
	if ip1.String() != "10.4.0.1" {
		t.Fatalf("expected 10.4.0.1, got %s", ip1)
	}

	ip2, err := mt.Map(addr2, nil)
	if err != nil {
		t.Fatalf("map addr2: %v", err)
	}
	if ip2.String() != "10.4.0.2" {
		t.Fatalf("expected 10.4.0.2, got %s", ip2)
	}
}

func TestMappingTableExplicitIP(t *testing.T) {
	t.Parallel()
	mt, err := gateway.NewMappingTable("10.4.0.0/16")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	addr := protocol.Addr{Network: 1, Node: 100}
	ip, err := mt.Map(addr, net.ParseIP("10.4.5.5"))
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if ip.String() != "10.4.5.5" {
		t.Fatalf("expected 10.4.5.5, got %s", ip)
	}
}

func TestMappingTableOutOfSubnet(t *testing.T) {
	t.Parallel()
	mt, err := gateway.NewMappingTable("10.4.0.0/16")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	addr := protocol.Addr{Network: 1, Node: 100}
	_, err = mt.Map(addr, net.ParseIP("192.168.1.1"))
	if err == nil {
		t.Fatal("expected error for IP outside subnet, got nil")
	}
}

func TestMappingTableDuplicateAddr(t *testing.T) {
	t.Parallel()
	mt, err := gateway.NewMappingTable("10.4.0.0/16")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	addr := protocol.Addr{Network: 1, Node: 100}
	ip1, err := mt.Map(addr, nil)
	if err != nil {
		t.Fatalf("first map: %v", err)
	}

	// Mapping same addr again should return existing IP
	ip2, err := mt.Map(addr, nil)
	if err != nil {
		t.Fatalf("second map: %v", err)
	}
	if !ip1.Equal(ip2) {
		t.Fatalf("expected same IP, got %s and %s", ip1, ip2)
	}
}

func TestMappingTableDuplicateIP(t *testing.T) {
	t.Parallel()
	mt, err := gateway.NewMappingTable("10.4.0.0/16")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	addr1 := protocol.Addr{Network: 1, Node: 100}
	addr2 := protocol.Addr{Network: 1, Node: 200}

	_, err = mt.Map(addr1, net.ParseIP("10.4.0.50"))
	if err != nil {
		t.Fatalf("first map: %v", err)
	}

	// Same IP for different addr should fail
	_, err = mt.Map(addr2, net.ParseIP("10.4.0.50"))
	if err == nil {
		t.Fatal("expected error for duplicate IP, got nil")
	}
}

func TestMappingTableUnmap(t *testing.T) {
	t.Parallel()
	mt, err := gateway.NewMappingTable("10.4.0.0/16")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	addr := protocol.Addr{Network: 1, Node: 100}
	ip, err := mt.Map(addr, nil)
	if err != nil {
		t.Fatalf("map: %v", err)
	}

	// Lookup should work
	found, ok := mt.Lookup(ip)
	if !ok || found != addr {
		t.Fatalf("lookup failed: ok=%v, found=%v", ok, found)
	}

	// Unmap
	if err := mt.Unmap(ip); err != nil {
		t.Fatalf("unmap: %v", err)
	}

	// Lookup should fail now
	_, ok = mt.Lookup(ip)
	if ok {
		t.Fatal("expected lookup to fail after unmap")
	}

	// Reverse lookup should also fail
	_, ok = mt.ReverseLookup(addr)
	if ok {
		t.Fatal("expected reverse lookup to fail after unmap")
	}
}

func TestMappingTableUnmapNotFound(t *testing.T) {
	t.Parallel()
	mt, err := gateway.NewMappingTable("10.4.0.0/16")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	err = mt.Unmap(net.ParseIP("10.4.0.1"))
	if err == nil {
		t.Fatal("expected error unmapping non-existent IP, got nil")
	}
}

func TestMappingTableReverseLookup(t *testing.T) {
	t.Parallel()
	mt, err := gateway.NewMappingTable("10.4.0.0/16")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	addr := protocol.Addr{Network: 1, Node: 100}
	ip, err := mt.Map(addr, nil)
	if err != nil {
		t.Fatalf("map: %v", err)
	}

	// Reverse lookup
	found, ok := mt.ReverseLookup(addr)
	if !ok {
		t.Fatal("reverse lookup failed")
	}
	if !found.Equal(ip) {
		t.Fatalf("expected %s, got %s", ip, found)
	}

	// Unknown addr
	_, ok = mt.ReverseLookup(protocol.Addr{Network: 99, Node: 99})
	if ok {
		t.Fatal("expected reverse lookup to fail for unknown addr")
	}
}

func TestMappingTableAll(t *testing.T) {
	t.Parallel()
	mt, err := gateway.NewMappingTable("10.4.0.0/16")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Empty table
	if len(mt.All()) != 0 {
		t.Fatal("expected empty All()")
	}

	// Add some
	for i := uint32(1); i <= 5; i++ {
		addr := protocol.Addr{Network: 1, Node: i}
		if _, err := mt.Map(addr, nil); err != nil {
			t.Fatalf("map node %d: %v", i, err)
		}
	}

	all := mt.All()
	if len(all) != 5 {
		t.Fatalf("expected 5 mappings, got %d", len(all))
	}
}

func TestMappingTableInvalidSubnet(t *testing.T) {
	t.Parallel()
	_, err := gateway.NewMappingTable("not-a-cidr")
	if err == nil {
		t.Fatal("expected error for invalid CIDR, got nil")
	}
}

func TestMappingTableRemapAfterUnmap(t *testing.T) {
	t.Parallel()
	mt, err := gateway.NewMappingTable("10.4.0.0/16")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	addr := protocol.Addr{Network: 1, Node: 100}
	ip, err := mt.Map(addr, nil)
	if err != nil {
		t.Fatalf("map: %v", err)
	}

	if err := mt.Unmap(ip); err != nil {
		t.Fatalf("unmap: %v", err)
	}

	// Should be able to re-map the same pilot addr after unmap
	ip2, err := mt.Map(addr, nil)
	if err != nil {
		t.Fatalf("remap: %v", err)
	}
	t.Logf("remapped %s → %s", addr, ip2)
}

func TestMappingTableUnmapAndAllConsistent(t *testing.T) {
	t.Parallel()
	mt, err := gateway.NewMappingTable("10.4.0.0/16")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Map 3 addresses
	addrs := make([]protocol.Addr, 3)
	ips := make([]net.IP, 3)
	for i := 0; i < 3; i++ {
		addrs[i] = protocol.Addr{Network: 1, Node: uint32(i + 1)}
		ips[i], err = mt.Map(addrs[i], nil)
		if err != nil {
			t.Fatalf("map %d: %v", i, err)
		}
	}

	if len(mt.All()) != 3 {
		t.Fatalf("expected 3 mappings, got %d", len(mt.All()))
	}

	// Unmap the middle one
	if err := mt.Unmap(ips[1]); err != nil {
		t.Fatalf("unmap: %v", err)
	}

	all := mt.All()
	if len(all) != 2 {
		t.Fatalf("expected 2 mappings after unmap, got %d", len(all))
	}

	// Verify remaining mappings are correct
	_, ok0 := mt.Lookup(ips[0])
	_, ok1 := mt.Lookup(ips[1])
	_, ok2 := mt.Lookup(ips[2])
	if !ok0 || ok1 || !ok2 {
		t.Fatalf("lookup after unmap: ok0=%v ok1=%v ok2=%v", ok0, ok1, ok2)
	}
}

func TestGatewayUnmapCleanup(t *testing.T) {
	t.Parallel()

	gw, err := gateway.New(gateway.Config{
		Subnet: "10.99.0.0/16",
	})
	if err != nil {
		t.Fatalf("create gateway: %v", err)
	}
	// Don't call Start() — we're testing Unmap logic without daemon connection

	// Manually add a mapping via the mapping table
	addr := protocol.Addr{Network: 1, Node: 42}
	ip, err := gw.Mappings().Map(addr, nil)
	if err != nil {
		t.Fatalf("map: %v", err)
	}

	// Unmap should succeed (no listeners to close, no alias to remove in test)
	if err := gw.Unmap(ip.String()); err != nil {
		t.Fatalf("unmap: %v", err)
	}

	// Verify mapping is gone
	_, ok := gw.Mappings().Lookup(ip)
	if ok {
		t.Fatal("mapping should be removed after Unmap")
	}
	_, ok = gw.Mappings().ReverseLookup(addr)
	if ok {
		t.Fatal("reverse mapping should be removed after Unmap")
	}
}

func TestGatewayUnmapNotFound(t *testing.T) {
	t.Parallel()

	gw, err := gateway.New(gateway.Config{
		Subnet: "10.99.0.0/16",
	})
	if err != nil {
		t.Fatalf("create gateway: %v", err)
	}

	err = gw.Unmap("10.99.0.1")
	if err == nil {
		t.Fatal("expected error unmapping non-existent IP")
	}
}

func TestGatewayUnmapInvalidIP(t *testing.T) {
	t.Parallel()

	gw, err := gateway.New(gateway.Config{
		Subnet: "10.99.0.0/16",
	})
	if err != nil {
		t.Fatalf("create gateway: %v", err)
	}

	err = gw.Unmap("not-an-ip")
	if err == nil {
		t.Fatal("expected error for invalid IP")
	}
}

func TestGatewayDefaultPorts(t *testing.T) {
	t.Parallel()
	// Verify default ports match spec
	expected := []uint16{80, 443, 1000, 1001, 1002, 7, 8080, 8443}
	if len(gateway.DefaultPorts) != len(expected) {
		t.Fatalf("expected %d default ports, got %d", len(expected), len(gateway.DefaultPorts))
	}
	for i, p := range expected {
		if gateway.DefaultPorts[i] != p {
			t.Fatalf("port %d: expected %d, got %d", i, p, gateway.DefaultPorts[i])
		}
	}
}
