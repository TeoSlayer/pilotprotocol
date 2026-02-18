package gateway

import (
	"fmt"
	"net"
	"sync"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// MappingTable maps local IPs to Pilot addresses and vice versa.
type MappingTable struct {
	mu      sync.RWMutex
	forward map[string]protocol.Addr // local IP → pilot addr
	reverse map[protocol.Addr]net.IP // pilot addr → local IP
	subnet  *net.IPNet
	nextIP  net.IP
}

// NewMappingTable creates a mapping table for the given subnet (e.g. "10.4.0.0/16").
func NewMappingTable(cidr string) (*MappingTable, error) {
	_, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse subnet: %w", err)
	}

	// Start allocation at .0.1
	startIP := make(net.IP, len(subnet.IP))
	copy(startIP, subnet.IP)
	startIP[len(startIP)-1] = 1

	return &MappingTable{
		forward: make(map[string]protocol.Addr),
		reverse: make(map[protocol.Addr]net.IP),
		subnet:  subnet,
		nextIP:  startIP,
	}, nil
}

// Map registers a mapping between a Pilot address and a local IP.
// If localIP is nil, the next available IP in the subnet is assigned.
func (mt *MappingTable) Map(pilotAddr protocol.Addr, localIP net.IP) (net.IP, error) {
	mt.mu.Lock()
	defer mt.mu.Unlock()

	// Check if already mapped
	if existing, ok := mt.reverse[pilotAddr]; ok {
		return existing, nil
	}

	if localIP == nil {
		localIP = mt.allocNextIP()
		if localIP == nil {
			return nil, fmt.Errorf("subnet exhausted")
		}
	} else {
		if !mt.subnet.Contains(localIP) {
			return nil, fmt.Errorf("IP %s not in subnet %s", localIP, mt.subnet)
		}
	}

	ipStr := localIP.String()
	if _, exists := mt.forward[ipStr]; exists {
		return nil, fmt.Errorf("IP %s already mapped", ipStr)
	}

	mt.forward[ipStr] = pilotAddr
	mt.reverse[pilotAddr] = localIP
	return localIP, nil
}

// Unmap removes a mapping by local IP.
func (mt *MappingTable) Unmap(localIP net.IP) error {
	mt.mu.Lock()
	defer mt.mu.Unlock()

	ipStr := localIP.String()
	addr, ok := mt.forward[ipStr]
	if !ok {
		return fmt.Errorf("no mapping for %s", ipStr)
	}

	delete(mt.forward, ipStr)
	delete(mt.reverse, addr)
	return nil
}

// Lookup returns the Pilot address for a local IP.
func (mt *MappingTable) Lookup(localIP net.IP) (protocol.Addr, bool) {
	mt.mu.RLock()
	defer mt.mu.RUnlock()
	addr, ok := mt.forward[localIP.String()]
	return addr, ok
}

// ReverseLookup returns the local IP for a Pilot address.
func (mt *MappingTable) ReverseLookup(addr protocol.Addr) (net.IP, bool) {
	mt.mu.RLock()
	defer mt.mu.RUnlock()
	ip, ok := mt.reverse[addr]
	return ip, ok
}

// All returns all current mappings as (localIP, pilotAddr) pairs.
type Mapping struct {
	LocalIP   net.IP
	PilotAddr protocol.Addr
}

func (mt *MappingTable) All() []Mapping {
	mt.mu.RLock()
	defer mt.mu.RUnlock()
	result := make([]Mapping, 0, len(mt.forward))
	for ipStr, addr := range mt.forward {
		result = append(result, Mapping{
			LocalIP:   net.ParseIP(ipStr),
			PilotAddr: addr,
		})
	}
	return result
}

func (mt *MappingTable) allocNextIP() net.IP {
	for {
		ip := make(net.IP, len(mt.nextIP))
		copy(ip, mt.nextIP)

		if !mt.subnet.Contains(ip) {
			return nil
		}

		// Increment nextIP
		incIP(mt.nextIP)

		// Skip .0 and .255 for /24+ subnets
		ipStr := ip.String()
		if _, exists := mt.forward[ipStr]; !exists {
			return ip
		}
	}
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}
