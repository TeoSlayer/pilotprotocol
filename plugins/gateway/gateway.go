// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"os/exec"
	"runtime"
	"sync"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// DefaultPorts is the default set of ports the gateway proxies.
var DefaultPorts = []uint16{80, 443, 1000, 1001, 1002, 7, 8080, 8443}

// Dialer is satisfied by *driver.Driver. The concrete implementation
// lives at the L12 composition root (cmd/gateway) so plugins/gateway
// stays free of pkg/driver.
type Dialer interface {
	DialAddr(dst protocol.Addr, port uint16) (net.Conn, error)
	Close() error
}

// Config configures the gateway.
type Config struct {
	Subnet string   // CIDR subnet for local IPs (default: "10.4.0.0/16")
	Ports  []uint16 // Ports to proxy (default: DefaultPorts)
}

// Gateway bridges standard IP/TCP traffic to the Pilot Protocol overlay.
// In proxy mode, it listens on mapped local IPs and forwards TCP connections
// through Pilot Protocol streams.
type Gateway struct {
	config    Config
	mappings  *MappingTable
	dialer    Dialer
	mu        sync.Mutex
	listeners map[string]net.Listener // localIP:port → TCP listener
	aliases   []net.IP                // loopback aliases to clean up on Stop
	done      chan struct{}
}

// New creates a new Gateway bound to the given Dialer. The Dialer is
// typically a *driver.Driver constructed by cmd/gateway.
func New(cfg Config, d Dialer) (*Gateway, error) {
	if cfg.Subnet == "" {
		cfg.Subnet = "10.4.0.0/16"
	}

	mt, err := NewMappingTable(cfg.Subnet)
	if err != nil {
		return nil, err
	}

	if len(cfg.Ports) == 0 {
		cfg.Ports = DefaultPorts
	}

	return &Gateway{
		config:    cfg,
		mappings:  mt,
		dialer:    d,
		listeners: make(map[string]net.Listener),
		done:      make(chan struct{}),
	}, nil
}

// Stop shuts down the gateway and cleans up loopback aliases.
// Safe to call multiple times.
func (gw *Gateway) Stop() {
	select {
	case <-gw.done:
		return // already stopped
	default:
		close(gw.done)
	}
	gw.mu.Lock()
	for ip, ln := range gw.listeners {
		ln.Close()
		delete(gw.listeners, ip)
	}
	aliases := make([]net.IP, len(gw.aliases))
	copy(aliases, gw.aliases)
	gw.aliases = nil
	gw.mu.Unlock()

	for _, ip := range aliases {
		gw.removeLoopbackAlias(ip)
	}
	if len(aliases) > 0 {
		slog.Info("gateway removed loopback aliases", "count", len(aliases))
	}

	if gw.dialer != nil {
		gw.dialer.Close()
	}
}

// Mappings returns the mapping table for external use.
func (gw *Gateway) Mappings() *MappingTable {
	return gw.mappings
}

// Map registers a Pilot address and starts proxying for it.
// If localIP is empty, one is auto-assigned from the subnet.
func (gw *Gateway) Map(pilotAddr protocol.Addr, localIP string) (net.IP, error) {
	var ip net.IP
	if localIP != "" {
		ip = net.ParseIP(localIP)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP: %s", localIP)
		}
	}

	assigned, err := gw.mappings.Map(pilotAddr, ip)
	if err != nil {
		return nil, err
	}

	go gw.startProxy(assigned, pilotAddr)

	slog.Info("gateway mapped address", "local_ip", assigned, "pilot_addr", pilotAddr)
	return assigned, nil
}

// Unmap removes a mapping and stops proxying.
func (gw *Gateway) Unmap(localIP string) error {
	ip := net.ParseIP(localIP)
	if ip == nil {
		return fmt.Errorf("invalid IP: %s", localIP)
	}

	gw.mu.Lock()
	for key, ln := range gw.listeners {
		host, _, err := net.SplitHostPort(key)
		if err != nil {
			continue
		}
		if host == localIP {
			ln.Close()
			delete(gw.listeners, key)
		}
	}
	for i, alias := range gw.aliases {
		if alias.Equal(ip) {
			gw.aliases = append(gw.aliases[:i], gw.aliases[i+1:]...)
			break
		}
	}
	gw.mu.Unlock()

	gw.removeLoopbackAlias(ip)
	return gw.mappings.Unmap(ip)
}

func (gw *Gateway) startProxy(localIP net.IP, pilotAddr protocol.Addr) {
	gw.addLoopbackAlias(localIP)

	gw.mu.Lock()
	gw.aliases = append(gw.aliases, localIP)
	gw.mu.Unlock()

	for _, port := range gw.config.Ports {
		go gw.listenPort(localIP, port, pilotAddr)
	}
}

func (gw *Gateway) addLoopbackAlias(ip net.IP) {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("ip", "addr", "add", ip.String()+"/32", "dev", "lo").Run()
	case "darwin":
		err = exec.Command("ifconfig", "lo0", "alias", ip.String()).Run()
	default:
		slog.Error("addLoopbackAlias: unsupported OS", "os", runtime.GOOS)
		return
	}
	if err != nil {
		slog.Error("addLoopbackAlias failed", "ip", ip, "os", runtime.GOOS, "err", err)
	}
}

func (gw *Gateway) removeLoopbackAlias(ip net.IP) {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("ip", "addr", "del", ip.String()+"/32", "dev", "lo").Run()
	case "darwin":
		err = exec.Command("ifconfig", "lo0", "-alias", ip.String()).Run()
	default:
		slog.Error("removeLoopbackAlias: unsupported OS", "os", runtime.GOOS)
		return
	}
	if err != nil {
		slog.Error("removeLoopbackAlias failed", "ip", ip, "os", runtime.GOOS, "err", err)
	}
}

func (gw *Gateway) listenPort(localIP net.IP, port uint16, pilotAddr protocol.Addr) {
	addr := fmt.Sprintf("%s:%d", localIP, port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		slog.Warn("gateway listen failed", "addr", addr, "err", err)
		return
	}

	gw.mu.Lock()
	key := fmt.Sprintf("%s:%d", localIP, port)
	gw.listeners[key] = ln
	gw.mu.Unlock()

	slog.Info("gateway proxy listening", "addr", addr, "pilot_addr", pilotAddr)

	for {
		tcpConn, err := ln.Accept()
		if err != nil {
			return
		}
		go gw.bridgeConnection(tcpConn, pilotAddr, port)
	}
}

func (gw *Gateway) bridgeConnection(tcpConn net.Conn, pilotAddr protocol.Addr, port uint16) {
	defer tcpConn.Close()

	pilotConn, err := gw.dialer.DialAddr(pilotAddr, port)
	if err != nil {
		slog.Error("gateway dial failed", "pilot_addr", pilotAddr, "port", port, "err", err)
		return
	}
	defer pilotConn.Close()

	done := make(chan struct{}, 2)
	go func() {
		if _, err := io.Copy(pilotConn, tcpConn); err != nil {
			slog.Debug("gateway copy tcp→pilot ended", "error", err)
		}
		pilotConn.Close()
		done <- struct{}{}
	}()
	go func() {
		if _, err := io.Copy(tcpConn, pilotConn); err != nil {
			slog.Debug("gateway copy pilot→tcp ended", "error", err)
		}
		tcpConn.Close()
		done <- struct{}{}
	}()

	<-done
	<-done
}
