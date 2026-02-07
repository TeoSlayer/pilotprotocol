package gateway

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"os/exec"
	"runtime"
	"sync"

	"web4/pkg/driver"
	"web4/pkg/protocol"
)

// DefaultPorts is the default set of ports the gateway proxies.
var DefaultPorts = []uint16{80, 443, 1000, 1001, 1002, 7, 8080, 8443}

// Config configures the gateway.
type Config struct {
	Subnet     string   // CIDR subnet for local IPs (default: "10.4.0.0/16")
	SocketPath string   // Daemon socket path
	Ports      []uint16 // Ports to proxy (default: DefaultPorts)
}

// Gateway bridges standard IP/TCP traffic to the Pilot Protocol overlay.
// In proxy mode, it listens on mapped local IPs and forwards TCP connections
// through Pilot Protocol streams.
type Gateway struct {
	config    Config
	mappings  *MappingTable
	driver    *driver.Driver
	mu        sync.Mutex
	listeners map[string]net.Listener // localIP:port → TCP listener
	aliases   []net.IP               // loopback aliases to clean up on Stop
	done      chan struct{}
}

// New creates a new Gateway.
func New(cfg Config) (*Gateway, error) {
	if cfg.Subnet == "" {
		cfg.Subnet = "10.4.0.0/16"
	}
	if cfg.SocketPath == "" {
		cfg.SocketPath = driver.DefaultSocketPath
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
		listeners: make(map[string]net.Listener),
		done:      make(chan struct{}),
	}, nil
}

// Start connects to the daemon and begins proxying.
func (gw *Gateway) Start() error {
	d, err := driver.Connect(gw.config.SocketPath)
	if err != nil {
		return fmt.Errorf("connect to daemon: %w", err)
	}
	gw.driver = d
	slog.Info("gateway connected", "subnet", gw.config.Subnet)
	return nil
}

// Stop shuts down the gateway and cleans up loopback aliases.
// Safe to call multiple times (M17 fix).
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

	// Clean up loopback aliases
	for _, ip := range aliases {
		gw.removeLoopbackAlias(ip)
	}
	if len(aliases) > 0 {
		slog.Info("gateway removed loopback aliases", "count", len(aliases))
	}

	if gw.driver != nil {
		gw.driver.Close()
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

	// Start a TCP proxy listener on this local IP
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

	// Close all listeners for this IP (keys are "IP:port")
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

	// Remove from alias tracking
	for i, alias := range gw.aliases {
		if alias.Equal(ip) {
			gw.aliases = append(gw.aliases[:i], gw.aliases[i+1:]...)
			break
		}
	}
	gw.mu.Unlock()

	// Remove loopback alias
	gw.removeLoopbackAlias(ip)

	return gw.mappings.Unmap(ip)
}

// startProxy listens on localIP for TCP connections on configured ports
// and bridges them to the Pilot overlay.
func (gw *Gateway) startProxy(localIP net.IP, pilotAddr protocol.Addr) {
	// Add loopback alias so we can bind this IP
	gw.addLoopbackAlias(localIP)

	// Track alias for cleanup on Stop
	gw.mu.Lock()
	gw.aliases = append(gw.aliases, localIP)
	gw.mu.Unlock()

	for _, port := range gw.config.Ports {
		go gw.listenPort(localIP, port, pilotAddr)
	}
}

// addLoopbackAlias adds an IP address to the loopback interface.
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

// removeLoopbackAlias removes an IP address from the loopback interface.
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
		slog.Debug("gateway listen failed (expected if IP not yet routable)", "addr", addr, "err", err)
		return
	}

	gw.mu.Lock()
	key := fmt.Sprintf("%s:%d", localIP, port)
	gw.listeners[key] = ln
	gw.mu.Unlock()

	slog.Debug("gateway proxy listening", "addr", addr)

	for {
		tcpConn, err := ln.Accept()
		if err != nil {
			return
		}
		go gw.bridgeConnection(tcpConn, pilotAddr, port)
	}
}

// bridgeConnection bridges a local TCP connection to a Pilot stream.
func (gw *Gateway) bridgeConnection(tcpConn net.Conn, pilotAddr protocol.Addr, port uint16) {
	defer tcpConn.Close()

	pilotConn, err := gw.driver.DialAddr(pilotAddr, port)
	if err != nil {
		slog.Error("gateway dial failed", "pilot_addr", pilotAddr, "port", port, "err", err)
		return
	}
	defer pilotConn.Close()

	// Bidirectional copy — close both sides when either direction finishes
	// to unblock the other goroutine and prevent leaks
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(pilotConn, tcpConn)
		pilotConn.Close()
		done <- struct{}{}
	}()
	go func() {
		io.Copy(tcpConn, pilotConn)
		tcpConn.Close()
		done <- struct{}{}
	}()

	// Wait for both directions to finish
	<-done
	<-done
}
