// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package beacon

import (
	"context"
	"net"
	"syscall"
)

// soReusePort is the Linux value for SO_REUSEPORT. The Go stdlib syscall
// package doesn't export it on Linux (only Darwin), so we declare it
// here to avoid taking a dependency on golang.org/x/sys/unix.
const soReusePort = 0xf

// listenReusePort binds a UDP socket to addr with SO_REUSEPORT enabled,
// which lets multiple sockets bind to the same port. The kernel
// flow-hashes incoming packets across all such sockets — true parallel
// receive without user-space coordination. We spawn one reader per
// CPU core, each on its own socket, eliminating the single-reader
// bottleneck of plain net.ListenUDP.
func listenReusePort(addr string) (*net.UDPConn, error) {
	lc := &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var sockErr error
			err := c.Control(func(fd uintptr) {
				sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, 1)
			})
			if err != nil {
				return err
			}
			return sockErr
		},
	}
	pc, err := lc.ListenPacket(context.Background(), "udp", addr)
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

// MaxReusePortShards is unlimited on Linux — the kernel flow-hashes
// across all open SO_REUSEPORT sockets. 0 means "use the configured
// 2× NumCPU default in ListenAndServe."
const MaxReusePortShards = 0
