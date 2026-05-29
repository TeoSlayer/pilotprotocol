//go:build linux

package daemon

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// checkPeerUID verifies that a Unix-domain socket connection comes from
// the same Unix UID as the daemon. Linux variant: SO_PEERCRED + Ucred.
//
// Returns nil if the peer UID matches the daemon's UID, or an error
// if the socket is not Unix-domain, the syscall failed, or the peer
// UID differs. This is the primary IPC access control for PILOT-246.
func checkPeerUID(conn net.Conn) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("IPC: not a unix socket")
	}
	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("IPC: SyscallConn: %w", err)
	}
	var ucred *unix.Ucred
	var getErr error
	ctrlErr := rawConn.Control(func(fd uintptr) {
		ucred, getErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if ctrlErr != nil {
		return fmt.Errorf("IPC: Control: %w", ctrlErr)
	}
	if getErr != nil {
		return fmt.Errorf("IPC: SO_PEERCRED: %w", getErr)
	}
	if ucred.Uid != uint32(os.Getuid()) {
		return fmt.Errorf("IPC: peer UID %d != daemon UID %d", ucred.Uid, os.Getuid())
	}
	return nil
}
