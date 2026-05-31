//go:build darwin

package daemon

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// resolveProcessName is a no-op on Darwin — Xucred doesn't expose PID.
// IPC whitelist is Linux-only (PILOT-346).
func resolveProcessName(pid int32) string { return "" }

// checkPeerUID — Darwin variant. Uses LOCAL_PEERCRED + GetsockoptXucred,
// the BSD equivalent of Linux SO_PEERCRED, to retrieve the effective UID
// of the connected peer. Returns 0 for PID — Darwin Xucred does not
// expose the peer PID, so IPC whitelist is Linux-only (PILOT-346).
func checkPeerUID(conn net.Conn) (int32, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("IPC: not a unix socket")
	}
	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("IPC: SyscallConn: %w", err)
	}
	var xucred *unix.Xucred
	var getErr error
	ctrlErr := rawConn.Control(func(fd uintptr) {
		xucred, getErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	})
	if ctrlErr != nil {
		return 0, fmt.Errorf("IPC: Control: %w", ctrlErr)
	}
	if getErr != nil {
		return 0, fmt.Errorf("IPC: LOCAL_PEERCRED: %w", getErr)
	}
	if xucred.Uid != uint32(os.Getuid()) {
		return 0, fmt.Errorf("IPC: peer UID %d != daemon UID %d", xucred.Uid, os.Getuid())
	}
	return 0, nil
}
