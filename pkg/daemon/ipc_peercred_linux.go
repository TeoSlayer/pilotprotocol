//go:build linux

package daemon

import (
	"fmt"
	"net"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// checkPeerUID verifies that a Unix-domain socket connection comes from
// the same Unix UID as the daemon. Linux variant: SO_PEERCRED + Ucred.
//
// Returns the peer PID (for whitelist checks) and nil if the peer UID
// matches the daemon's UID, or an error if the socket is not Unix-domain,
// the syscall failed, or the peer UID differs. This is the primary IPC
// access control for PILOT-246.
func checkPeerUID(conn net.Conn) (int32, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("IPC: not a unix socket")
	}
	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("IPC: SyscallConn: %w", err)
	}
	var ucred *unix.Ucred
	var getErr error
	ctrlErr := rawConn.Control(func(fd uintptr) {
		ucred, getErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if ctrlErr != nil {
		return 0, fmt.Errorf("IPC: Control: %w", ctrlErr)
	}
	if getErr != nil {
		return 0, fmt.Errorf("IPC: SO_PEERCRED: %w", getErr)
	}
	if ucred.Uid != uint32(os.Getuid()) {
		return 0, fmt.Errorf("IPC: peer UID %d != daemon UID %d", ucred.Uid, os.Getuid())
	}
	return int32(ucred.Pid), nil
}

// resolveProcessName reads /proc/<pid>/comm and returns the process name
// (trimmed). Returns empty string on any error (process gone, permission
// denied, etc.). Used for IPC whitelist matching (PILOT-346).
func resolveProcessName(pid int32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
