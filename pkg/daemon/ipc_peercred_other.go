//go:build !linux && !darwin

package daemon

import (
	"fmt"
	"net"
)

// resolveProcessName is a no-op on unsupported platforms.
// IPC whitelist is Linux-only (PILOT-346).
func resolveProcessName(pid int32) string { return "" }

// checkPeerUID — fallback for non-Linux, non-Darwin builds. Pilot does
// not officially support these platforms; the IPC peer-UID check is a
// no-op so the build keeps compiling. Returns 0 for PID.
func checkPeerUID(conn net.Conn) (int32, error) {
	if _, ok := conn.(*net.UnixConn); !ok {
		return 0, fmt.Errorf("IPC: not a unix socket")
	}
	return 0, nil
}
