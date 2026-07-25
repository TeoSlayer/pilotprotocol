//go:build !linux && !darwin

package daemon

import (
	"fmt"
	"net"
)

func resolveProcessName(pid int32) string { return "" }

func checkPeerUID(conn net.Conn) (int32, error) {
	if _, ok := conn.(*net.UnixConn); !ok {
		return 0, fmt.Errorf("IPC: not a unix socket")
	}
	return 0, fmt.Errorf("IPC: peer credential check unsupported on this platform")
}
