//go:build !linux && !darwin

package daemon

import (
	"fmt"
	"net"
)

// checkPeerUID — fallback for non-Linux, non-Darwin builds. Pilot does
// not officially support these platforms; the IPC peer-UID check is a
// no-op so the build keeps compiling.
func checkPeerUID(conn net.Conn) error {
	if _, ok := conn.(*net.UnixConn); !ok {
		return fmt.Errorf("IPC: not a unix socket")
	}
	return nil
}
