//go:build darwin

package daemon

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// checkPeerUID — Darwin variant. Uses LOCAL_PEERCRED + GetsockoptXucred,
// the BSD equivalent of Linux SO_PEERCRED, to retrieve the effective UID
// of the connected peer.
func checkPeerUID(conn net.Conn) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("IPC: not a unix socket")
	}
	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("IPC: SyscallConn: %w", err)
	}
	var xucred *unix.Xucred
	var getErr error
	ctrlErr := rawConn.Control(func(fd uintptr) {
		xucred, getErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	})
	if ctrlErr != nil {
		return fmt.Errorf("IPC: Control: %w", ctrlErr)
	}
	if getErr != nil {
		return fmt.Errorf("IPC: LOCAL_PEERCRED: %w", getErr)
	}
	if xucred.Uid != uint32(os.Getuid()) {
		return fmt.Errorf("IPC: peer UID %d != daemon UID %d", xucred.Uid, os.Getuid())
	}
	return nil
}
