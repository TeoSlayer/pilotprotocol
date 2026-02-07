package secure

import (
	"web4/pkg/driver"
	"web4/pkg/protocol"
)

// Dial connects to a remote agent's secure port and performs the handshake.
// Returns an encrypted connection that implements net.Conn.
func Dial(d *driver.Driver, addr protocol.Addr) (*SecureConn, error) {
	conn, err := d.DialAddr(addr, protocol.PortSecure)
	if err != nil {
		return nil, err
	}

	sc, err := Handshake(conn, false)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return sc, nil
}
