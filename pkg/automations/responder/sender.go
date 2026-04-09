package responder

import (
	"fmt"

	"github.com/TeoSlayer/pilotprotocol/pkg/dataexchange"
	"github.com/TeoSlayer/pilotprotocol/pkg/driver"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// SendReply sends a plain-text message back to toAddr via the local pilot daemon.
// It dials the remote node's data-exchange port (1001), sends a TypeText frame,
// and waits for the ACK before closing to ensure delivery.
func SendReply(socketPath string, toAddr string, message string) error {
	addr, err := protocol.ParseAddr(toAddr)
	if err != nil {
		return fmt.Errorf("parse sender address %q: %w", toAddr, err)
	}

	d, err := driver.Connect(socketPath)
	if err != nil {
		return fmt.Errorf("connect to daemon at %s: %w", socketPath, err)
	}
	defer d.Close()

	client, err := dataexchange.Dial(d, addr)
	if err != nil {
		return fmt.Errorf("dial %s (data-exchange port %d): %w", toAddr, protocol.PortDataExchange, err)
	}
	defer client.Close()

	if err := client.SendText(message); err != nil {
		return fmt.Errorf("send reply to %s: %w", toAddr, err)
	}

	// Wait for ACK to ensure the message was fully received before closing.
	client.Recv() //nolint:errcheck // ACK is best-effort; ignore timeout/EOF
	return nil
}
