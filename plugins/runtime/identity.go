// SPDX-License-Identifier: AGPL-3.0-or-later

package runtime

import (
	"crypto/ed25519"
	"errors"

	"github.com/TeoSlayer/pilotprotocol/pkg/coreapi"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
)

// daemonIdentity adapts daemon's identity state to coreapi.Identity
// for plugin Deps. Methods that need the underlying *crypto.Identity
// (PublicKey, Sign) go through Daemon.Identity().

type daemonIdentity struct{ d *daemon.Daemon }

func (i daemonIdentity) NodeID() uint32        { return i.d.NodeID() }
func (i daemonIdentity) Address() coreapi.Addr { return i.d.Addr() }

func (i daemonIdentity) PublicKey() ed25519.PublicKey {
	id := i.d.Identity()
	if id == nil {
		return nil
	}
	return id.PublicKey
}

func (i daemonIdentity) Sign(msg []byte) ([]byte, error) {
	id := i.d.Identity()
	if id == nil {
		return nil, errors.New("identity not initialized")
	}
	return id.Sign(msg), nil
}

var _ coreapi.Identity = daemonIdentity{}
