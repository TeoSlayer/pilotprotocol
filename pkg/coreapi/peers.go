// SPDX-License-Identifier: AGPL-3.0-or-later

package coreapi

import (
	"context"
	"crypto/ed25519"
	"net"
)

// PeerInfo is the directory record for a remote node. Returned by
// PeerResolver.Resolve and PeerResolver.ListByNetwork.
type PeerInfo struct {
	NodeID    uint32
	Addr      Addr
	Endpoint  *net.UDPAddr // best-known reachable endpoint, or nil
	PubKey    ed25519.PublicKey
	Public    bool
	Hostname  string
	RelayOnly bool
}

// PeerResolver is the L8 directory surface. The daemon's
// implementation talks to the registry over the bootstrap TCP
// side-channel (see 01-LAYERS §L8).
type PeerResolver interface {
	Resolve(ctx context.Context, nodeID uint32) (PeerInfo, error)
	ResolveHostname(ctx context.Context, name string) (uint32, error)
	ListByNetwork(ctx context.Context, networkID uint32) ([]PeerInfo, error)
}
