// SPDX-License-Identifier: AGPL-3.0-or-later

package keyexchange

import "errors"

// errNoVerify mirrors the pre-extraction string ("no verify function")
// from tunnel.go's getPeerPubKey. Tests assert on this exact wording.
var errNoVerify = errors.New("no verify function")

var errPubKeyUnresolved = errors.New("peer pubkey unresolved (negatively cached)")
