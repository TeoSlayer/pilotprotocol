// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/routing"
)

// Pre-extraction names re-exposed as thin shims over routing/.
// Canonical definitions live at pkg/daemon/routing/select.go (L4).

func isUnreachableBeaconHost(host string) bool  { return routing.IsUnreachableBeaconHost(host) }
func filterUnreachable(addrs []string) []string { return routing.FilterUnreachable(addrs) }
func parseBeaconList(s string) []string         { return routing.ParseBeaconList(s) }
func pickBeacon(list []string, key []byte) string {
	return routing.PickBeacon(list, key)
}
func firstBeacon(s string) string { return routing.FirstBeacon(s) }
func mergeBeaconLists(bootstrap, discovered []string) []string {
	return routing.MergeBeaconLists(bootstrap, discovered)
}
