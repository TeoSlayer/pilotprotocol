// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build dev

package compat

// In dev builds, development root certs (dev-*.pem) are trusted
// alongside production roots. Production builds skip them.
func init() { skipDevPems = false }
