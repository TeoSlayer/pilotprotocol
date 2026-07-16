// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Per-app "store listing" detail document — the human-app-store surface
// (structured description, changelog, vendor, screenshots, size, source
// URL) that is deliberately kept OUT of the signed manifest.
//
// The manifest (app-store/pkg/manifest) is security-critical and
// re-verified on every supervisor rescan; bloating it with marketing
// metadata would expand the signed surface for no security benefit.
// Instead each catalogue entry points at a metadata.json via
// catalogueEntry.MetadataURL and pins its bytes with MetadataSHA — the
// exact same trust model the bundle tarball already gets. `pilotctl
// appstore view` fetches this lazily; the catalogue listing/install hot
// path never touches it.
//
// Every field is optional so a partial document still renders. Adding a
// field here means adding it to catalogue/apps/<id>/metadata.json AND to
// catalogue/README.md.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
)

// maxMetadataBytes bounds a hostile or runaway detail doc. Generous for
// text (a long description + full changelog is a few KiB) while keeping
// the fetch cheap and DoS-resistant, mirroring loadCatalogue's 1 MiB cap.
const maxMetadataBytes = 256 << 10 // 256 KiB

// appMetadata is the parsed wire shape of metadata.json. SchemaVersion is
// independent of the catalogue's version so the detail format can evolve
// on its own cadence.
type appMetadata struct {
	SchemaVersion int            `json:"schema_version"`
	ID            string         `json:"id"`
	DisplayName   string         `json:"display_name,omitempty"`
	Tagline       string         `json:"tagline,omitempty"`
	DescriptionMD string         `json:"description_md,omitempty"`
	Vendor        *mdVendor      `json:"vendor,omitempty"`
	Homepage      string         `json:"homepage,omitempty"`
	SourceURL     string         `json:"source_url,omitempty"`
	License       string         `json:"license,omitempty"`
	Categories    []string       `json:"categories,omitempty"`
	Keywords      []string       `json:"keywords,omitempty"`
	IconURL       string         `json:"icon_url,omitempty"`
	Screenshots   []mdScreenshot `json:"screenshots,omitempty"`
	Size          *mdSize        `json:"size,omitempty"`
	Compat        *mdCompat      `json:"compat,omitempty"`
	Methods       []mdMethod     `json:"methods,omitempty"`
	Changelog     []mdChangelog  `json:"changelog,omitempty"`
	Links         []mdLink       `json:"links,omitempty"`

	// ProductDemo is the optional, example-driven usage guide (see
	// appstore_demo.go). When present it is rendered at the last step of a
	// successful install and written as a SKILL.md; when absent (the common
	// case) install is unaffected. It rides inside this already-sha-verified
	// doc, so it adds no new trust surface.
	ProductDemo *ProductDemo `json:"product_demo,omitempty"`

	// Reviews is RESERVED for the future community-reviews service. It is
	// parsed if present but pilotctl never writes it today — reviews are a
	// separate, signed, dynamic service (see catalogue/README.md), not
	// static git-served data. Kept here so `view` output and the JSON
	// shape are stable when the service lands.
	Reviews *mdReviews `json:"reviews,omitempty"`

	PublishedAt string `json:"published_at,omitempty"`
	UpdatedAt   string `json:"updated_at,omitempty"`
}

type mdVendor struct {
	Name            string `json:"name,omitempty"`
	URL             string `json:"url,omitempty"`
	Contact         string `json:"contact,omitempty"`
	PublisherPubkey string `json:"publisher_pubkey,omitempty"` // ties the listing to manifest.store.publisher
}

type mdScreenshot struct {
	URL     string `json:"url"`
	Caption string `json:"caption,omitempty"`
}

type mdSize struct {
	BundleBytes    int64 `json:"bundle_bytes,omitempty"`    // compressed download
	InstalledBytes int64 `json:"installed_bytes,omitempty"` // approx unpacked footprint
}

type mdCompat struct {
	MinPilotVersion string   `json:"min_pilot_version,omitempty"`
	Runtimes        []string `json:"runtimes,omitempty"`
}

type mdMethod struct {
	Name    string `json:"name"`
	Summary string `json:"summary,omitempty"`
}

type mdChangelog struct {
	Version string   `json:"version"`
	Date    string   `json:"date,omitempty"`
	Notes   []string `json:"notes,omitempty"`
}

type mdLink struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

// mdReviews is the reserved aggregate shape for the future reviews
// service. Read-only snapshot; pilotctl does not compute or submit it yet.
type mdReviews struct {
	Average      float64 `json:"average,omitempty"`
	Count        int     `json:"count,omitempty"`
	Distribution []int   `json:"distribution,omitempty"` // [1★..5★] counts
}

// loadAppMetadata fetches the per-app detail doc named by the catalogue
// entry and, when the entry carries a pin, verifies the bytes against
// metadata_sha256 (the same CDN-substitution defence the bundle gets).
//
// An entry with no MetadataURL returns (nil, nil): "no extended detail",
// not an error — that is how a v1 entry, or a v2 entry that simply hasn't
// published a listing yet, degrades. A present-but-unpinned URL is
// fetched but logged as unverified by the caller; a present pin that
// mismatches is a hard error (someone served different bytes than the
// catalogue vouched for).
func loadAppMetadata(e catalogueEntry) (*appMetadata, error) {
	if e.MetadataURL == "" {
		return nil, nil
	}
	body, err := openURL(e.MetadataURL)
	if err != nil {
		return nil, fmt.Errorf("fetch metadata from %s: %w", e.MetadataURL, err)
	}
	defer body.Close()
	data, err := io.ReadAll(io.LimitReader(body, maxMetadataBytes))
	if err != nil {
		return nil, fmt.Errorf("read metadata body: %w", err)
	}
	if e.MetadataSHA != "" && e.MetadataSHA != "REPLACE_AT_RELEASE_TIME" {
		sum := sha256.Sum256(data)
		got := hex.EncodeToString(sum[:])
		if got != e.MetadataSHA {
			return nil, fmt.Errorf("metadata sha256 mismatch for %s: want=%s got=%s — the host served different bytes than the catalogue pinned", e.ID, e.MetadataSHA, got)
		}
	}
	var m appMetadata
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse metadata: %w", err)
	}
	// Cross-check the id so a mis-pinned or mis-uploaded doc can't masquerade
	// as a different app's listing. An empty id in the doc is tolerated
	// (the catalogue entry is authoritative).
	if m.ID != "" && m.ID != e.ID {
		return nil, fmt.Errorf("metadata id %q does not match catalogue id %q", m.ID, e.ID)
	}
	return &m, nil
}

// metadataPinned reports whether the entry carries a usable sha pin, so
// callers can label the detail doc as verified vs unverified.
func metadataPinned(e catalogueEntry) bool {
	return e.MetadataSHA != "" && e.MetadataSHA != "REPLACE_AT_RELEASE_TIME"
}
