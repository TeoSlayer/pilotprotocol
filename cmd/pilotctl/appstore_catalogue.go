// SPDX-License-Identifier: AGPL-3.0-or-later
//
// pilotctl appstore catalogue / install-by-id — fresh-user install path.
//
// A new user shouldn't need to know about bundle paths, manifests, or
// signatures. They run:
//
//	pilotctl appstore catalogue
//	pilotctl appstore install io.pilot.wallet
//
// and the tool fetches the bundle from a known-good URL, sha-checks it,
// extracts it, and hands it to the existing local-bundle install path
// (which validates the manifest + verifies the embedded ed25519 sig).
//
// The catalogue itself lives in the web4 repo at
// catalogue/catalogue.json and is fetched at runtime from
// defaultCatalogueURL. Override with $PILOT_APPSTORE_CATALOG_URL for
// local dev or for staging a release. See catalogue/README.md for the
// schema and publishing flow.
//
// Trust model (each layer checked at install time):
//
//   - User trusts pilotctl (project release pipeline).
//   - pilotctl fetches the catalogue from a URL hardcoded in this
//     binary — auditable in the public repo. Future: signed catalogue
//     verified against appstore.EmbeddedCatalogPubkey.
//   - Each catalogue entry pins the bundle's tarball sha256; a
//     compromised CDN can't substitute different bytes.
//   - The bundle's manifest carries an ed25519 signature against an
//     embedded publisher pubkey; the supervisor verifies it.

package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// defaultCatalogueURL points at the canonical catalogue.json on main.
// Override via $PILOT_APPSTORE_CATALOG_URL (use file:// for local
// staging, https:// for everything else; plain http:// is rejected
// off-loopback).
const defaultCatalogueURL = "https://raw.githubusercontent.com/TeoSlayer/pilotprotocol/main/catalogue/catalogue.json"

// catalogue is the parsed wire shape of catalogue.json. The schema is
// versioned (catalogue.json's "version" field) so future migrations
// can stay backward-compatible — pilotctl refuses any version it
// doesn't understand.
type catalogue struct {
	Version   int              `json:"version"`
	UpdatedAt string           `json:"updated_at"`
	Apps      []catalogueEntry `json:"apps"`
}

// catalogueEntry mirrors the JSON shape exactly. Adding a field here
// means adding it to catalogue.json AND to catalogue/README.md.
type catalogueEntry struct {
	ID          string `json:"id"`
	Version     string `json:"version"`
	Description string `json:"description"`
	BundleURL   string `json:"bundle_url"`
	BundleSHA   string `json:"bundle_sha256"`
}

// catalogueURL returns the URL pilotctl should fetch the catalogue
// from — env override wins so an operator can point at a staging
// file without rebuilding.
func catalogueURL() string {
	if u := os.Getenv("PILOT_APPSTORE_CATALOG_URL"); u != "" {
		return u
	}
	return defaultCatalogueURL
}

// loadCatalogue fetches + parses the catalogue. Errors out cleanly so
// `pilotctl appstore catalogue` and `install <id>` can both surface a
// useful diagnostic when the URL is wrong, offline, or returns
// garbage.
func loadCatalogue() (*catalogue, error) {
	u := catalogueURL()
	body, err := openURL(u)
	if err != nil {
		return nil, fmt.Errorf("fetch catalogue from %s: %w", u, err)
	}
	defer body.Close()
	data, err := io.ReadAll(io.LimitReader(body, 1<<20)) // 1 MiB cap
	if err != nil {
		return nil, fmt.Errorf("read catalogue body: %w", err)
	}
	var c catalogue
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse catalogue: %w", err)
	}
	if c.Version != 1 {
		return nil, fmt.Errorf("unsupported catalogue version %d (pilotctl understands version 1)", c.Version)
	}
	return &c, nil
}

func cmdAppStoreCatalogue(_ []string) {
	c, err := loadCatalogue()
	if err != nil {
		fatalHint("io_error",
			"check $PILOT_APPSTORE_CATALOG_URL (currently: "+catalogueURL()+")",
			"%v", err)
	}
	if jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(c.Apps)
		return
	}
	if len(c.Apps) == 0 {
		fmt.Println("catalogue is empty")
		return
	}
	fmt.Printf("Catalogue: %s (updated %s)\n\n", catalogueURL(), c.UpdatedAt)
	fmt.Println("Installable apps:")
	for _, e := range c.Apps {
		fmt.Printf("\n  %s  v%s\n", e.ID, e.Version)
		fmt.Printf("    %s\n", e.Description)
		fmt.Printf("    install: pilotctl appstore install %s\n", e.ID)
	}
}

// installSource tags how a bundle reached the install command.
// The install path uses this to switch between catalogue-signed and
// sideloaded trust regimes.
type installSource int

const (
	// installSourceCatalogue: target matched a catalogue entry; the
	// bundle was downloaded and sha-verified against the catalogue
	// pin. Goes through the standard signed-manifest install.
	installSourceCatalogue installSource = iota
	// installSourceLocal: target was a local directory path. No
	// publisher signature is expected; the install command applies
	// the sideload allow-list policy and plants `.sideloaded` so the
	// supervisor uses the sideloaded trust regime at runtime.
	installSourceLocal
)

// resolveInstallTarget turns the user's `target` arg into a local
// bundle directory the existing install code can consume, plus a
// source tag indicating which trust regime the bundle came from. If
// `target` matches a catalogue ID, the catalogue entry is fetched,
// verified, and unpacked. Otherwise `target` is treated as a local
// path and the caller is expected to apply sideload policy.
func resolveInstallTarget(target string) (string, installSource, error) {
	c, err := loadCatalogue()
	if err != nil {
		// Catalogue-lookup failure doesn't preclude a local-dir install
		// — fall through to the path branch so dev flows still work
		// offline. Surface a hint that the catalogue path failed so
		// the user knows their URL or env override might be the issue.
		fmt.Fprintf(os.Stderr, "warn: catalogue lookup failed (%v); proceeding with local-path interpretation\n", err)
	} else {
		for _, e := range c.Apps {
			if target == e.ID {
				dir, err := fetchAndUnpackBundle(e)
				return dir, installSourceCatalogue, err
			}
		}
	}
	info, err := os.Stat(target)
	if err == nil && info.IsDir() {
		return target, installSourceLocal, nil
	}
	return "", installSourceLocal, fmt.Errorf("not a catalogue ID or a bundle dir: %q (try `pilotctl appstore catalogue` to list installable apps)", target)
}

// fetchAndUnpackBundle downloads the catalogue entry's tarball,
// verifies its sha256 against the catalogue value (defence against a
// CDN substitute), and unpacks it into a tempdir whose path is
// returned for the install path to consume.
func fetchAndUnpackBundle(e catalogueEntry) (string, error) {
	if e.BundleSHA == "" || e.BundleSHA == "REPLACE_AT_RELEASE_TIME" {
		return "", fmt.Errorf("catalogue entry %s has placeholder sha256 — the release pipeline hasn't filled this in yet", e.ID)
	}
	fmt.Printf("fetching %s ...\n", e.BundleURL)
	body, err := openURL(e.BundleURL)
	if err != nil {
		return "", fmt.Errorf("fetch %s: %w", e.BundleURL, err)
	}
	defer body.Close()

	tmpTar, err := os.CreateTemp("", "pilot-bundle-*.tar.gz")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmpTar.Name())
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmpTar, h), body); err != nil {
		_ = tmpTar.Close()
		return "", fmt.Errorf("download body: %w", err)
	}
	if err := tmpTar.Close(); err != nil {
		return "", err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != e.BundleSHA {
		return "", fmt.Errorf("bundle sha256 mismatch: want=%s got=%s — the cdn served different bytes than the catalogue pinned", e.BundleSHA, got)
	}
	fmt.Printf("sha256 OK (%s)\n", got)

	unpackDir, err := os.MkdirTemp("", "pilot-bundle-unpack-*")
	if err != nil {
		return "", err
	}
	f, err := os.Open(tmpTar.Name())
	if err != nil {
		return "", err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()
	if err := untarUnder(gz, unpackDir); err != nil {
		return "", fmt.Errorf("untar: %w", err)
	}
	return unpackDir, nil
}

// openURL handles file:// (local dev), https://, and http:// only on
// loopback. Any non-loopback http:// is refused — install artifacts
// are too high-blast-radius to fetch over plaintext from anywhere we
// don't already trust.
func openURL(raw string) (io.ReadCloser, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "file":
		return os.Open(u.Path)
	case "https":
		return httpGet(raw)
	case "http":
		host := u.Hostname()
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return httpGet(raw)
		}
		return nil, fmt.Errorf("refusing plaintext http for non-localhost host %q (use https)", host)
	default:
		return nil, fmt.Errorf("unsupported url scheme %q", u.Scheme)
	}
}

func httpGet(raw string) (io.ReadCloser, error) {
	c := &http.Client{Timeout: 60 * time.Second}
	resp, err := c.Get(raw)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("http %d from %s", resp.StatusCode, raw)
	}
	return resp.Body, nil
}

// untarUnder writes every entry in r under dst, refusing any path
// that resolves outside dst (mirrors the supervisor's
// resolveUnder guard on manifest.binary.path).
func untarUnder(r io.Reader, dst string) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		clean := filepath.Clean(hdr.Name)
		if strings.HasPrefix(clean, "..") || strings.Contains(clean, "/../") {
			return fmt.Errorf("refusing entry with traversal: %q", hdr.Name)
		}
		out := filepath.Join(dst, clean)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(out, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode)&0o777)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				_ = f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
		default:
			// Skip symlinks, devices, etc. — neither needed for a
			// pilot app bundle nor safe to write blindly.
		}
	}
}
