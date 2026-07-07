# Pilot app store catalogue

This directory holds the app store catalogue:

- `catalogue.json` — the **index**: the list of apps installable via
  `pilotctl appstore install <app-id>`. Kept lightweight; read on every
  `catalogue` and `install`.
- `apps/<id>/metadata.json` — the per-app **detail document** ("store
  listing"): structured description, changelog, vendor, size, source URL,
  screenshots. Fetched lazily, only by `pilotctl appstore view <id>`.

The split mirrors a human app store (a cheap list vs a rich detail page) and
keeps the install hot path small. Each index entry sha-pins its detail doc the
same way it pins the bundle tarball.

## Index schema (`catalogue.json`)

The index is **versioned**. Version 1 is the original flat shape; version 2
adds optional teaser fields plus a pin to the detail doc. `pilotctl`
understands both — a v1 catalogue still loads, and an older `pilotctl`
ignores the v2 fields. **Always set `"version": 2` when using any v2 field.**

```json
{
  "version": 2,
  "updated_at": "<RFC3339 timestamp>",
  "apps": [
    {
      "id": "<reverse-DNS app id, must match manifest.id>",
      "version": "<semver>",
      "description": "<one-line teaser, shown in `pilotctl appstore catalogue`>",
      "bundle_url": "https://<host>/<path>.tar.gz",
      "bundle_sha256": "<hex sha256 of the tarball>",

      "bundles": {
        "linux/amd64":  {"bundle_url": "https://<host>/<path>-linux-amd64.tar.gz",  "bundle_sha256": "<hex>"},
        "linux/arm64":  {"bundle_url": "https://<host>/<path>-linux-arm64.tar.gz",  "bundle_sha256": "<hex>"},
        "darwin/arm64": {"bundle_url": "https://<host>/<path>-darwin-arm64.tar.gz", "bundle_sha256": "<hex>"},
        "darwin/amd64": {"bundle_url": "https://<host>/<path>-darwin-amd64.tar.gz", "bundle_sha256": "<hex>"}
      },

      "display_name": "<human name, optional>",
      "vendor": "<vendor name, optional>",
      "categories": ["<optional>", "<tags>"],
      "bundle_size": 0,
      "source_url": "https://github.com/<org>/<repo>",
      "license": "<SPDX id>",

      "metadata_url": "https://<host>/apps/<id>/metadata.json",
      "metadata_sha256": "<hex sha256 of metadata.json>",

      "renamed_to": "<canonical id>, optional",
      "hidden": false
    }
  ]
}
```

Everything from `display_name` down is optional (`omitempty`). The five v1
fields stay required. `pilotctl` decodes the index directly into
`catalogueEntry` in `cmd/pilotctl/appstore_catalogue.go` — any field added
here must also land there.

### Renaming an app (`renamed_to` + `hidden`)

Both are optional v2 fields (**keep `"version": 2`**). To rename an app id
`old → new` without breaking existing installs, do NOT delete the old entry —
the daemon supervisor pins each installed app's publisher key from its
catalogue entry and **fail-closes (stops) an installed app whose id has no
pin**. Instead, replace the old entry's body with a **tombstone**: keep `id`
and `publisher` (so existing installs keep their pin and keep running), set
`"renamed_to": "<new id>"`, and set `"hidden": true`. Drop `bundle_url` /
`bundles` / `metadata_url` (the tombstone is not installable) and delete the old
`apps/<old-id>/` detail dir. Then add the full new entry under the new id and
re-sign.

A bundles-aware `pilotctl` then, for the old id: omits it from `catalogue`,
and on `install`/`view`/`call` prints a deprecation warning and routes to
`renamed_to`. `hidden` alone (without `renamed_to`) just omits an entry from the
listing while keeping it resolvable. Older clients ignore both fields (they see
a normal, pin-only entry). One hop only — a `renamed_to` that points at another
tombstone is a bug and is not chased.

`bundles` is the per-platform map keyed by `"os/arch"`. It is an **optional v2
field — keep `"version": 2`, do NOT bump to 3.** `loadCatalogue` fail-closes on
any version other than 1 or 2, so a version-3 catalogue is rejected wholesale by
every client; `bundles` follows the same optional-field rule as the other v2
additions. When present, a bundles-aware client (`pilotctl` ≥ v1.12.0) picks the
host's entry; older clients ignore the map and fetch the top-level `bundle_url`.
`bundle_url` / `bundle_sha256` stay as the back-compat primary (linux/amd64) so a
`bundles`-bearing entry still installs on pre-v1.12 `pilotctl` for that one
platform. An entry that omits `bundles` behaves exactly as before (single-platform,
top-level `bundle_url`).

## Detail schema (`apps/<id>/metadata.json`)

Fetched only by `pilotctl appstore view <id>`, verified against the index's
`metadata_sha256`. Every field is optional so a partial document still
renders. Decoded into `appMetadata` in `cmd/pilotctl/appstore_metadata.go`.

```json
{
  "schema_version": 1,
  "id": "<must match the catalogue id>",
  "display_name": "<human name>",
  "tagline": "<short one-liner>",
  "description_md": "<structured/long description (markdown)>",
  "vendor": { "name": "", "url": "", "contact": "", "publisher_pubkey": "ed25519:..." },
  "homepage": "https://...",
  "source_url": "https://github.com/<org>/<repo>",
  "license": "<SPDX id>",
  "categories": ["..."],
  "keywords": ["..."],
  "icon_url": "https://...",
  "screenshots": [{ "url": "https://...", "caption": "" }],
  "size": { "bundle_bytes": 0, "installed_bytes": 0 },
  "compat": { "min_pilot_version": "1.0.0", "runtimes": ["go"] },
  "methods": [{ "name": "app.method", "summary": "" }],
  "changelog": [{ "version": "X.Y.Z", "date": "YYYY-MM-DD", "notes": ["..."] }],
  "links": [{ "label": "Docs", "url": "https://..." }],
  "reviews": null,
  "published_at": "<RFC3339>",
  "updated_at": "<RFC3339>"
}
```

`reviews` is **reserved** — pilotctl parses it but never writes it. Community
reviews are a separate, signed, dynamic service (not static git data); the
slot exists so the `view` output and JSON shape stay stable when it lands.

## What `view` shows

`pilotctl appstore view <id>` merges three bands and labels their provenance:

- **catalogue** — the index teaser (publisher-attested, sha-anchored),
- **metadata** — the detail doc above (publisher copy),
- **local-manifest** — verified install facts when the app is installed
  (integrity, real on-disk size, granted permissions, methods).

It works whether or not the app is installed, and whether or not it is in the
catalogue (a sideloaded app renders from local facts alone). Publisher copy and
verified install facts are kept visually distinct so they are never conflated.
Add `--all-changelog` for the full version history; `--json` for the merged
`appViewReport`.

## Where pilotctl loads it from

By default, `pilotctl appstore catalogue` and `pilotctl appstore install
<id>` fetch this file from the URL hardcoded in `appstore_catalogue.go`
(`defaultCatalogueURL`, pointing at this file's raw URL on `main`). Override
with `PILOT_APPSTORE_CATALOG_URL` for local dev or for staging a release:

```bash
# point at a local file while staging a release
export PILOT_APPSTORE_CATALOG_URL=file:///path/to/staging/catalogue.json
pilotctl appstore catalogue
```

`http://` is rejected unless the host is loopback (no plaintext install
from a remote — operators relying on a catalogue do so over `https` only).

## Publishing a new app version

1. Bump the version in the app's `manifest.json`. Re-sign:
   ```bash
   pilotctl appstore sign --key /secure/path/publisher.key path/to/manifest.json
   ```
2. Build the bundle dir (`manifest.json` + `bin/<name>`) and tar it:
   ```bash
   tar czf io.pilot.wallet-X.Y.Z.tar.gz manifest.json bin/wallet
   ```
3. Compute the sha256:
   ```bash
   shasum -a 256 io.pilot.wallet-X.Y.Z.tar.gz
   ```
4. Upload the tarball as a release artifact (`gh release upload` or
   equivalent — GitHub releases, Cloudflare R2, anywhere reachable over
   HTTPS).
5. Write or update the detail doc at `apps/<id>/metadata.json` (bump its
   `changelog`, `version`, `size`, `updated_at`). Then recompute its sha:
   ```bash
   shasum -a 256 apps/<id>/metadata.json
   ```
6. Update this `catalogue.json` with the new `version`, `bundle_url`,
   `bundle_sha256`, the teaser fields, **and** the new `metadata_sha256`
   from step 5. Commit everything together — the index pin and the detail
   doc must change in the same commit or `view` will reject a stale pin.

   > **Pin discipline:** `metadata_sha256` must be the sha256 of the exact
   > committed `metadata.json` bytes. Edit the doc, then recompute — never
   > the other way round. A mismatch makes `view` fall back to the teaser
   > and warn.
7. **Re-sign the catalogue** (the signature covers the exact `catalogue.json`
   bytes, so it must be regenerated on every edit — including the
   `metadata_sha256` pin change from step 6):
   ```bash
   pilotctl appstore sign-catalogue --key /secure/path/catalog-signing.key \
     catalogue/catalogue.json
   ```
   This writes `catalogue.json.sig` (detached, base64 ed25519). Commit
   `catalogue.json`, `catalogue.json.sig`, **and** the updated
   `apps/<id>/metadata.json` together. The change goes live the moment they
   land on `main` and the raw URLs serve the new bytes — no daemon restart,
   no pilotctl release.

`pilotctl` fetches `catalogue.json` **and** `catalogue.json.sig` and
verifies the signature against the embedded catalogue public key before
trusting any entry. An unsigned, missing-signature, or tampered catalogue
is refused (fail-closed).

## Catalogue signing key

The catalogue is signed with a dedicated ed25519 key, separate from any
app-publisher key. The **private** key is held by the release pipeline and
is never committed. The **public** key is compiled into pilotctl and the
daemon at `internal/catalogtrust` (`publicKeyB64`) and can be rotated at
build time without a code change:

```bash
go build -ldflags \
  "-X github.com/TeoSlayer/pilotprotocol/internal/catalogtrust.publicKeyB64=<new-b64-pubkey>" \
  ./cmd/pilotctl ./cmd/daemon
```

To rotate: generate a new keypair, store the private key securely, update
the embedded public key (source default or `-ldflags`), and re-sign the
catalogue. `sign-catalogue` refuses to sign with a key that doesn't match
the embedded public key, so a mismatch is caught before publishing a dead
signature.

## Trust model

| Layer | Trust anchor | Verifies |
|---|---|---|
| User trusts pilotctl | Project release pipeline (signed pilotctl binary) | The catalogue URL is correct |
| pilotctl trusts the catalogue | Detached ed25519 signature against the embedded catalogue key (`internal/catalogtrust`) | The app list (IDs → bundle URLs + SHAs) is authentic; a substituted catalogue is rejected |
| pilotctl trusts the bundle | Embedded `bundle_sha256` matches downloaded bytes | A CDN substitute is rejected |
| pilotctl trusts the detail doc | Index `metadata_sha256` matches fetched `metadata.json` | A substituted listing is rejected (`view` falls back to the teaser) |
| Daemon trusts the manifest | Embedded ed25519 publisher pubkey verifies the signature | The bundle's manifest hasn't been tampered with |

Every layer is checked at install/view time, and the manifest signature is
re-verified at every supervisor rescan (every 2 s). The detail doc carries no
authority of its own — it is display metadata, anchored only by the index pin,
and `view` keeps it visually separate from verified install facts.
