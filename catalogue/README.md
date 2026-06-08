# Pilot app store catalogue

This directory holds `catalogue.json` — the canonical list of apps installable via
`pilotctl appstore install <app-id>`.

## Schema

```json
{
  "version": 1,
  "updated_at": "<RFC3339 timestamp>",
  "apps": [
    {
      "id": "<reverse-DNS app id, must match manifest.id>",
      "version": "<semver>",
      "description": "<one-line, shown in `pilotctl appstore catalogue`>",
      "bundle_url": "https://<host>/<path>.tar.gz",
      "bundle_sha256": "<hex sha256 of the tarball>"
    }
  ]
}
```

The schema is intentionally flat — `pilotctl` decodes it directly into
`catalogueEntry` in `cmd/pilotctl/appstore_catalogue.go`. Any field added
here must also land there.

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
5. Update this `catalogue.json` with the new `version`, `bundle_url`, and
   `bundle_sha256`. Commit. The change goes live the moment the commit
   lands on `main` and the raw URL serves the new bytes — no daemon
   restart, no pilotctl release.

## Trust model

| Layer | Trust anchor | Verifies |
|---|---|---|
| User trusts pilotctl | Project release pipeline (signed pilotctl binary) | The catalogue URL is correct |
| pilotctl trusts the catalogue | Future: signed against `EmbeddedCatalogPubkey`; today: the raw URL itself | App IDs map to specific bundle URLs + SHAs |
| pilotctl trusts the bundle | Embedded `bundle_sha256` matches downloaded bytes | A CDN substitute is rejected |
| Daemon trusts the manifest | Embedded ed25519 publisher pubkey verifies the signature | The bundle's manifest hasn't been tampered with |

Every layer is checked at install time, and the manifest signature is
re-verified at every supervisor rescan (every 2 s).
