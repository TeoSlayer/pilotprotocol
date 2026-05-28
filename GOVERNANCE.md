# Governance

Pilot Protocol is an open-source project. This document describes how the
project is maintained, how decisions are made, and how to report issues.

## Maintainers

The Pilot Protocol repository is maintained by:

- Teodor Calin
- Alex Godoroja

The maintainers set technical direction and operate the managed service.

Commit access is restricted to the maintainers. Direct pushes to `main`
are normal operation, not an exception.

## Contributions

External contributions are welcome through GitHub pull requests. The
maintainers review and merge.

- No contributor license agreement is required.
- By submitting a pull request, you license your contribution under the
  repository's license.
- Discussion happens on GitHub issues and pull requests.

## Decision-Making

Technical decisions are made by the maintainers. Open discussion is
encouraged via GitHub issues; the final call rests with the maintainers.
Material architectural changes are published in commit messages and, where
appropriate, in `docs/` or the whitepaper.

## Security Disclosures

Report security issues privately to `founders@pilotprotocol.network`.
Do not open a public issue until a fix has been released.

## Commercial and Partnership Inquiries

For the managed service, enterprise licensing, or partnership inquiries,
contact `founders@pilotprotocol.network`.

## SDK versioning and release cadence

Three official SDKs ship under the Pilot Protocol brand:

- `sdk-node` — published to npm as `pilotprotocol`
- `sdk-python` — published to PyPI as `pilotprotocol`
- `sdk-swift` — published as a Swift Package, distributed via GitHub releases

These SDKs share a wire protocol and a maintainer team, and they target API
parity (see [docs/SDK_PARITY.md](docs/SDK_PARITY.md)). The following policy
applies to all three.

### Semver alignment

- All three SDKs share the same `MAJOR.MINOR` line at any given time. Patch
  versions diverge — a Swift-only crash fix bumps only `sdk-swift`'s patch
  number.
- A wire-protocol change or daemon RPC schema change is a `MINOR` bump. All
  three SDKs cut a matching `MINOR` release on the same day.
- A breaking change to any SDK's public API is a `MAJOR` bump on that SDK.
  We avoid these — at most one breaking change per `MAJOR`, and only when no
  additive path exists.

### Coordinated releases

When a `MINOR` train cuts:

1. The `pilotprotocol` repo tags the wire-protocol version first.
2. The three SDK repos rebase, bump their `MINOR` to match, and release in
   parallel.
3. Each SDK's `CHANGELOG.md` cross-links the matching release of the other two.
4. The parity matrix (see [docs/SDK_PARITY.md](docs/SDK_PARITY.md)) is
   re-generated against the new commits — any new gap must be classified
   `intentional` (with a rationale) or filed as a follow-up ticket before
   the train ships.

### Deprecation policy

A symbol scheduled for removal must be marked deprecated for at least one
`MINOR` release before it disappears, using the native idiom per language:

- **Node:** `@deprecated` JSDoc on the symbol; TypeScript surfaces a warning.
- **Python:** `warnings.warn(DeprecationWarning(...))` at call time; mention
  in the docstring.
- **Swift:** `@available(*, deprecated, message: "...")` attribute.

Deprecations announce themselves in the SDK's `CHANGELOG.md` and the
corresponding section of the parity matrix.

### Release cadence target

A `MINOR` train every month is the target. Patch releases ship as needed.
We do not gate the train on a calendar — if there's nothing meaningful to
release, the train skips a month.

## Succession

If both maintainers become unavailable, the repository will be archived
with public notice. The repository and its license remain in place
regardless.
