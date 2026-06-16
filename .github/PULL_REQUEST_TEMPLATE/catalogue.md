<!-- Deploy to TeoSlayer/pilotprotocol/.github/PULL_REQUEST_TEMPLATE/catalogue.md
     (or paste into the description of any catalogue.json PR).
     The human half of the app-store review gate (SPEC §7.2). -->

## App-store catalogue change

**App id:** `io.pilot.____`
**Version:** `____`  (new app / version bump)
**Publisher:** `____` (must appear in `pilot-protocol/catalog` `publishers/registry.json`)

### Automated gate
- [ ] `catalogue-validate` CI is green (sha, manifest, signature, `<ns>.help`, id/version, no downgrade).

### Reviewer checklist (do not merge until all checked)
- [ ] Publisher is in `publishers/registry.json` (or added in a linked PR).
- [ ] **Grants are proportional** to the described function. Scrutinize any
      `proc.exec`, `fs.write`, `key.sign`, or broad `net.dial` target.
- [ ] `description` accurately reflects what the app does.
- [ ] Backend host (for `net.dial`) is one the publisher controls.
- [ ] Bundle is released on **`pilot-protocol/catalog`**, not `TeoSlayer/pilotprotocol`.
- [ ] Existing catalogue entries are preserved (only the intended app changed).

### Notes
<!-- anything a reviewer should know: new caps, backend changes, etc. -->
