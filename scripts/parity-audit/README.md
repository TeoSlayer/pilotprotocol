# SDK parity audit

Re-runnable extractor + classifier for the cross-SDK API surface comparison
(PILOT-42). Walks the public surface of `sdk-node`, `sdk-python`, and
`sdk-swift` and emits a CSV matrix with one row per canonical method, columns
per SDK, and a `gap_type` (`none` / `intentional` / `convention` / `unintentional`)
classification on every row.

## Run it

Clone the three SDKs side-by-side, then:

```bash
python3 build_matrix.py \
    --node-root   ../path/to/sdk-node   \
    --python-root ../path/to/sdk-python \
    --swift-root  ../path/to/sdk-swift  \
    --out-dir     ./inventory
```

Outputs:

- `inventory/node.csv` — every public symbol exported by sdk-node
- `inventory/python.csv` — every public symbol in sdk-python's `__all__`
- `inventory/swift.csv` — every `public` declaration in `Sources/Pilot/Pilot.swift`
- `inventory/matrix.csv` — normalized cross-SDK matrix, with classifications

Upload `matrix.csv` to Google Sheets to refresh the canonical parity matrix
linked from `docs/SDK_PARITY.md`.

## How it works

- **sdk-python**: AST parses `pilotprotocol/__init__.py` for `__all__`, then
  AST parses `pilotprotocol/client.py` for class methods. Skips
  underscore-prefixed members and the internal `_call_json` helper.
- **sdk-node**: regex parses `src/*.ts` for `export class` blocks and method
  declarations. Skips `private`, `#`-prefixed, and `_`-prefixed members.
- **sdk-swift**: brace-depth state machine over `Sources/Pilot/Pilot.swift`,
  capturing `public func` / `public init` / `public var|let` /
  `public class|struct|enum`. Tracks nested containers so methods attribute
  to the right type.

The matrix's `canonical` column uses camelCase as the cross-SDK key (matching
Node/Swift conventions). Python's snake_case names are converted; ALL_CAPS
constants are preserved verbatim.

Idiomatic equivalents are merged via an explicit alias map inside
`build_matrix.py` (`canonical_alias`): e.g. `__init__` ≡ `constructor` ≡ `init`
all collapse to `__construct`. Edit that map to refine the merging — it's the
single place where "these are the same operation" is asserted.

## Conventions for `gap_type`

| value | meaning |
|---|---|
| `none` | All three SDKs expose this — full parity. |
| `convention` | Idiomatic difference, not a gap (e.g. typed Swift struct vs. untyped dict). |
| `intentional` | Real gap, but justified by a platform constraint (e.g. no FFI loader for Swift's embedded library). |
| `unintentional` | Real gap with no platform justification — needs a follow-up ticket. |
| `review-needed` | Auto-classifier didn't match a rule. Should be 0 after merge. |
