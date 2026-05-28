#!/usr/bin/env python3
"""Extract the public API surface of sdk-node, sdk-python, sdk-swift and emit a
parity matrix CSV.

Reproducible audit for PILOT-42. Re-runnable against any future checkout of the
three SDKs — just point the SDK_ROOTS at clean clones.

Output:
  inventory/node.csv        — every public symbol in sdk-node
  inventory/python.csv      — every public symbol in sdk-python
  inventory/swift.csv       — every public symbol in sdk-swift
  inventory/matrix.csv      — normalized cross-SDK matrix (one row per
                              canonical method, columns per SDK, plus gap
                              classification placeholders)

Usage:
  python3 build_matrix.py \\
      --node-root   ~/agent-work/PILOT-42/sdk-node    \\
      --python-root ~/agent-work/PILOT-42/sdk-python  \\
      --swift-root  ~/agent-work/PILOT-42/sdk-swift   \\
      --out-dir     ~/agent-work/PILOT-42/inventory
"""
from __future__ import annotations

import argparse
import ast
import csv
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Symbol:
    sdk: str          # "node" | "python" | "swift"
    container: str    # owning class/struct/module
    kind: str         # "class" | "method" | "init" | "property" | "const" | "function" | "enum" | "struct"
    name: str         # raw identifier as it appears in the source
    signature: str    # one-line signature snippet
    canonical: str = ""   # normalized name shared across SDKs


def canonicalize(name: str) -> str:
    """snake_case → camelCase; preserves dunder, acronyms, and ALL_CAPS constants."""
    if name.startswith("__") and name.endswith("__"):
        return name
    # ALL_CAPS_WITH_UNDERSCORES is a constant convention shared across languages —
    # don't camel-case it.
    if name.isupper() or (name.replace("_", "").isupper() and "_" in name):
        return name
    parts = name.split("_")
    if len(parts) == 1:
        return parts[0]
    head, *tail = parts
    return head + "".join(p[:1].upper() + p[1:] for p in tail)


# ---------------------------------------------------------------------------
# sdk-python — AST parse client.py + read __all__
# ---------------------------------------------------------------------------

def extract_python(root: Path) -> list[Symbol]:
    init_py = root / "pilotprotocol" / "__init__.py"
    client_py = root / "pilotprotocol" / "client.py"

    init_tree = ast.parse(init_py.read_text())
    public_names: set[str] = set()
    for node in ast.walk(init_tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__all__":
                    if isinstance(node.value, ast.List):
                        public_names = {
                            elt.value for elt in node.value.elts
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                        }

    client_tree = ast.parse(client_py.read_text())
    out: list[Symbol] = []

    # Module-level constants in __all__
    for node in client_tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in public_names:
                    out.append(Symbol(
                        sdk="python", container="<module>", kind="const",
                        name=target.id, signature=f"{target.id} = ...",
                        canonical=canonicalize(target.id),
                    ))

    # Public classes from __all__
    for node in client_tree.body:
        if isinstance(node, ast.ClassDef) and node.name in public_names:
            out.append(Symbol(
                sdk="python", container="<module>", kind="class",
                name=node.name, signature=f"class {node.name}",
                canonical=canonicalize(node.name),
            ))
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if item.name.startswith("_") and not (
                        item.name.startswith("__") and item.name.endswith("__")
                    ):
                        continue
                    # Skip leaking-internals helpers
                    if item.name in {"_call_json"}:
                        continue
                    sig = _python_sig(item)
                    out.append(Symbol(
                        sdk="python", container=node.name, kind="method",
                        name=item.name, signature=sig,
                        canonical=canonicalize(item.name),
                    ))
    return out


def _python_sig(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    args = [a.arg for a in fn.args.args]
    return f"def {fn.name}({', '.join(args)})"


# ---------------------------------------------------------------------------
# sdk-node — regex parse src/client.ts (+ index.ts re-exports)
# ---------------------------------------------------------------------------

EXPORTED_NAMES_RE = re.compile(r"^\s*export\s+(?:type\s+)?\{([^}]+)\}", re.MULTILINE)
CLASS_RE = re.compile(r"^export class (\w+)\b", re.MULTILINE)
METHOD_RE = re.compile(
    r"^  (?!private|#|_)([a-zA-Z][a-zA-Z0-9]*)\s*\([^)]*\)\s*(?::|=>|\{)",
    re.MULTILINE,
)
CONSTRUCTOR_RE = re.compile(r"^  constructor\s*\([^)]*\)", re.MULTILINE)

def extract_node(root: Path) -> list[Symbol]:
    index_ts = (root / "src" / "index.ts").read_text()
    public_names: set[str] = set()
    for match in EXPORTED_NAMES_RE.finditer(index_ts):
        for token in match.group(1).split(","):
            token = token.strip().split(" as ")[0].strip()
            if token:
                public_names.add(token)

    # Scan every src/*.ts file for class declarations; we want anything that
    # appears in public_names regardless of which file declares it.
    src_files = sorted((root / "src").glob("*.ts"))
    all_src = "\n// === FILE BOUNDARY ===\n".join(p.read_text() for p in src_files)
    client_ts = all_src
    out: list[Symbol] = []

    # Capture each exported class block, then extract methods within
    # We split on `export class` and process each segment.
    class_segments = re.split(r"^(export class \w+[^{]*\{)", client_ts, flags=re.MULTILINE)
    # split produces alternating [pre, header, body, header, body, ...]
    for i in range(1, len(class_segments), 2):
        header = class_segments[i]
        body = class_segments[i + 1] if i + 1 < len(class_segments) else ""
        cls_match = re.search(r"export class (\w+)", header)
        if not cls_match:
            continue
        cls_name = cls_match.group(1)
        if cls_name not in public_names:
            continue

        out.append(Symbol(
            sdk="node", container="<module>", kind="class",
            name=cls_name, signature=f"class {cls_name}",
            canonical=canonicalize(cls_name),
        ))

        # Trim body at the matching closing brace (best effort: first \n}\n)
        end_match = re.search(r"^\}\s*$", body, flags=re.MULTILINE)
        if end_match:
            body = body[: end_match.start()]

        # Constructor
        if CONSTRUCTOR_RE.search(body):
            out.append(Symbol(
                sdk="node", container=cls_name, kind="init",
                name="constructor", signature="constructor(...)",
                canonical="constructor",
            ))

        # Methods (skip private/#/_ prefixed via regex; skip Symbol.dispose
        # which we record under a synthetic canonical name)
        for m in METHOD_RE.finditer(body):
            name = m.group(1)
            if name in {"constructor", "if", "for", "while", "switch", "return", "throw", "new"}:
                continue
            # Capture full method signature (line)
            line_start = body.rfind("\n", 0, m.start()) + 1
            line_end = body.find("\n", m.end())
            sig = body[line_start:line_end].strip().rstrip("{").rstrip()
            out.append(Symbol(
                sdk="node", container=cls_name, kind="method",
                name=name, signature=sig,
                canonical=canonicalize(name),
            ))

        # Symbol.dispose support
        if "[Symbol.dispose]" in body:
            out.append(Symbol(
                sdk="node", container=cls_name, kind="method",
                name="[Symbol.dispose]", signature="[Symbol.dispose](): void",
                canonical="dispose",
            ))

    # Module-level exports (constants, functions) from index.ts re-exports
    for name in public_names:
        # Skip class names already captured
        if any(s.name == name for s in out):
            continue
        # Look up in client.ts
        const_match = re.search(rf"^export const {name}\b\s*[=:]\s*([^;]+)", client_ts, re.MULTILINE)
        if const_match:
            out.append(Symbol(
                sdk="node", container="<module>", kind="const",
                name=name, signature=f"const {name} = {const_match.group(1).strip()}",
                canonical=canonicalize(name),
            ))
            continue
        # Functions in ffi.ts
        ffi_ts = (root / "src" / "ffi.ts").read_text()
        fn_match = re.search(rf"^export function {name}\b([^{{]*)", ffi_ts, re.MULTILINE)
        if fn_match:
            out.append(Symbol(
                sdk="node", container="<module>", kind="function",
                name=name, signature=f"function {name}{fn_match.group(1).strip()}".rstrip(),
                canonical=canonicalize(name),
            ))

    return out


# ---------------------------------------------------------------------------
# sdk-swift — regex over Sources/Pilot/Pilot.swift
# ---------------------------------------------------------------------------

SWIFT_DECL_RE = re.compile(
    r"^\s*public\s+(?:final\s+)?(?:static\s+)?"
    r"(?P<kind>func|init|class|struct|enum|var|let)\s+"
    r"(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)?"
    r"(?P<rest>[^{\n]*)",
    re.MULTILINE,
)
SWIFT_FUNC_NAME_RE = re.compile(r"public\s+(?:static\s+)?func\s+(\w+)\s*\(")

def extract_swift(root: Path) -> list[Symbol]:
    """Parse public decls out of Pilot.swift with a brace-depth container stack.

    Each entry on the stack is (container_name, brace_depth_at_open). When the
    overall brace depth drops below the recorded open depth, pop the container.
    """
    src = (root / "Sources" / "Pilot" / "Pilot.swift").read_text()
    out: list[Symbol] = []
    container_stack: list[tuple[str, int]] = [("<module>", 0)]
    depth = 0

    def current_container() -> str:
        return container_stack[-1][0]

    for line in src.split("\n"):
        stripped = line.strip()
        # Strip line comments so braces inside `//` don't disturb counts
        if "//" in line:
            line_for_braces = line[: line.index("//")]
        else:
            line_for_braces = line
        opens = line_for_braces.count("{")
        closes = line_for_braces.count("}")

        # A container's scope is closed only when the *net* depth after this
        # line drops below its open-depth. A balanced one-liner like
        # `deinit { try? stop() }` doesn't close any container.
        net_depth_after_line = depth + opens - closes
        while len(container_stack) > 1 and container_stack[-1][1] > net_depth_after_line:
            container_stack.pop()

        # Public type declarations open a new container
        type_match = re.match(
            r"public\s+(?:final\s+)?(class|struct|enum)\s+(\w+)", stripped
        )
        if type_match:
            kind, name = type_match.group(1), type_match.group(2)
            owner = current_container()
            display = name if owner == "<module>" else f"{owner}.{name}"
            out.append(Symbol(
                sdk="swift", container=owner, kind=kind,
                name=display, signature=f"{kind} {display}",
                canonical=canonicalize(name),
            ))
            depth += opens - closes
            if "{" in line_for_braces:
                # New container opens at current depth (before its own opening
                # brace counted into `depth`).
                container_stack.append((display, depth - opens + 1))
            continue

        # Public func / init / var / let
        func_match = re.match(
            r"public\s+(?:static\s+)?func\s+(\w+)\s*(\([^)]*\)[^{\n]*)", stripped
        )
        if func_match:
            name = func_match.group(1)
            sig = f"public func {name}{func_match.group(2)}".rstrip()
            out.append(Symbol(
                sdk="swift", container=current_container(), kind="method",
                name=name, signature=sig,
                canonical=canonicalize(name),
            ))
            depth += opens - closes
            continue

        if re.match(r"public\s+init\s*\(", stripped):
            out.append(Symbol(
                sdk="swift", container=current_container(), kind="init",
                name="init", signature=stripped.rstrip("{").rstrip(),
                canonical="init",
            ))
            depth += opens - closes
            continue

        var_match = re.match(r"public\s+(var|let)\s+(\w+)\s*:\s*([^=]+?)(\s*=.*)?$", stripped)
        if var_match:
            kind, name, type_, _ = var_match.groups()
            out.append(Symbol(
                sdk="swift", container=current_container(), kind="property",
                name=name, signature=f"public {kind} {name}: {type_.strip()}",
                canonical=canonicalize(name),
            ))
            depth += opens - closes
            continue

        depth += opens - closes

    return out


# ---------------------------------------------------------------------------
# CSV writers
# ---------------------------------------------------------------------------

def write_csv(path: Path, symbols: list[Symbol]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["sdk", "container", "kind", "name", "canonical", "signature"])
        for s in sorted(symbols, key=lambda s: (s.container, s.kind, s.name)):
            w.writerow([s.sdk, s.container, s.kind, s.name, s.canonical, s.signature])


def build_matrix(node: list[Symbol], py: list[Symbol], swift: list[Symbol]) -> list[dict]:
    """Build one row per (container, canonical) tuple across all SDKs.

    Idiomatic equivalents across languages are merged into a single canonical
    row so the matrix shows *protocol*-level gaps, not naming differences.
    """
    # Map container names across SDKs to a canonical container.
    container_map = {
        "Driver": "Driver",
        "Pilot": "Driver",          # Swift's main type → canonical "Driver"
        "Conn": "Conn",
        "Listener": "Listener",
        "PilotError": "PilotError",
        "<module>": "<module>",
    }

    # Language-idiomatic equivalents — merged to the same canonical name so
    # they don't look like gaps. Keyed by (container, raw_canonical).
    canonical_alias = {
        # Constructor idioms across languages
        ("Driver", "__init__"): "__construct",
        ("Driver", "constructor"): "__construct",
        ("Driver", "start"): "__construct",    # Swift factory == constructor
        ("Conn", "__init__"): "__construct",
        ("Conn", "constructor"): "__construct",
        ("Listener", "__init__"): "__construct",
        ("Listener", "constructor"): "__construct",
        # Cleanup / `with` / `using` idioms
        ("Driver", "__exit__"): "__dispose",
        ("Driver", "dispose"): "__dispose",
        ("Driver", "close"): "__dispose",
        ("Driver", "stop"): "__dispose",       # Swift uses stop() for close
        ("Conn", "__exit__"): "__dispose",
        ("Conn", "dispose"): "__dispose",
        ("Conn", "close"): "__dispose",
        ("Listener", "__exit__"): "__dispose",
        ("Listener", "dispose"): "__dispose",
        ("Listener", "close"): "__dispose",
        # Pure language ceremony — drop from matrix entirely
        ("Driver", "__enter__"): None,
        ("Driver", "__del__"): None,
        ("Conn", "__enter__"): None,
        ("Conn", "__del__"): None,
        ("Listener", "__enter__"): None,
        ("Listener", "__del__"): None,
        # Python alias of rotate_key
        ("Driver", "rotateIdentity"): "rotateKey",
        # Datagram send/recv idioms — Swift split addr+port, others combine
        ("Driver", "send"): "sendTo",
        ("Driver", "receive"): "recvFrom",
        # Module-level main-class re-exports (each SDK names its top class
        # differently but they all map to canonical "Driver" export)
        ("<module>", "Pilot"): "Driver",
        ("<module>", "PilotError"): "PilotError",
    }

    rows: dict[tuple[str, str], dict] = defaultdict(lambda: {
        "container": "", "canonical": "",
        "node_name": "", "python_name": "", "swift_name": "",
        "node_signature": "", "python_signature": "", "swift_signature": "",
        "node_present": False, "python_present": False, "swift_present": False,
        "gap_type": "", "rationale": "", "follow_up_ticket": "",
        "category": "",
    })

    def add(symbols: list[Symbol], sdk: str):
        for s in symbols:
            container = container_map.get(s.container, s.container)
            raw_canonical = s.canonical or s.name
            alias_key = (container, raw_canonical)
            final_canonical = canonical_alias.get(alias_key, raw_canonical)
            if final_canonical is None:
                continue   # language ceremony — excluded from matrix
            key = (container, final_canonical)
            row = rows[key]
            row["container"] = container
            row["canonical"] = key[1]
            # Append to per-SDK column if multiple raw symbols collapse here
            # (e.g. Swift's `start` static + `start` property both alias to
            # __construct — record both names so the row stays honest).
            existing = row.get(f"{sdk}_name") or ""
            row[f"{sdk}_name"] = (
                s.name if not existing else f"{existing} / {s.name}"
            )
            existing_sig = row.get(f"{sdk}_signature") or ""
            row[f"{sdk}_signature"] = (
                s.signature if not existing_sig else f"{existing_sig} | {s.signature}"
            )
            row[f"{sdk}_present"] = True

    add(node, "node")
    add(py, "python")
    add(swift, "swift")

    # Categorize
    for (container, canonical), row in rows.items():
        if container == "<module>":
            row["category"] = "module-level"
        elif container == "Driver":
            if canonical in {"info", "health", "rotateKey", "rotateIdentity"}:
                row["category"] = "daemon-admin"
            elif canonical in {"handshake", "approveHandshake", "rejectHandshake",
                                "pendingHandshakes", "trustedPeers", "revokeTrust",
                                "waitForTrust"}:
                row["category"] = "trust"
            elif canonical in {"resolveHostname", "setHostname", "setVisibility",
                                "deregister", "setTags", "setWebhook"}:
                row["category"] = "registry-admin"
            elif canonical in {"dial", "listen", "disconnect"}:
                row["category"] = "streams"
            elif canonical in {"sendTo", "recvFrom", "broadcast", "send", "receive"}:
                row["category"] = "datagrams"
            elif canonical.startswith("network"):
                row["category"] = "networks"
            elif canonical.startswith("managed"):
                row["category"] = "managed-networks"
            elif canonical.startswith("policy"):
                row["category"] = "policy"
            elif canonical.startswith("memberTags"):
                row["category"] = "member-tags"
            elif canonical in {"sendMessage", "sendFile", "publishEvent",
                                "subscribeEvent"}:
                row["category"] = "high-level-services"
            elif canonical in {"close", "constructor", "stop", "start"}:
                row["category"] = "lifecycle"
            else:
                row["category"] = "driver-other"
        elif container in {"Conn", "Listener"}:
            row["category"] = f"{container.lower()}-methods"
        elif container == "PilotError":
            row["category"] = "errors"
        else:
            row["category"] = "swift-specific-type"

    # Classify each row (gap_type + rationale) using rules — keeps the
    # judgment in one auditable place rather than scattered through docs.
    for row in rows.values():
        node_p = row["node_present"]
        py_p = row["python_present"]
        sw_p = row["swift_present"]
        present_count = sum([node_p, py_p, sw_p])

        # Module-level main-class export — always present in some form
        if row["container"] == "<module>" and row["canonical"] == "Driver":
            row["gap_type"] = "none"
            row["rationale"] = "Each SDK exports its top-level client class (Driver / Driver / Pilot)."
            continue

        # FFI-loader helpers (node-only) — internal/advanced API
        if row["canonical"] in {"findLibrary", "loadLibrary"}:
            row["gap_type"] = "intentional"
            row["rationale"] = (
                "Node exposes libpilot FFI helpers for advanced consumers. "
                "Python keeps them in `_runtime.py` (private). Swift embeds the "
                "library in an XCFramework — no path to resolve."
            )
            continue

        # PilotError module re-export — present in all where it's a real class
        if row["canonical"] == "PilotError":
            row["gap_type"] = "none"
            row["rationale"] = "Error type is exported in node + python; Swift uses the `Pilot.Error` enum."
            continue

        # PilotError constructor — language ceremony, not API
        if row["container"] == "PilotError":
            row["gap_type"] = "convention"
            row["rationale"] = "Language ceremony — error construction idiom differs across languages."
            continue

        # DEFAULT_SOCKET_PATH constant
        if row["canonical"] == "DEFAULT_SOCKET_PATH":
            row["gap_type"] = "intentional"
            row["rationale"] = "Swift's embedded daemon uses a per-instance socket under dataDir; no global default."
            continue

        # Swift-only typed structs (Config, StartResult, Datagram, Error class)
        if row["category"] in {"driver-other", "swift-specific-type"} and sw_p and not node_p and not py_p:
            row["gap_type"] = "convention"
            row["rationale"] = (
                "Swift idiom: typed structs for responses. Node/Python expose "
                "the same data as `Record<string, unknown>` / `dict[str, Any]` "
                "from the corresponding RPC."
            )
            continue

        # Full parity
        if present_count == 3:
            row["gap_type"] = "none"
            row["rationale"] = "Full parity."
            continue

        # waitForTrust — Swift-only convenience, real ergonomic gap in node+python
        if row["canonical"] == "waitForTrust":
            row["gap_type"] = "unintentional"
            row["rationale"] = (
                "Swift offers a blocking helper that completes when trust is "
                "established. Node/Python users must poll `pendingHandshakes`. "
                "Worth adding."
            )
            continue

        # Missing in Swift only — classify by category
        if node_p and py_p and not sw_p:
            cat = row["category"]
            if cat in {"streams", "listener-methods", "conn-methods"}:
                row["gap_type"] = "unintentional"
                row["rationale"] = (
                    "Stream (TCP-like) API. The wire protocol supports it; the "
                    "Swift surface just doesn't expose it yet."
                )
            elif cat == "networks":
                row["gap_type"] = "unintentional"
                row["rationale"] = "Network membership/discovery — protocol feature, not platform-gated."
            elif cat == "managed-networks":
                row["gap_type"] = "unintentional"
                row["rationale"] = "Managed-network ranking engine — same wire RPC as node/python."
            elif cat == "policy":
                row["gap_type"] = "unintentional"
                row["rationale"] = "Network policy get/set — protocol feature, missing only in Swift."
            elif cat == "member-tags":
                row["gap_type"] = "unintentional"
                row["rationale"] = "Per-member tags — protocol feature, missing only in Swift."
            elif cat == "high-level-services":
                row["gap_type"] = "unintentional"
                row["rationale"] = "High-level message/event services — protocol feature, missing only in Swift."
            elif cat == "registry-admin":
                row["gap_type"] = "unintentional"
                row["rationale"] = "Registry/hostname/visibility admin — protocol feature, missing only in Swift."
            elif cat == "trust":
                row["gap_type"] = "unintentional"
                row["rationale"] = "Trust admin (approve/reject/pending/revoke) — protocol feature."
            elif cat == "datagrams" and row["canonical"] == "broadcast":
                row["gap_type"] = "unintentional"
                row["rationale"] = "Network-wide broadcast — protocol feature, missing only in Swift."
            elif cat == "daemon-admin":
                row["gap_type"] = "unintentional"
                row["rationale"] = "Daemon admin operation — protocol-level, no platform reason to omit."
            else:
                row["gap_type"] = "unintentional"
                row["rationale"] = "Present in node + python; absent in Swift."
            continue

        # Default fallback
        row["gap_type"] = "review-needed"
        row["rationale"] = "Auto-classifier did not match a rule; review manually."

    # Sort the matrix: category → container → canonical
    return sorted(
        rows.values(),
        key=lambda r: (r["category"], r["container"], r["canonical"]),
    )


def write_matrix_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=[
            "category", "container", "canonical",
            "node_present", "python_present", "swift_present",
            "node_name", "python_name", "swift_name",
            "node_signature", "python_signature", "swift_signature",
            "gap_type", "rationale", "follow_up_ticket",
        ])
        w.writeheader()
        for row in rows:
            w.writerow(row)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--node-root", required=True, type=Path)
    p.add_argument("--python-root", required=True, type=Path)
    p.add_argument("--swift-root", required=True, type=Path)
    p.add_argument("--out-dir", required=True, type=Path)
    args = p.parse_args()

    node = extract_node(args.node_root.expanduser())
    py = extract_python(args.python_root.expanduser())
    swift = extract_swift(args.swift_root.expanduser())

    out = args.out_dir.expanduser()
    write_csv(out / "node.csv", node)
    write_csv(out / "python.csv", py)
    write_csv(out / "swift.csv", swift)
    matrix = build_matrix(node, py, swift)
    write_matrix_csv(out / "matrix.csv", matrix)

    print(f"node:   {len(node):3d} symbols → {out/'node.csv'}")
    print(f"python: {len(py):3d} symbols → {out/'python.csv'}")
    print(f"swift:  {len(swift):3d} symbols → {out/'swift.csv'}")
    print(f"matrix: {len(matrix):3d} rows → {out/'matrix.csv'}")


if __name__ == "__main__":
    main()
