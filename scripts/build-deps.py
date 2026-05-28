#!/usr/bin/env python3
"""
build-deps.py — generate .github/deps.json from the actual go.mod, package.json,
and Package.swift of every Pilot Protocol repo.

Replaces the hand-maintained deps.json. Run on a schedule and on every relevant
push (see refresh-deps-graph.yml). If the regenerated file differs from what's
checked in, the workflow opens a PR (or commits to main) so the graph cannot
silently drift.

What's derived (no human action required):
  - depends_on edges  → parsed from each repo's go.mod require + replace lines,
                        plus a tiny inference for SDK→libpilot build edges.
  - go_module path    → from `module ...` in go.mod.
  - type              → heuristic (presence of go.mod = go-sibling, package.json
                        with `pilotprotocol-*` deps = sdk-node, etc.)

What's NOT derived (lives in deps.policy.json sidecar):
  - bump_policy           (stable_only, auto_commit_main, open_pr_instead_of_main)
  - freeloader marking    (no edges in either direction by intent, not by accident)
  - friendly notes / _changelog text
  - manual overrides for cases the parser misses

Usage:
  scripts/build-deps.py                 # write .github/deps.json
  scripts/build-deps.py --check         # exit 1 if regen disagrees with checked-in
  scripts/build-deps.py --org pilot-protocol --hub TeoSlayer/pilotprotocol
"""
from __future__ import annotations
import argparse
import json
import re
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Iterable

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT  = SCRIPT_DIR.parent
DEPS_FILE  = REPO_ROOT / ".github" / "deps.json"
POLICY_FILE = REPO_ROOT / ".github" / "deps.policy.json"

# Patterns that mark a require line as pointing at a Pilot Protocol module.
PILOT_MODULE_RE = re.compile(
    r"^github\.com/(pilot-protocol/[a-zA-Z0-9._-]+|TeoSlayer/pilotprotocol(?:/[a-zA-Z0-9./_-]+)?)(?:/[a-zA-Z0-9./_-]+)?$"
)

def run(cmd: list[str]) -> str:
    return subprocess.check_output(cmd, text=True).strip()

def list_org_repos(org: str) -> list[dict]:
    """Use gh CLI to enumerate every public repo in the org."""
    raw = run(["gh", "repo", "list", org, "--json", "name,defaultBranchRef", "--limit", "200"])
    return json.loads(raw)

def fetch_raw(owner: str, repo: str, ref: str, path: str) -> str | None:
    """Fetch a single file from GitHub raw. Return None if 404."""
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return r.read().decode("utf-8", errors="replace")
    except Exception:
        return None

def parse_go_mod(text: str) -> dict:
    """
    Extract module path and require + replace edges from a go.mod file body.
    Returns:
      { "module": "<go.mod module>",
        "requires": [(path, version, indirect_bool)],
        "replaces": [(from_path, to_path_or_module)] }
    """
    out: dict = {"module": None, "requires": [], "replaces": []}
    in_require_block = False
    in_replace_block = False
    for raw_line in text.splitlines():
        line = re.sub(r"//.*", "", raw_line).strip()
        if not line:
            continue
        if line.startswith("module "):
            out["module"] = line.split()[1].strip('"')
            continue
        # require block
        if line.startswith("require (") :
            in_require_block = True; continue
        if line.startswith("replace ("):
            in_replace_block = True; continue
        if line == ")":
            in_require_block = in_replace_block = False; continue
        # single-line require
        if line.startswith("require "):
            tokens = line.split()[1:]
            if len(tokens) >= 2:
                indirect = "indirect" in raw_line
                out["requires"].append((tokens[0], tokens[1], indirect))
            continue
        if in_require_block:
            tokens = line.split()
            if len(tokens) >= 2:
                indirect = "indirect" in raw_line
                out["requires"].append((tokens[0], tokens[1], indirect))
            continue
        # replace handling
        if line.startswith("replace "):
            body = line[len("replace "):]
            parts = [p.strip() for p in body.split("=>", 1)]
            if len(parts) == 2:
                src = parts[0].split()[0]
                dst = parts[1].split()[0]
                out["replaces"].append((src, dst))
            continue
        if in_replace_block:
            parts = [p.strip() for p in line.split("=>", 1)]
            if len(parts) == 2:
                src = parts[0].split()[0]
                dst = parts[1].split()[0]
                out["replaces"].append((src, dst))
            continue
    return out

def module_to_node(mod_path: str, name_map: dict[str, str]) -> str | None:
    """Translate a Go import path into a node name from name_map. Returns None if not a Pilot module."""
    # Trim any trailing subpath: pilot-protocol/handshake/x → pilot-protocol/handshake
    for prefix in ("github.com/pilot-protocol/", "github.com/TeoSlayer/"):
        if mod_path.startswith(prefix):
            tail = mod_path[len(prefix):]
            # tail may contain a sub-path
            top = tail.split("/", 1)[0]
            if prefix.endswith("TeoSlayer/") and top == "pilotprotocol":
                return name_map.get("__hub__")  # web4
            return name_map.get(top)
    return None

def classify_repo(name: str, has_go_mod: bool, has_pkg_json: str | None, has_package_swift: bool) -> str:
    if name == "common":
        return "shared-types"
    if name == "libpilot":
        return "ffi-fan-in"
    if name == "homebrew-pilot":
        return "package-tap"
    if name == "website":
        return "surface"
    if name == "sdk-node":
        return "sdk"
    if name == "sdk-python":
        return "sdk"
    if name == "sdk-swift":
        return "sdk"
    if name == "app-store":
        return "go-app"
    if name == "examples":
        return "go-sibling"
    if name in ("handshake", "runtime"):
        return "go-plugin"
    if has_go_mod:
        return "go-sibling"
    return "unknown"

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--org", default="pilot-protocol")
    ap.add_argument("--hub", default="TeoSlayer/pilotprotocol",
                    help="Special-case repo that owns the daemon engine")
    ap.add_argument("--ref", default="main", help="Branch/tag/sha to read from each repo")
    ap.add_argument("--output", default=str(DEPS_FILE))
    ap.add_argument("--check", action="store_true",
                    help="Exit 1 if the generated file differs from the file on disk")
    ap.add_argument("--policy", default=str(POLICY_FILE),
                    help="Sidecar JSON with bump_policy and freeloader markings")
    args = ap.parse_args()

    # Load policy sidecar (small hand-maintained file).
    policy: dict = {}
    if Path(args.policy).exists():
        policy = json.loads(Path(args.policy).read_text())

    print(f"# Enumerating repos in {args.org} ...", file=sys.stderr)
    org_repos = list_org_repos(args.org)
    names = [r["name"] for r in org_repos]

    # Always include the hub explicitly.
    hub_owner, hub_repo = args.hub.split("/", 1)

    # name_map: top-level path → node name. Hub is sentinel "__hub__".
    name_map = {n: n for n in names}
    name_map["__hub__"] = "web4"
    # Add an explicit "web4" entry (the node label for the hub repo) so it
    # appears in the output even though its owner is different.
    names.append("web4")
    seen_web4 = True

    nodes: dict[str, dict] = {}

    def add_node(name: str, repo: str, has_go: bool, has_node: bool, has_swift: bool,
                 go_module: str | None, edges: list[str], extra: dict | None = None):
        nodes[name] = {
            "repo": repo,
            "type": classify_repo(name, has_go, "package.json" if has_node else None, has_swift),
        }
        if go_module:
            nodes[name]["go_module"] = go_module
        nodes[name]["depends_on"] = sorted(set(e for e in edges if e and e != name))
        # Merge policy sidecar
        if name in policy.get("nodes", {}):
            nodes[name].update(policy["nodes"][name])
        if extra:
            nodes[name].update(extra)

    # Walk each org repo
    for r in org_repos:
        name = r["name"]
        ref = r.get("defaultBranchRef", {}).get("name") or args.ref
        gomod = fetch_raw(args.org, name, ref, "go.mod")
        pkgjson = fetch_raw(args.org, name, ref, "package.json")
        pkgswift = fetch_raw(args.org, name, ref, "Package.swift")

        # Skip noise repos with no manifest at all (docs, configs, runbooks,
        # workflow repo, etc.). Manual_nodes in policy can still bring them
        # in later if they need explicit representation.
        if name not in policy.get("nodes", {}) and not gomod and not pkgjson and not pkgswift:
            continue

        edges: list[str] = []
        go_module = None
        if gomod:
            parsed = parse_go_mod(gomod)
            go_module = parsed["module"]
            # Include BOTH direct and indirect requires — sibling-to-sibling
            # edges (runtime → rendezvous, webhook → trustedagents, etc.)
            # commonly land in go.mod as // indirect because the compiler
            # discovers them transitively through the import graph; the
            # cascade still needs to fire when an indirect upstream ships.
            for path, _ver, _indirect in parsed["requires"]:
                node = module_to_node(path, name_map)
                if node and node != name:
                    edges.append(node)
            # Nested submodule (app-store/integration, examples/go) edges
            # accrue to the parent node so a sibling push triggers any
            # downstream that depends on its umbrella name.
            for sub in ("integration/go.mod", "go/go.mod"):
                nested = fetch_raw(args.org, name, ref, sub)
                if nested:
                    p2 = parse_go_mod(nested)
                    for path, _ver, _indirect in p2["requires"]:
                        node = module_to_node(path, name_map)
                        if node and node != name:
                            edges.append(node)
        # SDKs have implicit build-time edges to libpilot that are not in any manifest.
        if name in ("sdk-node", "sdk-python", "sdk-swift"):
            edges.append("libpilot")
        add_node(name, f"{args.org}/{name}",
                 has_go=bool(gomod),
                 has_node=bool(pkgjson),
                 has_swift=bool(pkgswift),
                 go_module=go_module, edges=edges)

    # Hub: walk web4 separately.
    hub_gomod = fetch_raw(hub_owner, hub_repo, args.ref, "go.mod")
    if hub_gomod:
        parsed = parse_go_mod(hub_gomod)
        hub_edges: list[str] = []
        for path, _ver, indirect in parsed["requires"]:
            if indirect:
                continue
            node = module_to_node(path, name_map)
            if node and node != "web4":
                hub_edges.append(node)
        add_node("web4", args.hub,
                 has_go=True, has_node=False, has_swift=False,
                 go_module=parsed["module"], edges=hub_edges,
                 extra={"_imports_pkg_daemon_via": ["handshake", "runtime", "libpilot"]})

    # Constellation freeloaders + manual surfaces (homebrew lives outside
    # the org, website may not have manifests we can parse, etc.). The
    # policy sidecar carries { node: {repo, depends_on} } for these.
    for extra_name, manual in policy.get("manual_nodes", {}).items():
        if extra_name not in nodes:
            nodes[extra_name] = {
                "repo": manual["repo"],
                "type": classify_repo(extra_name, False, None, False),
                "depends_on": sorted(manual.get("depends_on", [])),
            }
            if extra_name in policy.get("nodes", {}):
                nodes[extra_name].update(policy["nodes"][extra_name])

    out = {
        "$schema": "https://pilotprotocol.network/.well-known/deps.schema.json",
        "version": 3,
        "_generated_by": "scripts/build-deps.py",
        "_do_not_edit": "Regenerated on every push by .github/workflows/refresh-deps-graph.yml. Edit deps.policy.json to override bump_policy or add manual_nodes.",
        "nodes": dict(sorted(nodes.items())),
    }

    out_text = json.dumps(out, indent=2) + "\n"
    if args.check:
        existing = Path(args.output).read_text() if Path(args.output).exists() else ""
        if existing != out_text:
            print("deps.json is out of date — regenerate with scripts/build-deps.py", file=sys.stderr)
            return 1
        print("deps.json is up to date.", file=sys.stderr)
        return 0
    Path(args.output).write_text(out_text)
    print(f"wrote {args.output} ({len(nodes)} nodes)", file=sys.stderr)
    return 0

if __name__ == "__main__":
    sys.exit(main())
