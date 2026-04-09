"""
Tools available to the Gemini agent for reading pilotprotocol docs and source code.
"""

import os
import re
from pathlib import Path

PILOTPROTOCOL_ROOT = Path(
    os.environ.get("PILOTPROTOCOL_ROOT", "/Users/alexgodo/web4/pilotprotocol")
)
DOCS_DIR = PILOTPROTOCOL_ROOT / "docs"
CMD_DIR = PILOTPROTOCOL_ROOT / "cmd"
PKG_DIR = PILOTPROTOCOL_ROOT / "pkg"
EXAMPLES_DIR = PILOTPROTOCOL_ROOT / "examples"

ALLOWED_DIRS = [DOCS_DIR, CMD_DIR, PKG_DIR, EXAMPLES_DIR, PILOTPROTOCOL_ROOT]


def _is_allowed(path: Path) -> bool:
    try:
        resolved = path.resolve()
        return any(
            str(resolved).startswith(str(d.resolve()))
            for d in ALLOWED_DIRS
        )
    except Exception:
        return False


def list_docs() -> dict:
    result = []
    for f in DOCS_DIR.rglob("*"):
        if f.is_file() and f.suffix in (".md", ".txt"):
            result.append(str(f.relative_to(PILOTPROTOCOL_ROOT)))
    for f in PILOTPROTOCOL_ROOT.glob("*.md"):
        result.append(str(f.relative_to(PILOTPROTOCOL_ROOT)))
    return {"files": sorted(result)}


def read_doc(filename: str) -> dict:
    candidate = PILOTPROTOCOL_ROOT / filename
    if not candidate.exists():
        candidate = DOCS_DIR / filename
    if not candidate.exists():
        bare = filename.lstrip("docs/")
        candidate = DOCS_DIR / bare
    if not candidate.exists():
        return {"error": f"File not found: {filename}. Use list_docs() to see available files."}
    if not _is_allowed(candidate):
        return {"error": "Access denied."}
    try:
        content = candidate.read_text(encoding="utf-8", errors="replace")
        if len(content) > 60_000:
            content = content[:60_000] + "\n\n[... truncated at 60,000 chars ...]"
        return {"content": content, "path": str(candidate.relative_to(PILOTPROTOCOL_ROOT))}
    except Exception as e:
        return {"error": str(e)}


def read_source(filepath: str) -> dict:
    candidate = PILOTPROTOCOL_ROOT / filepath
    if not candidate.exists():
        return {"error": f"File not found: {filepath}"}
    if not _is_allowed(candidate):
        return {"error": "Access denied."}
    allowed_extensions = {".go", ".py", ".sh", ".json", ".yaml", ".yml", ".toml", ".mod"}
    if candidate.suffix not in allowed_extensions:
        return {"error": f"File type {candidate.suffix} not allowed."}
    try:
        content = candidate.read_text(encoding="utf-8", errors="replace")
        if len(content) > 40_000:
            content = content[:40_000] + "\n\n[... truncated ...]"
        return {"content": content, "path": str(candidate.relative_to(PILOTPROTOCOL_ROOT))}
    except Exception as e:
        return {"error": str(e)}


def list_source_files(directory: str = "") -> dict:
    target = PILOTPROTOCOL_ROOT / directory if directory else PILOTPROTOCOL_ROOT
    if not target.exists() or not target.is_dir():
        return {"error": f"Directory not found: {directory}"}
    if not _is_allowed(target):
        return {"error": "Access denied."}
    files = []
    for f in sorted(target.iterdir()):
        entry = str(f.relative_to(PILOTPROTOCOL_ROOT))
        if f.is_dir():
            entry += "/"
        files.append(entry)
    return {"files": files}


def search_source(pattern: str, directory: str = "") -> dict:
    search_root = PILOTPROTOCOL_ROOT / directory if directory else PILOTPROTOCOL_ROOT
    if not _is_allowed(search_root):
        return {"error": "Access denied."}
    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        return {"error": f"Invalid regex: {e}"}
    matches = []
    for path in search_root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in {".go", ".py", ".md", ".sh", ".json"}:
            continue
        if not _is_allowed(path):
            continue
        try:
            for i, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if regex.search(line):
                    matches.append({
                        "file": str(path.relative_to(PILOTPROTOCOL_ROOT)),
                        "line_number": i,
                        "line": line.strip(),
                    })
                    if len(matches) >= 50:
                        return {"matches": matches, "truncated": True}
        except Exception:
            continue
    return {"matches": matches, "truncated": False}


TOOL_DEFINITIONS = [
    {
        "name": "list_docs",
        "description": "List all documentation files in the pilotprotocol project.",
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "read_doc",
        "description": (
            "Read a documentation file from the pilotprotocol project. "
            "Use before generating commands if syntax is uncertain. "
            "Key files: docs/SKILLS.md (command reference), README.md, AGENTS.md."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "filename": {
                    "type": "string",
                    "description": "Relative path from pilotprotocol root, e.g. 'docs/SKILLS.md'",
                }
            },
            "required": ["filename"],
        },
    },
    {
        "name": "read_source",
        "description": (
            "Read a Go source file to verify command behavior or flag names. "
            "Key files: 'cmd/pilotctl/main.go', 'pkg/daemon/daemon.go'."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "filepath": {
                    "type": "string",
                    "description": "Relative path, e.g. 'cmd/pilotctl/main.go'",
                }
            },
            "required": ["filepath"],
        },
    },
    {
        "name": "list_source_files",
        "description": "List files in a directory of the pilotprotocol source tree.",
        "parameters": {
            "type": "object",
            "properties": {
                "directory": {
                    "type": "string",
                    "description": "Relative path, e.g. 'cmd/pilotctl'. Leave empty for top-level.",
                }
            },
            "required": [],
        },
    },
    {
        "name": "search_source",
        "description": "Search for a regex pattern across source files and docs (max 50 results).",
        "parameters": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Regex to search for, e.g. 'task submit'",
                },
                "directory": {
                    "type": "string",
                    "description": "Limit search to this directory. Leave empty to search all.",
                },
            },
            "required": ["pattern"],
        },
    },
]

TOOL_FUNCTIONS = {
    "list_docs": lambda args: list_docs(),
    "read_doc": lambda args: read_doc(args["filename"]),
    "read_source": lambda args: read_source(args["filepath"]),
    "list_source_files": lambda args: list_source_files(args.get("directory", "")),
    "search_source": lambda args: search_source(args["pattern"], args.get("directory", "")),
}
