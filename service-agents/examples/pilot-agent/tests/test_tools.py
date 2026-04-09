"""
Unit tests for pilot-agent tools.

Tests the sandbox enforcement and tool utility functions without
requiring a real pilotprotocol source tree or Gemini API key.
"""

import os
import tempfile
from pathlib import Path
from unittest import mock

import pytest


# ---------------------------------------------------------------------------
# Fixture: patch PILOTPROTOCOL_ROOT to a controlled temp directory
# ---------------------------------------------------------------------------

@pytest.fixture()
def fake_root(tmp_path, monkeypatch):
    """Return a tmp_path that mimics a minimal pilotprotocol tree."""
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "SKILLS.md").write_text("# Skills\n\nCommand reference.")
    (docs / "README.md").write_text("# Readme\n")
    (tmp_path / "README.md").write_text("# Root readme\n")

    cmd = tmp_path / "cmd"
    cmd.mkdir()
    pilotctl = cmd / "pilotctl"
    pilotctl.mkdir()
    (pilotctl / "main.go").write_text('package main\nfunc main() {}')

    monkeypatch.setenv("PILOTPROTOCOL_ROOT", str(tmp_path))
    # Re-import with patched env
    import importlib
    import agent.tools as t
    importlib.reload(t)
    return tmp_path, t


# ---------------------------------------------------------------------------
# list_docs
# ---------------------------------------------------------------------------

class TestListDocs:
    def test_returns_md_files(self, fake_root):
        root, t = fake_root
        result = t.list_docs()
        assert "files" in result
        files = result["files"]
        assert any("SKILLS.md" in f for f in files)

    def test_no_non_md_files(self, fake_root):
        root, t = fake_root
        result = t.list_docs()
        for f in result["files"]:
            assert f.endswith(".md") or f.endswith(".txt"), f"Unexpected file: {f}"


# ---------------------------------------------------------------------------
# read_doc
# ---------------------------------------------------------------------------

class TestReadDoc:
    def test_reads_existing_doc(self, fake_root):
        root, t = fake_root
        result = t.read_doc("docs/SKILLS.md")
        assert "error" not in result
        assert "Skills" in result["content"]

    def test_missing_doc_returns_error(self, fake_root):
        root, t = fake_root
        result = t.read_doc("docs/nonexistent.md")
        assert "error" in result

    def test_path_traversal_blocked(self, fake_root):
        root, t = fake_root
        result = t.read_doc("../../etc/passwd")
        assert "error" in result


# ---------------------------------------------------------------------------
# read_source
# ---------------------------------------------------------------------------

class TestReadSource:
    def test_reads_go_file(self, fake_root):
        root, t = fake_root
        result = t.read_source("cmd/pilotctl/main.go")
        assert "error" not in result
        assert "main" in result["content"]

    def test_missing_file_returns_error(self, fake_root):
        root, t = fake_root
        result = t.read_source("cmd/pilotctl/nope.go")
        assert "error" in result

    def test_blocked_extension(self, fake_root):
        root, t = fake_root
        # Write a .exe-style file — not in allowed_extensions
        (root / "cmd" / "pilotctl" / "binary.exe").write_bytes(b"\x00\x01")
        result = t.read_source("cmd/pilotctl/binary.exe")
        assert "error" in result


# ---------------------------------------------------------------------------
# list_source_files
# ---------------------------------------------------------------------------

class TestListSourceFiles:
    def test_lists_top_level(self, fake_root):
        root, t = fake_root
        result = t.list_source_files("")
        assert "files" in result
        names = result["files"]
        assert any("cmd/" in f for f in names)

    def test_lists_subdirectory(self, fake_root):
        root, t = fake_root
        result = t.list_source_files("cmd")
        assert "files" in result
        assert any("pilotctl" in f for f in result["files"])

    def test_missing_dir_returns_error(self, fake_root):
        root, t = fake_root
        result = t.list_source_files("nonexistent")
        assert "error" in result


# ---------------------------------------------------------------------------
# search_source
# ---------------------------------------------------------------------------

class TestSearchSource:
    def test_finds_pattern(self, fake_root):
        root, t = fake_root
        result = t.search_source("package main")
        assert "matches" in result
        assert len(result["matches"]) >= 1
        assert any("main.go" in m["file"] for m in result["matches"])

    def test_no_match_returns_empty(self, fake_root):
        root, t = fake_root
        result = t.search_source("XYZZY_NOTHING_HERE_42")
        assert result["matches"] == []

    def test_invalid_regex_returns_error(self, fake_root):
        root, t = fake_root
        result = t.search_source("[invalid(regex")
        assert "error" in result


# ---------------------------------------------------------------------------
# _is_allowed sandbox
# ---------------------------------------------------------------------------

class TestIsAllowed:
    def test_allowed_path(self, fake_root):
        root, t = fake_root
        allowed = root / "docs" / "SKILLS.md"
        assert t._is_allowed(allowed) is True

    def test_blocked_path(self, fake_root, tmp_path):
        root, t = fake_root
        outside = Path("/etc/passwd")
        assert t._is_allowed(outside) is False
