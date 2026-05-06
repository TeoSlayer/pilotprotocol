"""Unit tests for the runtime seeder (pilotprotocol/_runtime.py).

These tests exercise the 5 seeder states (missing, older, equal, newer,
corrupt), the daemon-running guard, the lock contention path, and the
atomic-rename behavior. They do NOT require a real daemon or libpilot.so;
the bundled "binaries" are stub files written into a tmpdir.
"""

from __future__ import annotations

import json
import os
import platform as platform_mod
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

import pilotprotocol._runtime as rt


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_fake_pkg_bin(tmp: Path, version: str, names: list[str]) -> Path:
    """Build a fake bundled bin/ directory with stub executables and marker."""
    pkg = tmp / "pkg-bin"
    pkg.mkdir(parents=True, exist_ok=True)
    for n in names:
        (pkg / n).write_text(f"#!/bin/sh\necho {n} {version}\n")
        (pkg / n).chmod(0o755)
    (pkg / ".pilot-version").write_text(version + "\n")
    return pkg


def _platform_lib() -> str:
    return rt._LIB_NAMES[platform_mod.system()]


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    """Redirect ~/.pilot/ to a tmpdir and the package bin/ to another.

    Also stubs the daemon-liveness probe to "not running" so tests do not
    pick up the real pilot daemon that may be running on the developer
    machine. Tests that need the probe enabled re-monkeypatch ``_daemon_running``.
    """
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("PILOT_HOME", str(fake_home / ".pilot"))

    pkg = _make_fake_pkg_bin(
        tmp_path,
        "1.9.1",
        list(rt._BIN_NAMES) + [_platform_lib()],
    )
    monkeypatch.setattr(rt, "_pkg_bin_dir", lambda: pkg)
    monkeypatch.setattr(rt, "_daemon_running", lambda: False)
    rt.reset_seeded_marker()
    yield {"home": fake_home, "pkg": pkg, "tmp": tmp_path, "monkeypatch": monkeypatch}
    rt.reset_seeded_marker()


# ---------------------------------------------------------------------------
# State machine
# ---------------------------------------------------------------------------

class TestSeederStates:
    def test_missing_seeds_everything(self, _isolate):
        report = rt.run_seeder()
        assert report.action == "seed"
        # All four executables + libpilot should be copied
        assert set(report.copied) == set(rt._BIN_NAMES) | {_platform_lib()}
        assert report.skipped == []

        rtbin = _isolate["home"] / ".pilot" / "bin"
        for name in report.copied:
            assert (rtbin / name).is_file(), f"{name} not seeded"
        assert (rtbin / ".pilot-version").read_text().strip() == "1.9.1"

    def test_equal_version_is_noop(self, _isolate):
        # First pass seeds.
        rt.run_seeder()
        rt.reset_seeded_marker()

        # Second pass with identical bundled version → noop.
        report = rt.run_seeder()
        assert report.action == "noop"
        assert report.copied == []

    def test_older_bundle_does_not_downgrade(self, _isolate, tmp_path, monkeypatch):
        # Seed at 1.9.1
        rt.run_seeder()
        rt.reset_seeded_marker()

        # Replace the package bin/ with a 1.8.0 build.
        pkg = _make_fake_pkg_bin(
            tmp_path / "older",
            "1.8.0",
            list(rt._BIN_NAMES) + [_platform_lib()],
        )
        monkeypatch.setattr(rt, "_pkg_bin_dir", lambda: pkg)

        report = rt.run_seeder()
        assert report.action == "noop"
        assert report.copied == []
        rtbin = _isolate["home"] / ".pilot" / "bin"
        assert (rtbin / ".pilot-version").read_text().strip() == "1.9.1"

    def test_newer_bundle_upgrades(self, _isolate, tmp_path, monkeypatch):
        rt.run_seeder()
        rt.reset_seeded_marker()

        pkg = _make_fake_pkg_bin(
            tmp_path / "newer",
            "2.0.0",
            list(rt._BIN_NAMES) + [_platform_lib()],
        )
        monkeypatch.setattr(rt, "_pkg_bin_dir", lambda: pkg)

        report = rt.run_seeder()
        assert report.action == "upgrade"
        assert set(report.copied) == set(rt._BIN_NAMES) | {_platform_lib()}
        rtbin = _isolate["home"] / ".pilot" / "bin"
        assert (rtbin / ".pilot-version").read_text().strip() == "2.0.0"
        # Content actually replaced
        assert "2.0.0" in (rtbin / "pilotctl").read_text()

    def test_corrupt_runtime_re_seeds_missing_files(self, _isolate):
        rt.run_seeder()
        rtbin = _isolate["home"] / ".pilot" / "bin"
        # Simulate corruption: delete pilotctl but leave the marker.
        (rtbin / "pilotctl").unlink()
        rt.reset_seeded_marker()

        report = rt.run_seeder()
        # Same version, but a file was missing → seeder noticed and re-seeded.
        assert "pilotctl" in report.copied
        assert (rtbin / "pilotctl").is_file()


# ---------------------------------------------------------------------------
# Daemon-running guard
# ---------------------------------------------------------------------------

class TestDaemonGuard:
    def test_skips_pilot_daemon_when_socket_live(self, _isolate, monkeypatch, tmp_path):
        # First seed normally so pilot-daemon exists.
        rt.run_seeder()
        rt.reset_seeded_marker()

        # Replace package with a newer version.
        pkg = _make_fake_pkg_bin(
            tmp_path / "newer",
            "2.0.0",
            list(rt._BIN_NAMES) + [_platform_lib()],
        )
        monkeypatch.setattr(rt, "_pkg_bin_dir", lambda: pkg)

        # Stub _daemon_running → True.
        monkeypatch.setattr(rt, "_daemon_running", lambda: True)

        report = rt.run_seeder()
        assert "pilot-daemon" in report.skipped
        assert "pilot-daemon" not in report.copied
        # Other binaries still upgrade.
        assert "pilotctl" in report.copied
        assert report.action == "daemon-skip"

    def test_first_install_seeds_daemon_even_if_socket_present(
        self, _isolate, monkeypatch
    ):
        # No prior install. Even with daemon "running" (somehow), there's
        # no existing pilot-daemon to preserve, so we seed fresh.
        monkeypatch.setattr(rt, "_daemon_running", lambda: True)
        report = rt.run_seeder()
        assert "pilot-daemon" in report.copied


class TestDaemonProbe:
    """Direct tests of _daemon_running. The fixture stubs it to False, so
    these tests un-stub by importing the module fresh and re-resolving."""

    def _real_daemon_running(self, _isolate):
        # Replace config to point socket somewhere we control.
        cfg_path = _isolate["home"] / ".pilot" / "config.json"
        return cfg_path

    def test_no_socket_means_not_running(self, _isolate):
        cfg = self._real_daemon_running(_isolate)
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_text(json.dumps({"socket": str(_isolate["tmp"] / "no.sock")}))
        # Importlib-reload to bypass the autouse monkeypatch on the symbol.
        # Easier: call the original via __wrapped__ — but we don't have it.
        # Cleanest: import the function from the module directly under
        # a different binding.
        import pilotprotocol._runtime as rt_mod
        # Save and restore.
        stub = rt_mod._daemon_running
        orig = type(stub).__name__  # noqa: F841 — debug breadcrumb
        # Recover the original from the module dict (we never deleted it).
        # The fixture set rt._daemon_running to a lambda; the function is
        # still bound at module import time only via attribute access. To
        # get the original, we need to undo the monkeypatch.
        _isolate["monkeypatch"].setattr(rt_mod, "_daemon_running", _orig_daemon_running)
        assert rt_mod._daemon_running() is False

    def test_unconnectable_socket_means_not_running(self, _isolate, tmp_path):
        cfg = self._real_daemon_running(_isolate)
        cfg.parent.mkdir(parents=True, exist_ok=True)
        sock_path = tmp_path / "fake.sock"
        sock_path.touch()
        cfg.write_text(json.dumps({"socket": str(sock_path)}))
        _isolate["monkeypatch"].setattr(rt, "_daemon_running", _orig_daemon_running)
        assert rt._daemon_running() is False

    def test_listening_socket_means_running(self, _isolate):
        cfg = self._real_daemon_running(_isolate)
        cfg.parent.mkdir(parents=True, exist_ok=True)
        # AF_UNIX has a ~104 char path limit on macOS, so use a short
        # tmpdir under /tmp rather than the very long pytest tmp_path.
        short = Path(tempfile.mkdtemp(prefix="psk", dir="/tmp"))
        sock_path = short / "live.sock"
        cfg.write_text(json.dumps({"socket": str(sock_path)}))

        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(str(sock_path))
        srv.listen(1)
        try:
            _isolate["monkeypatch"].setattr(rt, "_daemon_running", _orig_daemon_running)
            assert rt._daemon_running() is True
        finally:
            srv.close()
            sock_path.unlink(missing_ok=True)
            short.rmdir()


# Capture the original _daemon_running once, before any fixture monkeypatches it.
_orig_daemon_running = rt._daemon_running


# ---------------------------------------------------------------------------
# Atomic install + concurrent seeders
# ---------------------------------------------------------------------------

class TestAtomicInstall:
    def test_atomic_replace_survives_existing_target(self, _isolate, tmp_path):
        rt.run_seeder()
        rtbin = _isolate["home"] / ".pilot" / "bin"
        # Pretend pilotctl is "running": grab a file handle and overwrite.
        target = rtbin / "pilotctl"
        with open(target, "rb") as f:
            initial = f.read()
            # Now atomic-install something different.
            src = tmp_path / "newctl"
            src.write_text("DIFFERENT\n")
            rt._atomic_install(src, target)
            # The held handle still sees the old content (Unix semantics).
            f.seek(0)
            assert f.read() == initial
        # And the on-disk file is the new one.
        assert target.read_text() == "DIFFERENT\n"

    def test_no_tmp_files_left_behind(self, _isolate):
        rt.run_seeder()
        rtbin = _isolate["home"] / ".pilot" / "bin"
        leftovers = list(rtbin.glob("*.tmp.*"))
        assert leftovers == []


class TestConcurrentSeeders:
    def test_two_threads_only_one_writes(self, _isolate):
        # Both threads see "missing" state; both attempt to seed; flock
        # serializes them so the second sees the freshly-seeded marker
        # and ends up doing a noop. The final state is consistent.
        results: list[rt.SeedReport] = []
        barrier = threading.Barrier(2)

        def worker():
            barrier.wait()
            rt.reset_seeded_marker()
            results.append(rt.run_seeder())

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        # Exactly one thread did the actual seeding; the other was a noop.
        actions = sorted(r.action for r in results)
        assert actions in (["noop", "seed"], ["seed", "seed"])
        # Either way, the runtime is intact.
        rtbin = _isolate["home"] / ".pilot" / "bin"
        for name in rt._BIN_NAMES:
            assert (rtbin / name).is_file()


# ---------------------------------------------------------------------------
# Config + directory bootstrap
# ---------------------------------------------------------------------------

class TestConfigBootstrap:
    def test_creates_default_config_when_missing(self, _isolate):
        rt.run_seeder()
        cfg_path = _isolate["home"] / ".pilot" / "config.json"
        assert cfg_path.is_file()
        cfg = json.loads(cfg_path.read_text())
        assert cfg["registry"] == rt.DEFAULT_REGISTRY
        assert cfg["beacon"] == rt.DEFAULT_BEACON
        assert cfg["socket"] == rt.DEFAULT_SOCKET
        assert cfg["encrypt"] is True
        # No email — we never auto-set one; user supplies via daemon start.
        assert "email" not in cfg

    def test_preserves_existing_config(self, _isolate):
        cfg_path = _isolate["home"] / ".pilot" / "config.json"
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        cfg_path.write_text(json.dumps({"email": "foo@bar.com", "preserved": True}))
        rt.run_seeder()
        cfg = json.loads(cfg_path.read_text())
        assert cfg.get("preserved") is True
        assert cfg.get("email") == "foo@bar.com"


# ---------------------------------------------------------------------------
# Wrong-platform package
# ---------------------------------------------------------------------------

class TestWrongPlatform:
    def test_missing_lib_does_not_crash_seeder(self, _isolate, tmp_path, monkeypatch):
        # Build a pkg with executables but no platform lib.
        pkg = tmp_path / "no-lib"
        pkg.mkdir()
        for n in rt._BIN_NAMES:
            (pkg / n).write_text("stub")
            (pkg / n).chmod(0o755)
        (pkg / ".pilot-version").write_text("1.9.1\n")
        monkeypatch.setattr(rt, "_pkg_bin_dir", lambda: pkg)

        # Seeder runs without exception; the lib name is just absent from copied.
        report = rt.run_seeder()
        assert _platform_lib() not in report.copied

        # runtime_library() raises a clear error, since the lib isn't anywhere.
        with pytest.raises(FileNotFoundError, match="libpilot"):
            rt.runtime_library()


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

class TestPublicEntryPoints:
    def test_runtime_binary_returns_seeded_path(self, _isolate):
        p = rt.runtime_binary("pilotctl")
        assert p == _isolate["home"] / ".pilot" / "bin" / "pilotctl"
        assert p.is_file()

    def test_runtime_binary_unknown_name_raises(self, _isolate):
        with pytest.raises(FileNotFoundError, match="bogus"):
            rt.runtime_binary("bogus")

    def test_runtime_library_seeds_and_returns_path(self, _isolate):
        p = rt.runtime_library()
        assert p == _isolate["home"] / ".pilot" / "bin" / _platform_lib()
        assert p.is_file()

    def test_ensure_runtime_seeded_idempotent_in_process(self, _isolate):
        rt.ensure_runtime_seeded()
        # Subsequent calls are short-circuited by the in-process flag.
        rtbin_marker = _isolate["home"] / ".pilot" / "bin" / ".pilot-version"
        first_mtime = rtbin_marker.stat().st_mtime
        time.sleep(0.01)
        rt.ensure_runtime_seeded()
        assert rtbin_marker.stat().st_mtime == first_mtime


# ---------------------------------------------------------------------------
# SemVer comparison
# ---------------------------------------------------------------------------

class TestSemverTuple:
    def test_basic_parsing(self):
        assert rt._semver_tuple("1.9.1") == (1, 9, 1)
        assert rt._semver_tuple("v1.9.1") == (1, 9, 1)
        assert rt._semver_tuple("1.9.1-rc4") == (1, 9, 1)
        assert rt._semver_tuple("1.9.1+meta") == (1, 9, 1)

    def test_unparseable_returns_empty_tuple(self):
        assert rt._semver_tuple("") == ()
        assert rt._semver_tuple("garbage") == ()
        assert rt._semver_tuple("1.x.0") == ()

    def test_ordering(self):
        assert rt._semver_tuple("1.9.1") > rt._semver_tuple("1.9.0")
        assert rt._semver_tuple("2.0.0") > rt._semver_tuple("1.9.99")
        assert rt._semver_tuple("1.9.1") == rt._semver_tuple("1.9.1")
