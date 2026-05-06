"""Command-line entry points for the Pilot Protocol CLI binaries.

The wheel ships pre-built Go binaries inside ``pilotprotocol/bin/``. On
first call, :mod:`pilotprotocol._runtime` mirrors those into
``~/.pilot/bin/`` (the canonical runtime directory shared with
``install.sh``) and these wrappers exec the seeded copy.

This means:
- pip-installed and curl-installed users converge on the same daemon.
- Multiple venvs, multiple SDK versions: highest version wins, no
  parallel binary trees.
- Uninstalling the wheel never deletes ``~/.pilot/`` (identity, config,
  daemon state are preserved).
"""

import subprocess
import sys

from ._runtime import ensure_runtime_seeded, runtime_binary


def _exec_runtime_binary(name: str) -> None:
    """Seed ``~/.pilot/bin/`` if needed, then exec the named binary."""
    ensure_runtime_seeded()
    binary = runtime_binary(name)
    sys.exit(subprocess.call([str(binary)] + sys.argv[1:]))


def run_pilotctl() -> None:
    """Entry point for the ``pilotctl`` console script."""
    _exec_runtime_binary("pilotctl")


def run_daemon() -> None:
    """Entry point for the ``pilot-daemon`` console script.

    Note: the daemon needs an email address (passed via ``--email`` or
    set in ``~/.pilot/config.json``) to register at the registry. The
    SDK does not auto-prompt for one — call::

        pilotctl daemon start --email you@example.com

    on first launch, after which the email is cached in ``config.json``.
    """
    _exec_runtime_binary("pilot-daemon")


def run_gateway() -> None:
    """Entry point for the ``pilot-gateway`` console script."""
    _exec_runtime_binary("pilot-gateway")


def run_updater() -> None:
    """Entry point for the ``pilot-updater`` console script."""
    _exec_runtime_binary("pilot-updater")
