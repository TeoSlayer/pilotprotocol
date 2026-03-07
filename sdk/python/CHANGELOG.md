# Changelog

All notable changes to the Pilot Protocol Python SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-03

### Added
- **Complete Pilot Protocol suite**: Bundles daemon, CLI tools (pilotctl), and gateway in wheel
- **Entry point console scripts**: `pilotctl`, `pilot-daemon`, and `pilot-gateway` available immediately after install
- **Automatic environment setup**: Creates `~/.pilot/` directory and `config.json` on first command execution
- **Bundled binaries**: Pre-built Go binaries and CGO shared libraries included in wheel for each platform
- **Modern packaging**: Pure `pyproject.toml` configuration using `[project.scripts]` entry points
- **Cross-platform support**: Platform-specific wheels for macOS, Linux, Windows
- **Type checking support**: `py.typed` marker file for static type checkers
- **Library auto-discovery**: Python SDK automatically finds `libpilot` in package directory or `~/.pilot/bin/`

### Changed
- **No setup.py**: Switched to modern `pyproject.toml`-only packaging
- **No post-install hooks**: Entry points replace custom installation logic
- **State separation**: Code stays in `site-packages/`, state goes to `~/.pilot/`
- **Simplified installation**: Single `pip install pilotprotocol` gets everything working
