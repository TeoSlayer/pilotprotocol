# Python SDK Development Guide

This guide is for developers working on the Pilot Protocol Python SDK.

## Important
To make use of the CI/CD pipeline that builds and publishes the python SDK for pilotprotocol, use following git branch naming convention: `build/*`

## Repository Structure

```
sdk/python/
├── pilotprotocol/           # Main package
│   ├── __init__.py         # Package exports
│   ├── client.py           # Core SDK implementation (ctypes FFI)
│   ├── cli.py              # Entry point wrappers for console scripts
│   └── bin/                # Go binaries (bundled in wheel)
│       ├── daemon          # Pilot daemon binary
│       ├── gateway         # Gateway binary
│       ├── pilotctl        # CLI binary
│       └── libpilot.*      # CGO shared library
├── tests/                  # Unit tests
│   └── test_client.py      # Test suite (61 tests, 100% coverage)
├── scripts/                # Build and maintenance scripts
│   ├── build-binaries.sh  # Build Go binaries for current platform
│   ├── build.sh           # Build Python wheel
│   ├── publish.sh         # Publish to PyPI/TestPyPI
│   ├── test-coverage.sh   # Run tests with coverage
│   └── generate-coverage-badge.sh  # Generate SVG badge
├── htmlcov/               # HTML coverage report (generated)
├── dist/                  # Build artifacts (generated)
├── pyproject.toml         # Package metadata and build config
├── MANIFEST.in            # Files to include in distribution
├── LICENSE                # AGPL-3.0 license
├── CHANGELOG.md           # Version history
├── README.md              # User documentation
├── Makefile               # Development tasks
└── .gitignore            # Git ignore patterns
```

## Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/TeoSlayer/pilotprotocol.git
   cd pilotprotocol/sdk/python
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # or `venv\Scripts\activate` on Windows
   ```

3. **Install in development mode with dev dependencies:**
   ```bash
   make install-dev
   # or manually:
   pip install -e .[dev]
   ```
   
   This installs:
   - The `pilotprotocol` package in editable mode
   - Console script entry points: `pilotctl`, `pilot-daemon`, `pilot-gateway`
   - Dev dependencies: pytest, pytest-cov, mypy, build, twine

4. **Build the Go binaries:**
   ```bash
   cd ../..  # back to repo root
   make sdk-lib  # Builds libpilot CGO library
   
   # Or build all binaries for SDK
   cd sdk/python
   make build  # Runs scripts/build-binaries.sh + scripts/build.sh
   ```

## Entry Point Architecture

The SDK uses modern Python packaging with console script entry points defined in `pyproject.toml`:

```toml
[project.scripts]
pilotctl = "pilotprotocol.cli:run_pilotctl"
pilot-daemon = "pilotprotocol.cli:run_daemon"
pilot-gateway = "pilotprotocol.cli:run_gateway"
```

When users install the package, `pip` creates executable scripts that call these entry points:

1. **User runs:** `pilotctl register MyOrg`
2. **Entry point calls:** `pilotprotocol.cli:run_pilotctl()`
3. **Wrapper finds binary:** `site-packages/pilotprotocol/bin/pilotctl`
4. **Wrapper executes binary:** `subprocess.call([binary_path, "register", "MyOrg"])`

### Entry Point Wrappers (`pilotprotocol/cli.py`)

Each wrapper function:
- **Ensures environment**: Creates `~/.pilot/` and `config.json` on first use
- **Resolves binary**: Finds binary in package installation
- **Executes subprocess**: Passes through all arguments and returns exit code

### State Management

- **Package code**: Installed in `site-packages/pilotprotocol/`
- **Binaries**: Bundled in wheel at `pilotprotocol/bin/`
- **User state**: Created lazily in `~/.pilot/` (logs, cache, persistent data)
- **Config**: `~/.pilot/config.json` with daemon socket path

This approach:
- ✅ Works with all Python package managers (pip, pipx, poetry, etc.)
- ✅ No post-install hooks or custom setup.py needed
- ✅ Clean separation between code and state
- ✅ Standard Python packaging practices

## Running Tests

```bash
# Run all tests
make test

# Run with coverage
make test-coverage

# Generate coverage badge
make coverage-badge
```

The test suite includes:
- 61 unit tests
- 100% code coverage
- Mocked C boundary (no daemon required)
- Tests for all error paths and edge cases

## Building for PyPI

### Local Build

```bash
# Build wheel and source distribution
make build

# Check package validity
twine check dist/*

# View build artifacts
ls -lh dist/
```

The build process:
1. **Build Go binaries** (`scripts/build-binaries.sh`):
   - Compiles daemon, gateway, pilotctl for current platform
   - Builds CGO shared library (libpilot.so/dylib/dll)
   - Places binaries in `pilotprotocol/bin/`

2. **Build Python wheel** (`scripts/build.sh`):
   - Creates wheel with binaries included (~7.8 MB)
   - Entry points defined in `pyproject.toml`:
     - `pilotctl` → `pilotprotocol.cli:run_pilotctl`
     - `pilot-daemon` → `pilotprotocol.cli:run_daemon`
     - `pilot-gateway` → `pilotprotocol.cli:run_gateway`

### Multi-Platform Builds (GitHub Actions)

For production releases, use GitHub Actions to build wheels for all platforms:

1. **Push to build branch:**
   ```bash
   git checkout -b build/your-feature
   git push origin build/your-feature
   ```

2. **Trigger workflow manually:**
   - Go to **Actions** tab → **Publish Python SDK**
   - Click **Run workflow**
   - Select branch (`build/your-feature` for TestPyPI, `main` for PyPI)
   - Click **Run workflow**

3. **Approve deployment:**
   - Workflow builds wheels on Linux, macOS, Windows
   - For TestPyPI (build/* branches): Requires **test** environment approval
   - For PyPI (main branch): Requires **production** environment approval
   - Check artifacts in workflow run before approving

4. **Post-publish verification:**
   - Workflow automatically tests installation on all platforms
   - Verifies CLI commands and Python imports work

**Important:** Push events trigger builds but **do not publish**. You must manually run the workflow and approve deployment.

## Publishing
Ensure your git branch name starts with `build/`

## Code Quality

### Type Checking

The SDK uses comprehensive type hints. Verify with:
```bash
mypy pilotprotocol/
```

### Coverage Requirements

- Maintain 100% test coverage
- Use `# pragma: no cover` only for:
  - Platform-specific code paths
  - Library loading functions (tested at import time)
  - Debug/logging code

### Testing Guidelines

- Mock the C boundary with `FakeLib`
- Test both success and error paths
- Verify memory management (FreeString calls)
- Test edge cases (closed connections, empty responses, etc.)

## CI/CD Workflow

### GitHub Actions Pipeline

The SDK uses GitHub Actions for automated multi-platform builds and publishing.

#### Workflow File

`.github/workflows/publish-python-sdk.yml`

#### Triggers

- **Manual only** (`workflow_dispatch`): Ensures intentional releases with human approval
- **Branch filter**: 
  - `main` → Production (PyPI)
  - `build/**` → Test (TestPyPI)

#### Jobs

1. **setup**
   - Determines target environment (production/test)
   - Validates branch naming conventions
   - Sets up approval requirements

2. **build-wheels** (matrix: ubuntu, macos, windows)
   - Checks out code
   - Installs Go 1.21+
   - Builds platform-specific binaries
   - Builds Python wheel
   - Uploads artifacts for inspection

3. **publish** (requires environment approval)
   - Downloads all platform wheels
   - Publishes to PyPI or TestPyPI based on branch
   - Uses GitHub environment protection for approval gate

4. **test-install** (matrix: ubuntu, macos, windows)
   - Installs published package
   - Verifies CLI commands work
   - Tests Python SDK imports

#### Environment Protection

**Setup required in GitHub repository settings:**

1. Go to **Settings** → **Environments**

2. Create **production** environment:
   - Deployment branches: `main` only
   - Required reviewers: Add maintainers
   - Enable "Prevent self-review" (optional)
   - Secrets: `PYPI_API_TOKEN`

3. Create **test** environment:
   - Deployment branches: `build/**` pattern
   - Required reviewers: Optional
   - Secrets: `TEST_PYPI_API_TOKEN`

#### Running the Workflow

1. **Navigate to Actions tab** in GitHub repository

2. **Select "Publish Python SDK"** workflow

3. **Click "Run workflow"**:
   - Select branch (main or build/*)
   - Click green "Run workflow" button

4. **Monitor build progress**:
   - Wait for build-wheels jobs to complete
   - Inspect artifacts if needed

5. **Approve deployment**:
   - Click "Review deployments" button
   - Review changes and artifacts
   - Approve or reject deployment

6. **Verify installation**:
   - Wait for test-install jobs to complete
   - Check logs for successful CLI execution

#### Best Practices

- **Never bypass approval**: Even for hotfixes, use the workflow
- **Test on TestPyPI first**: Use build/* branches before merging to main
- **Inspect artifacts**: Download and test wheels before approving
- **Monitor test-install**: Ensure package works on all platforms
- **Use semantic versioning**: Bump version appropriately before release

#### Troubleshooting Workflow Issues

**Build fails on specific platform:**
- Check Go installation in workflow logs
- Verify CGO compilation (requires gcc/clang)
- Review platform-specific build errors

**Publish fails with 403:**
- Verify API tokens are set in environment secrets
- Check token scope includes upload permissions
- Ensure token hasn't expired

**Test-install fails:**
- Check if package name conflicts with existing package
- Verify wheel architecture matches platform
- Review CLI execution errors in logs

## Architecture Notes

### FFI Boundary

The SDK uses `ctypes` to call Go functions exported via CGO:

```python
# Python side (ctypes)
lib.PilotConnect(socket_path.encode())

# Go side (CGO)
//export PilotConnect
func PilotConnect(socketPath *C.char) C.HandleErr { ... }
```

All Go functions return either:
- `*C.char` (JSON string or error)
- Struct with handle + error pointer
- Specialized result structs (ReadResult, WriteResult)

### Memory Management

- Python calls `FreeString()` for every returned `*C.char`
- Context managers (`__enter__`/`__exit__`) ensure cleanup
- `__del__` methods provide fallback cleanup (catches exceptions)

### Handle Pattern

Go maintains a global `map[uint64]interface{}` storing Driver/Conn/Listener objects. Python passes uint64 handles in every call. This avoids exposing Go pointers across the CGO boundary.

## Version Bumping

### Manual Version Bump

1. Update version in `pyproject.toml`:
   ```toml
   [project]
   version = "0.2.2"
   ```

2. Add entry to `CHANGELOG.md`:
   ```markdown
   ## [0.2.2] - 2024-01-15
   ### Added
   - New feature description
   ### Fixed
   - Bug fix description
   ```

3. Commit changes:
   ```bash
   git add pyproject.toml CHANGELOG.md
   git commit -m "chore: bump version to 0.2.2"
   ```

4. Tag release:
   ```bash
   git tag -a v0.2.2 -m "Release 0.2.2"
   git push --follow-tags
   ```

### Release Workflow

**For TestPyPI (validation):**
```bash
# 1. Create build branch
git checkout -b build/v0.2.2

# 2. Bump version
# Edit pyproject.toml, CHANGELOG.md

# 3. Commit and push
git commit -am "chore: bump version to 0.2.2"
git push origin build/v0.2.2

# 4. Publish via GitHub Actions
# Actions → Run workflow → build/v0.2.2 → Approve test deployment

# 5. Test installation
pip install --index-url https://test.pypi.org/simple/ pilotprotocol
```

**For PyPI (production):**
```bash
# 1. Merge to main after TestPyPI validation
git checkout main
git merge build/v0.2.2

# 2. Tag release
git tag -a v0.2.2 -m "Release 0.2.2"
git push --follow-tags

# 3. Publish via GitHub Actions
# Actions → Run workflow → main → Approve production deployment
```

**Version Numbering:**
- **Patch** (0.2.x): Bug fixes, minor improvements
- **Minor** (0.x.0): New features, backward compatible
- **Major** (x.0.0): Breaking changes

## Troubleshooting

### Import Error: Cannot find libpilot

Ensure the shared library is built:
```bash
cd ../../  # repo root
make sdk-lib
```

Set `PILOT_LIB_PATH` if needed:
```bash
export PILOT_LIB_PATH=/path/to/libpilot.so
```

### Tests Fail: Connection Refused

The tests mock the C boundary and don't require a daemon. If you're seeing connection errors, ensure you're running the test suite, not the examples.

### Build Fails: Missing Dependencies

Install build dependencies:
```bash
pip install build twine
```

## Contributing

See [CONTRIBUTING.md](../../CONTRIBUTING.md) in the repository root.

## Quick Reference

### Common Development Commands

```bash
# Setup
make install-dev              # Install in dev mode with dependencies
make build                    # Build binaries + wheel

# Testing
make test                     # Run tests
make test-coverage            # Run tests with coverage report
make coverage-badge           # Generate coverage badge

# Publishing
make publish-test             # Publish to TestPyPI
make publish                  # Publish to PyPI (with confirmation)

# Cleanup
make clean                    # Remove build artifacts
```

### GitHub Actions Quick Start

```bash
# Test release workflow
git checkout -b build/test-v0.2.2
# ... make changes, bump version ...
git push origin build/test-v0.2.2
# → Go to Actions → Run workflow → Approve test deployment

# Production release workflow
git checkout main
git merge build/test-v0.2.2
git tag -a v0.2.2 -m "Release 0.2.2"
git push --follow-tags
# → Go to Actions → Run workflow → Approve production deployment
```

### File Locations

```
# Package code
site-packages/pilotprotocol/          # Installed package
site-packages/pilotprotocol/bin/      # Bundled binaries

# User state
~/.pilot/                             # State directory
~/.pilot/config.json                  # Configuration
~/.pilot/pilot.sock                   # Daemon socket

# Entry points (created by pip)
/usr/local/bin/pilotctl               # CLI command
/usr/local/bin/pilot-daemon           # Daemon command
/usr/local/bin/pilot-gateway          # Gateway command
```

## License

AGPL-3.0-or-later — See [LICENSE](LICENSE)
