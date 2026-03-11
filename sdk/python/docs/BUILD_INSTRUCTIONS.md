# Building Pilot Protocol Python SDK for PyPI

This guide explains how to build platform-specific wheels for PyPI distribution using modern Python packaging with entry points.

## Overview

The Python SDK bundles the **complete Pilot Protocol suite**:
- `pilot-daemon` - Background service
- `pilotctl` - Command-line interface  
- `pilot-gateway` - IP traffic bridge
- `libpilot.{so|dylib|dll}` - CGO bindings for Python

**Architecture:**
- Binaries are bundled in the wheel at `pilotprotocol/bin/`
- Entry points create console scripts that wrap the binaries
- State directory `~/.pilot/` is created on first command execution
- No post-install scripts needed - pure `pyproject.toml` configuration

## Build Requirements

### macOS
```bash
# Install Go
brew install go

# Install Python build tools
pip install build twine
```

### Linux
```bash
# Install Go
sudo apt-get update
sudo apt-get install golang-go gcc

# Install Python build tools
pip install build twine
```

### Windows
```powershell
# Install Go from https://go.dev/dl/
# Install GCC via MinGW or MSYS2

# Install Python build tools
pip install build twine
```

## Building for Your Platform

### 1. Clone the repository
```bash
git clone https://github.com/TeoSlayer/pilotprotocol.git
cd pilotprotocol/sdk/python
```

### 2. Run the build script
```bash
./scripts/build.sh
```

This script:
1. Builds `pilot-daemon`, `pilotctl`, `pilot-gateway` (Go binaries)
2. Builds `libpilot.{so|dylib|dll}` (CGO shared library)
3. Copies all binaries to `pilotprotocol/bin/`
4. Builds the Python wheel and source distribution
5. Verifies with `twine check`

### 3. Test installation locally
```bash
# Create test venv
python3 -m venv /tmp/test-pilot
source /tmp/test-pilot/bin/activate

# Install wheel
pip install dist/pilotprotocol-*.whl

# Test entry points
pilotctl info
pilot-daemon --help
pilot-gateway --help

# Verify Python SDK
python -c "from pilotprotocol import Driver; print('✓ SDK works')"

# Check auto-created config
cat ~/.pilot/config.json

# Cleanup
deactivate
rm -rf /tmp/test-pilot
```

## Publishing to PyPI

### Test on TestPyPI First
```bash
./scripts/publish.sh testpypi

# Test installation
pip install --index-url https://test.pypi.org/simple/ pilotprotocol
```

### Publish to Production
```bash
./scripts/publish.sh pypi
```

## User Installation Flow

When users run `pip install pilotprotocol`:

1. **Wheel downloaded** from PyPI (~7-8 MB)
2. **Package extracted** to `site-packages/pilotprotocol/`
3. **Entry points created** in `venv/bin/`:
   - `pilotctl` → `pilotprotocol.cli:run_pilotctl`
   - `pilot-daemon` → `pilotprotocol.cli:run_daemon`
   - `pilot-gateway` → `pilotprotocol.cli:run_gateway`

4. **First command execution** creates `~/.pilot/config.json`

Users can immediately use:
```bash
# CLI commands
pilotctl daemon start --hostname my-agent

# Python SDK
from pilotprotocol import Driver
d = Driver()
```

## Benefits

✅ **Pure pyproject.toml** - No setup.py needed
✅ **Standard Python** - Works with pip, pipx, poetry, conda
✅ **Clean separation** - Code in site-packages, state in ~/.pilot
✅ **PyPI compliant** - No external downloads during install
✅ **Cross-platform** - Same approach works everywhere
