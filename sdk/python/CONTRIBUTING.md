# Python SDK Development Guide

This guide is for developers working on the Pilot Protocol Python SDK.

## Repository Structure

```
sdk/python/
├── pilotprotocol/           # Main package
│   ├── __init__.py         # Package exports
│   └── client.py           # Core SDK implementation (ctypes FFI)
├── tests/                  # Unit tests
│   └── test_client.py      # Test suite (61 tests, 100% coverage)
├── scripts/                # Build and maintenance scripts
│   ├── build.sh           # Build wheel and sdist
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

4. **Build the Go shared library:**
   ```bash
   cd ../..  # back to repo root
   make sdk-lib
   ```

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

```bash
# Build wheel and source distribution
make build

# Check package validity
twine check dist/*

# View build artifacts
ls -lh dist/
```

## Publishing

### TestPyPI (for testing)

```bash
make publish-test
```

Then test installation:
```bash
pip install --index-url https://test.pypi.org/simple/ pilotprotocol
```

### PyPI (production)

```bash
make publish
```

You'll be prompted for confirmation before publishing.

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

1. Update version in `pyproject.toml`
2. Add entry to `CHANGELOG.md`
3. Commit changes
4. Tag release: `git tag -a v0.2.1 -m "Release 0.2.1"`
5. Push: `git push --follow-tags`
6. Build and publish: `make build && make publish`

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

## License

AGPL-3.0-or-later — See [LICENSE](LICENSE)
