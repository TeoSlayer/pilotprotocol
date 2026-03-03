# PyPI Publishing Guide

This guide explains how to publish the Pilot Protocol Python SDK to PyPI and TestPyPI.

## Prerequisites

### 1. Install Publishing Tools

```bash
pip install build twine
```

### 2. Create PyPI Accounts

- **TestPyPI** (testing): https://test.pypi.org/account/register/
- **PyPI** (production): https://pypi.org/account/register/

### 3. Create API Tokens

#### TestPyPI Token
1. Go to https://test.pypi.org/manage/account/#api-tokens
2. Click "Add API token"
3. Name: `pilotprotocol-upload`
4. Scope: `Entire account` (or specific project after first upload)
5. Copy the token (starts with `pypi-`)

#### PyPI Token
1. Go to https://pypi.org/manage/account/#api-tokens
2. Click "Add API token"
3. Name: `pilotprotocol-upload`
4. Scope: `Entire account` (or specific project after first upload)
5. Copy the token (starts with `pypi-`)

### 4. Configure Credentials

Create or edit `~/.pypirc`:

```ini
[distutils]
index-servers =
    pypi
    testpypi

[pypi]
username = __token__
password = pypi-YOUR_PRODUCTION_TOKEN_HERE

[testpypi]
repository = https://test.pypi.org/legacy/
username = __token__
password = pypi-YOUR_TEST_TOKEN_HERE
```

**Security:** Make sure the file has proper permissions:
```bash
chmod 600 ~/.pypirc
```

## Publishing Workflow

### Step 1: Update Version

Edit `pyproject.toml`:
```toml
[project]
version = "0.1.0"  # Increment for each release
```

### Step 2: Update Changelog

Edit `CHANGELOG.md` with release notes:
```markdown
## [0.1.0] - 2026-03-03

### Added
- Feature 1
- Feature 2

### Fixed
- Bug fix 1
```

### Step 3: Build Package

```bash
cd sdk/python
./scripts/build.sh
```

This creates:
- `dist/pilotprotocol-0.1.0-py3-none-any.whl` (~7.8 MB)
- `dist/pilotprotocol-0.1.0.tar.gz` (~7.8 MB)

### Step 4: Test on TestPyPI

```bash
./scripts/publish.sh testpypi
```

This will:
1. Verify package integrity with `twine check`
2. Upload to https://test.pypi.org
3. Show installation instructions

### Step 5: Test Installation from TestPyPI

```bash
# Create test environment
python3 -m venv /tmp/test-pypi
source /tmp/test-pypi/bin/activate

# Install from TestPyPI
pip install --index-url https://test.pypi.org/simple/ --no-deps pilotprotocol

# Test CLI
pilotctl info

# Test Python SDK
python -c "from pilotprotocol import Driver; print('✓ SDK works')"

# Verify config creation
cat ~/.pilot/config.json

# Cleanup
deactivate
rm -rf /tmp/test-pypi
```

### Step 6: Publish to Production PyPI

```bash
./scripts/publish.sh pypi
```

⚠️ **Warning:** This publishes to production PyPI. You will be asked to confirm.

This will:
1. Verify package integrity
2. Ask for confirmation
3. Upload to https://pypi.org
4. Show installation instructions

### Step 7: Verify Production Installation

```bash
# Create test environment
python3 -m venv /tmp/test-prod
source /tmp/test-prod/bin/activate

# Install from PyPI
pip install pilotprotocol

# Test
pilotctl info
python -c "from pilotprotocol import Driver; d = Driver()"

# Cleanup
deactivate
rm -rf /tmp/test-prod
```

### Step 8: Create Git Tag

```bash
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```

## Troubleshooting

### Authentication Error

```
Error: HTTP 403: Invalid or non-existent authentication information
```

**Solution:** Check your `~/.pypirc` credentials:
- Token starts with `pypi-`
- Username is `__token__`
- No extra spaces in the file

### Version Already Exists

```
Error: File already exists
```

**Solution:** PyPI doesn't allow re-uploading the same version. Update the version in `pyproject.toml`:
```toml
version = "0.1.1"  # Increment version
```

### Package Name Already Taken

```
Error: The name 'pilotprotocol' conflicts with an existing project
```

**Solution:** If this is your first upload and someone else owns the name, you'll need to:
1. Contact PyPI support to claim the name, or
2. Choose a different name in `pyproject.toml`

### Missing Build Dependencies

```
Error: No module named 'build'
```

**Solution:**
```bash
pip install build twine
```

### Binary Missing in Wheel

```
Error: Binary 'pilot-daemon' not found
```

**Solution:** Rebuild with binaries:
```bash
./scripts/build.sh
```

### Twine Not Found

```
Error: twine is not installed
```

**Solution:**
```bash
pip install twine
```

## Post-Publishing Checklist

After publishing to PyPI:

- ✅ Test installation on fresh environment
- ✅ Verify entry points work (`pilotctl`, `pilot-daemon`, `pilot-gateway`)
- ✅ Verify Python SDK imports (`from pilotprotocol import Driver`)
- ✅ Check PyPI page: https://pypi.org/project/pilotprotocol/
- ✅ Update documentation with new version
- ✅ Create GitHub release with changelog
- ✅ Announce release (if applicable)

## Version Numbering

Follow [Semantic Versioning](https://semver.org/):

- **MAJOR** version (1.0.0): Incompatible API changes
- **MINOR** version (0.1.0): Add functionality (backwards-compatible)
- **PATCH** version (0.0.1): Bug fixes (backwards-compatible)

Examples:
- `0.1.0` - First release
- `0.1.1` - Bug fix
- `0.2.0` - New features
- `1.0.0` - Stable API

## Security Notes

### API Tokens vs Passwords

✅ **Use API tokens** (recommended):
- Can be scoped to specific projects
- Can be revoked without changing password
- More secure than passwords

❌ **Don't use passwords**:
- Less secure
- Can't be scoped
- Deprecated by PyPI

### Token Storage

- Store tokens in `~/.pypirc` with `chmod 600`
- Never commit `~/.pypirc` to git
- Use different tokens for TestPyPI and PyPI
- Rotate tokens periodically

### CI/CD Publishing

For automated publishing in GitHub Actions:

```yaml
- name: Publish to PyPI
  env:
    TWINE_USERNAME: __token__
    TWINE_PASSWORD: ${{ secrets.PYPI_API_TOKEN }}
  run: |
    cd sdk/python
    ./scripts/publish.sh pypi
```

Store the token in GitHub repository secrets (not in code).

## Support

- **PyPI Help**: https://pypi.org/help/
- **TestPyPI Help**: https://test.pypi.org/help/
- **Packaging Guide**: https://packaging.python.org/
- **Twine Docs**: https://twine.readthedocs.io/
