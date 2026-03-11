# Docker image for integration testing against real network
#
# The builder uses the golang image for compiling Go binaries, then a
# second Python-based stage builds the SDK wheel so the cpXY tag matches
# the runtime image exactly (both Python 3.12).
# -------------------------------------------------------------------

FROM golang:1.25-bookworm AS go-builder

WORKDIR /workspace
COPY . .

# Build Go binaries (CGO disabled — pure Go, no Python needed here)
RUN go build -o /bin/pilotctl ./cmd/pilotctl && \
    go build -o /bin/pilot-daemon ./cmd/daemon

# Build the CGO shared library (needs gcc + CGO_ENABLED=1)
# -extldflags '-Wl,-z,nodelete' marks the .so as NODELETE so the Go runtime
# is never torn down on dlclose – prevents munmap_chunk crashes in ctypes.
RUN cd sdk/cgo && \
    CGO_ENABLED=1 go build -buildmode=c-shared \
        -ldflags="-s -w -extldflags '-Wl,-z,nodelete'" \
        -o /workspace/sdk/python/pilotprotocol/bin/libpilot.so .

# Build the other Go binaries shipped inside the SDK wheel
RUN mkdir -p sdk/python/pilotprotocol/bin && \
    CGO_ENABLED=0 go build -ldflags="-s -w" -o sdk/python/pilotprotocol/bin/pilot-daemon  ./cmd/daemon && \
    CGO_ENABLED=0 go build -ldflags="-s -w" -o sdk/python/pilotprotocol/bin/pilotctl       ./cmd/pilotctl && \
    CGO_ENABLED=0 go build -ldflags="-s -w" -o sdk/python/pilotprotocol/bin/pilot-gateway   ./cmd/gateway

# ------------------------------------------------------------------
# Build the Python wheel using the SAME Python version as the runtime
# ------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS wheel-builder

RUN pip install --no-cache-dir build setuptools wheel

WORKDIR /workspace/sdk/python
# Copy only the SDK source + pre-built binaries from go-builder
COPY --from=go-builder /workspace/sdk/python /workspace/sdk/python

RUN SKIP_TWINE_CHECK=1 python -m build --wheel

# -------------------------------------------------------------------
# Runtime stage
# -------------------------------------------------------------------
FROM python:3.12-slim-bookworm

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    curl \
    jq \
    procps \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy binaries from go-builder
COPY --from=go-builder /bin/pilotctl /usr/local/bin/
COPY --from=go-builder /bin/pilot-daemon /usr/local/bin/

# Copy Python wheel from wheel-builder
COPY --from=wheel-builder /workspace/sdk/python/dist/*.whl /tmp/

# Install Python SDK
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl

# Make libpilot.so findable by the SDK.
# The wheel installs it into pilotprotocol/bin/ but _find_library() checks
# pilotprotocol/ (same dir as client.py) and ~/.pilot/bin/.  Copy (not
# symlink) so dlopen sees a normal file — avoids Go runtime init issues.
RUN SITE=$(python -c "import pilotprotocol, pathlib; print(pathlib.Path(pilotprotocol.__file__).parent)") && \
    if [ -f "$SITE/bin/libpilot.so" ] && [ ! -f "$SITE/libpilot.so" ]; then \
        cp "$SITE/bin/libpilot.so" "$SITE/libpilot.so"; \
    fi

# Copy test scripts
COPY tests/integration/test_*.sh /tests/
COPY tests/integration/test_*.py /tests/
RUN chmod +x /tests/test_*.sh /tests/test_*.py

# Create pilot directories
RUN mkdir -p /root/.pilot/inbox /root/.pilot/received

WORKDIR /tests

# Default command runs all tests
CMD ["/bin/bash", "-c", "bash test_cli.sh && python test_sdk.py"]
