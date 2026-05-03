# Verifies skillinject end-to-end: fetches the live pilot-skills manifest
# from raw.githubusercontent.com, applies it inside a container that has
# real (or attempted-real) installs of the priority agent tools.
#
# Build:   docker build -f pkg/skillinject/dockertest/Dockerfile -t pilot-skillinject-test .
# Run:     docker run --rm pilot-skillinject-test

FROM golang:1.25-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git curl jq nodejs npm python3 \
    && rm -rf /var/lib/apt/lists/*

# 1. Build pilotctl from the source we copy in.
WORKDIR /pilot
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /usr/local/bin/pilotctl ./cmd/pilotctl

RUN mkdir -p /test-logs

# 2. Try to install Claude Code via npm. Real install is straightforward.
RUN npm install -g @anthropic-ai/claude-code 2>&1 | tee /test-logs/claude-install.log | tail -3 || \
    echo "claude-code: npm install failed, will use stub dir" >> /test-logs/claude-install.log

# 3. Try to install OpenClaw, PicoClaw, Hermes via clones (best effort —
#    each project has install quirks so we tolerate failure).
RUN git clone --depth 1 https://github.com/openclaw/openclaw.git /tmp/openclaw 2>/dev/null && \
    (cd /tmp/openclaw && go build -o /usr/local/bin/openclaw ./cmd/openclaw 2>&1 || \
                        go build -o /usr/local/bin/openclaw . 2>&1) | tee /test-logs/openclaw-install.log | tail -3 || \
    echo "openclaw: build failed, will use stub dir" > /test-logs/openclaw-install.log

RUN git clone --depth 1 https://github.com/sipeed/picoclaw.git /tmp/picoclaw 2>/dev/null && \
    (cd /tmp/picoclaw && go build -o /usr/local/bin/picoclaw ./cmd/picoclaw 2>&1) | tee /test-logs/picoclaw-install.log | tail -3 || \
    echo "picoclaw: build failed, will use stub dir" > /test-logs/picoclaw-install.log

RUN git clone --depth 1 https://github.com/nousresearch/hermes-agent.git /tmp/hermes 2>/dev/null && \
    (cd /tmp/hermes && go build -o /usr/local/bin/hermes ./cmd/hermes 2>&1 || \
                        go build -o /usr/local/bin/hermes . 2>&1) | tee /test-logs/hermes-install.log | tail -3 || \
    echo "hermes: build failed, will use stub dir" > /test-logs/hermes-install.log

COPY pkg/skillinject/dockertest/run-test.sh /run-test.sh
RUN chmod +x /run-test.sh
CMD ["/run-test.sh"]
