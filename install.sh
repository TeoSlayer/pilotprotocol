#!/bin/sh
set -e

# Pilot Protocol installer
# Usage:
#   Install:    curl -fsSL https://raw.githubusercontent.com/TeoSlayer/pilotprotocol/main/install.sh | sh
#   Uninstall:  curl -fsSL https://raw.githubusercontent.com/TeoSlayer/pilotprotocol/main/install.sh | sh -s uninstall

REPO="TeoSlayer/pilotprotocol"
REGISTRY="35.193.106.76:9000"
BEACON="35.193.106.76:9001"
PILOT_DIR="$HOME/.pilot"
BIN_DIR="$PILOT_DIR/bin"

# --- Uninstall ---

if [ "${1}" = "uninstall" ]; then
    echo ""
    echo "  Uninstalling Pilot Protocol..."
    echo ""

    OS=$(uname -s | tr '[:upper:]' '[:lower:]')

    # Stop daemon
    if [ -x "$BIN_DIR/pilotctl" ]; then
        "$BIN_DIR/pilotctl" daemon stop 2>/dev/null || true
        "$BIN_DIR/pilotctl" gateway stop 2>/dev/null || true
    elif command -v pilotctl >/dev/null 2>&1; then
        pilotctl daemon stop 2>/dev/null || true
        pilotctl gateway stop 2>/dev/null || true
    fi

    # Remove system service
    if [ "$OS" = "linux" ] && [ -f /etc/systemd/system/pilot-daemon.service ]; then
        if [ "$(id -u)" = "0" ] || sudo -n true 2>/dev/null; then
            sudo systemctl stop pilot-daemon 2>/dev/null || true
            sudo systemctl disable pilot-daemon 2>/dev/null || true
            sudo rm -f /etc/systemd/system/pilot-daemon.service
            sudo systemctl daemon-reload
            echo "  Removed systemd service"
        else
            echo "  Skipped systemd removal (run with sudo to remove)"
        fi
    fi
    if [ "$OS" = "darwin" ]; then
        PLIST="$HOME/Library/LaunchAgents/com.vulturelabs.pilot-daemon.plist"
        if [ -f "$PLIST" ]; then
            launchctl unload "$PLIST" 2>/dev/null || true
            rm -f "$PLIST"
            echo "  Removed LaunchAgent"
        fi
    fi

    # Remove pilot directory (binaries, config, identity, received files)
    if [ -d "$PILOT_DIR" ]; then
        rm -rf "$PILOT_DIR"
        echo "  Removed $PILOT_DIR"
    fi

    # Remove socket
    rm -f /tmp/pilot.sock

    echo ""
    echo "  Pilot Protocol uninstalled."
    echo ""
    exit 0
fi

# Detect platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    arm64)   ARCH="arm64" ;;
    *)       echo "Error: unsupported architecture: $ARCH"; exit 1 ;;
esac

case "$OS" in
    linux|darwin) ;;
    *) echo "Error: unsupported OS: $OS"; exit 1 ;;
esac

echo ""
echo "  Pilot Protocol"
echo "  The network stack for AI agents."
echo ""
echo "  Platform:   ${OS}/${ARCH}"
echo "  Registry:   ${REGISTRY}"
echo "  Beacon:     ${BEACON}"
echo ""

# --- Download or build ---

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# Try downloading a release first
TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep '"tag_name"' | head -1 | cut -d'"' -f4 || true)

if [ -n "$TAG" ]; then
    ARCHIVE="pilot-${OS}-${ARCH}.tar.gz"
    URL="https://github.com/${REPO}/releases/download/${TAG}/${ARCHIVE}"
    echo "Downloading ${TAG}..."
    if curl -fsSL "$URL" -o "$TMPDIR/$ARCHIVE" 2>/dev/null; then
        tar -xzf "$TMPDIR/$ARCHIVE" -C "$TMPDIR"
        mv "$TMPDIR/pilot-daemon-${OS}-${ARCH}" "$TMPDIR/pilot-daemon"
        mv "$TMPDIR/pilot-pilotctl-${OS}-${ARCH}" "$TMPDIR/pilotctl"
        mv "$TMPDIR/pilot-gateway-${OS}-${ARCH}" "$TMPDIR/pilot-gateway"
    else
        TAG=""
    fi
fi

if [ -z "$TAG" ]; then
    echo "No release available. Building from source..."
    if ! command -v go >/dev/null 2>&1; then
        echo "Error: Go is required to build from source."
        echo "Install Go: https://go.dev/dl/"
        exit 1
    fi
    if ! command -v git >/dev/null 2>&1; then
        echo "Error: git is required to build from source."
        exit 1
    fi
    echo "Cloning..."
    git clone --depth 1 "https://github.com/${REPO}.git" "$TMPDIR/src" >/dev/null 2>&1
    echo "Building daemon..."
    CGO_ENABLED=0 go build -o "$TMPDIR/pilot-daemon" "$TMPDIR/src/cmd/daemon"
    echo "Building pilotctl..."
    CGO_ENABLED=0 go build -o "$TMPDIR/pilotctl" "$TMPDIR/src/cmd/pilotctl"
    echo "Building gateway..."
    CGO_ENABLED=0 go build -o "$TMPDIR/pilot-gateway" "$TMPDIR/src/cmd/gateway"
fi

# --- Install binaries to ~/.pilot/bin ---

echo "Installing binaries..."
mkdir -p "$BIN_DIR"

cp "$TMPDIR/pilot-daemon" "$BIN_DIR/pilot-daemon"
cp "$TMPDIR/pilotctl" "$BIN_DIR/pilotctl"
cp "$TMPDIR/pilot-gateway" "$BIN_DIR/pilot-gateway"
chmod 755 "$BIN_DIR/pilot-daemon" "$BIN_DIR/pilotctl" "$BIN_DIR/pilot-gateway"

# --- Symlink to /usr/local/bin if writable, otherwise skip ---

LINK_DIR="/usr/local/bin"
if [ -d "$LINK_DIR" ] && [ -w "$LINK_DIR" ]; then
    ln -sf "$BIN_DIR/pilot-daemon" "$LINK_DIR/pilot-daemon"
    ln -sf "$BIN_DIR/pilotctl" "$LINK_DIR/pilotctl"
    ln -sf "$BIN_DIR/pilot-gateway" "$LINK_DIR/pilot-gateway"
    echo "  Symlinked to ${LINK_DIR}"
fi

# --- Write config ---

cat > "$PILOT_DIR/config.json" <<CONF
{
  "registry": "${REGISTRY}",
  "beacon": "${BEACON}",
  "socket": "/tmp/pilot.sock",
  "encrypt": true,
  "identity": "${PILOT_DIR}/identity.json"
}
CONF

echo "Config written to ${PILOT_DIR}/config.json"

# --- Set up system service ---

if [ "$OS" = "linux" ] && command -v systemctl >/dev/null 2>&1; then
    CAN_SUDO=false
    if [ "$(id -u)" = "0" ] || sudo -n true 2>/dev/null; then
        CAN_SUDO=true
    fi
    if [ "$CAN_SUDO" = true ]; then
    echo "Setting up systemd service..."
    HOSTNAME_FLAG=""
    if [ -n "$PILOT_HOSTNAME" ]; then
        HOSTNAME_FLAG="-hostname $PILOT_HOSTNAME"
    fi
    PUBLIC_FLAG=""
    if [ -n "$PILOT_PUBLIC" ]; then
        PUBLIC_FLAG="-public"
    fi
    sudo tee /etc/systemd/system/pilot-daemon.service >/dev/null <<SVC
[Unit]
Description=Pilot Protocol Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$(whoami)
ExecStart=${BIN_DIR}/pilot-daemon \\
  -registry ${REGISTRY} \\
  -beacon ${BEACON} \\
  -listen :4000 \\
  -socket /tmp/pilot.sock \\
  -identity ${PILOT_DIR}/identity.json \\
  -encrypt ${HOSTNAME_FLAG} ${PUBLIC_FLAG}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
SVC
    sudo systemctl daemon-reload
    echo "  Service: pilot-daemon.service"
    echo "  Start:   sudo systemctl start pilot-daemon"
    echo "  Enable:  sudo systemctl enable pilot-daemon"
    else
    echo "  Skipped systemd setup (run as root or with passwordless sudo to enable)"
    fi
fi

if [ "$OS" = "darwin" ]; then
    PLIST_DIR="$HOME/Library/LaunchAgents"
    PLIST="$PLIST_DIR/com.vulturelabs.pilot-daemon.plist"
    mkdir -p "$PLIST_DIR"
    EXTRA_ARGS=""
    if [ -n "$PILOT_HOSTNAME" ]; then
        EXTRA_ARGS="${EXTRA_ARGS}        <string>-hostname</string>
        <string>${PILOT_HOSTNAME}</string>
"
    fi
    if [ -n "$PILOT_PUBLIC" ]; then
        EXTRA_ARGS="${EXTRA_ARGS}        <string>-public</string>
"
    fi
    cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.vulturelabs.pilot-daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>${BIN_DIR}/pilot-daemon</string>
        <string>-registry</string>
        <string>${REGISTRY}</string>
        <string>-beacon</string>
        <string>${BEACON}</string>
        <string>-listen</string>
        <string>:4000</string>
        <string>-socket</string>
        <string>/tmp/pilot.sock</string>
        <string>-identity</string>
        <string>${PILOT_DIR}/identity.json</string>
        <string>-encrypt</string>
${EXTRA_ARGS}    </array>
    <key>RunAtLoad</key>
    <false/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>${PILOT_DIR}/daemon.log</string>
    <key>StandardErrorPath</key>
    <string>${PILOT_DIR}/daemon.log</string>
</dict>
</plist>
PLIST
    echo "  Service: com.vulturelabs.pilot-daemon"
    echo "  Start:   launchctl load $PLIST"
    echo "  Stop:    launchctl unload $PLIST"
fi

# --- Add to PATH ---

IN_PATH=false
case ":$PATH:" in
    *":${BIN_DIR}:"*) IN_PATH=true ;;
esac

if [ "$IN_PATH" = false ]; then
    SHELL_NAME=$(basename "$SHELL" 2>/dev/null || echo "sh")
    case "$SHELL_NAME" in
        zsh)  RC="$HOME/.zshrc" ;;
        bash) RC="$HOME/.bashrc" ;;
        *)    RC="$HOME/.profile" ;;
    esac
    if [ -f "$RC" ] && grep -q "$BIN_DIR" "$RC" 2>/dev/null; then
        : # already in rc file
    else
        echo "" >> "$RC"
        echo "# Pilot Protocol" >> "$RC"
        echo "export PATH=\"${BIN_DIR}:\$PATH\"" >> "$RC"
        echo "  Added ${BIN_DIR} to PATH in ${RC}"
    fi
fi

# --- Verify ---

echo ""
echo "Installed:"
echo "  pilot-daemon   ${BIN_DIR}/pilot-daemon"
echo "  pilotctl        ${BIN_DIR}/pilotctl"
echo "  pilot-gateway   ${BIN_DIR}/pilot-gateway"
echo ""
echo "Config: ${PILOT_DIR}/config.json"
echo "  Registry: ${REGISTRY}"
echo "  Beacon:   ${BEACON}"
echo "  Socket:   /tmp/pilot.sock"
echo "  Identity: ${PILOT_DIR}/identity.json"
echo ""
echo "Get started:"
echo ""
echo "  export PATH=\"${BIN_DIR}:\$PATH\"    # if not restarting your shell"
echo "  pilotctl daemon start --hostname my-agent"
echo "  pilotctl info"
echo "  pilotctl ping <other-agent>"
echo ""
echo "Bridge IP traffic (requires root for ports < 1024):"
echo ""
echo "  sudo ${BIN_DIR}/pilotctl gateway start --ports 80,3000 <pilot-addr>"
echo "  curl http://10.4.0.1:3000/status"
echo ""
