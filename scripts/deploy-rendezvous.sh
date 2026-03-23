#!/usr/bin/env bash
#
# deploy-rendezvous.sh — deploy, health-check, and auto-rollback for the rendezvous server.
# Runs on the VM. Called by the GitHub Actions workflow.
#
set -euo pipefail

BINARY_NAME="pilot-rendezvous"
INSTALL_DIR="/usr/local/bin"
CURRENT="$INSTALL_DIR/$BINARY_NAME"
PREV="$INSTALL_DIR/$BINARY_NAME.prev"
STAGED="$HOME/$BINARY_NAME-staged"
SERVICE_NAME="pilot-rendezvous"
REGISTRY_JSON="/var/lib/pilot/registry.json"
BACKUP_DIR="/var/lib/pilot/backups"
HEALTH_URL="http://127.0.0.1:3000/api/stats"
HEALTH_TIMEOUT=30
HEALTH_INTERVAL=2

log() { echo "[deploy] $(date '+%H:%M:%S') $*"; }

preflight() {
    if [ ! -f "$STAGED" ]; then
        log "ERROR: staged binary not found at $STAGED"
        exit 1
    fi
    if ! file "$STAGED" | grep -q "ELF"; then
        log "ERROR: staged file is not a valid ELF binary"
        exit 1
    fi
    chmod +x "$STAGED"
    log "Preflight OK — staged binary is valid ELF"
}

backup() {
    # Backup current binary
    if [ -f "$CURRENT" ]; then
        sudo cp "$CURRENT" "$PREV"
        log "Backed up current binary to $PREV"
    fi

    # Backup registry JSON
    if [ -f "$REGISTRY_JSON" ]; then
        sudo mkdir -p "$BACKUP_DIR"
        TIMESTAMP=$(date '+%Y%m%d-%H%M%S')
        sudo cp "$REGISTRY_JSON" "$BACKUP_DIR/registry-$TIMESTAMP.json"
        log "Backed up registry.json to registry-$TIMESTAMP.json"

        # Rotate: keep last 5 backups
        BACKUP_COUNT=$(ls -1 "$BACKUP_DIR"/registry-*.json 2>/dev/null | wc -l)
        if [ "$BACKUP_COUNT" -gt 5 ]; then
            ls -1t "$BACKUP_DIR"/registry-*.json | tail -n +"6" | xargs sudo rm -f
            log "Rotated backups — kept last 5"
        fi
    fi
}

stop_service() {
    log "Stopping $SERVICE_NAME..."
    sudo systemctl stop "$SERVICE_NAME"
    sleep 1
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log "ERROR: service still active after stop"
        exit 1
    fi
    log "Service stopped"
}

swap_binary() {
    sudo cp "$STAGED" "$CURRENT"
    log "Swapped binary"
}

start_service() {
    log "Starting $SERVICE_NAME..."
    sudo systemctl start "$SERVICE_NAME"
    log "Service started"
}

health_check() {
    log "Running health checks (${HEALTH_TIMEOUT}s timeout, every ${HEALTH_INTERVAL}s)..."
    ELAPSED=0
    while [ "$ELAPSED" -lt "$HEALTH_TIMEOUT" ]; do
        sleep "$HEALTH_INTERVAL"
        ELAPSED=$((ELAPSED + HEALTH_INTERVAL))

        # Check systemd unit is active
        if ! systemctl is-active --quiet "$SERVICE_NAME"; then
            log "Health: service not active (${ELAPSED}s)"
            continue
        fi

        # Check HTTP endpoint
        HTTP_CODE=$(curl -s -o /tmp/health-response.json -w "%{http_code}" "$HEALTH_URL" 2>/dev/null || echo "000")
        if [ "$HTTP_CODE" != "200" ]; then
            log "Health: HTTP $HTTP_CODE (${ELAPSED}s)"
            continue
        fi

        # Check node and trust counts
        NODES=$(jq -r '.total_nodes // 0' /tmp/health-response.json 2>/dev/null || echo "0")
        TRUSTS=$(jq -r '.total_trust_links // 0' /tmp/health-response.json 2>/dev/null || echo "0")

        if [ "$NODES" -ge 10000 ] && [ "$TRUSTS" -ge 10000 ]; then
            log "Health check PASSED — nodes=$NODES trusts=$TRUSTS (${ELAPSED}s)"
            rm -f /tmp/health-response.json
            return 0
        fi
        log "Health: nodes=$NODES trusts=$TRUSTS — waiting (${ELAPSED}s)"
    done

    log "Health check FAILED after ${HEALTH_TIMEOUT}s"
    rm -f /tmp/health-response.json
    return 1
}

rollback() {
    log "ROLLING BACK to previous binary..."
    if [ ! -f "$PREV" ]; then
        log "ERROR: no previous binary at $PREV — cannot rollback"
        exit 1
    fi

    sudo systemctl stop "$SERVICE_NAME" || true
    sleep 1
    sudo cp "$PREV" "$CURRENT"
    sudo systemctl start "$SERVICE_NAME"
    sleep 3

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log "Rollback complete — service is active"
    else
        log "CRITICAL: rollback failed — service did not start"
        sudo journalctl -u "$SERVICE_NAME" --no-pager -n 20
        exit 1
    fi
}

deploy() {
    log "=== Starting deployment ==="
    preflight
    backup
    stop_service
    swap_binary
    start_service

    if health_check; then
        log "=== Deployment successful ==="
        exit 0
    else
        rollback
        log "=== Deployment FAILED — rolled back ==="
        exit 1
    fi
}

case "${1:-deploy}" in
    deploy)   deploy ;;
    rollback) rollback ;;
    health)   health_check ;;
    *)        echo "Usage: $0 {deploy|rollback|health}"; exit 1 ;;
esac
