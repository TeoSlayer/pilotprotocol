#!/usr/bin/env bash
# Verifies skillinject against the LIVE pilot-skills manifest on GitHub
# (https://raw.githubusercontent.com/TeoSlayer/pilot-skills/main/...) inside
# a container with real-or-stubbed installs of the priority agent tools.
set -euo pipefail

PASS=0
FAIL=0

check() {
    local name="$1"
    local cmd="$2"
    if eval "$cmd" >/dev/null 2>&1; then
        echo "  ✓ $name"
        PASS=$((PASS + 1))
    else
        echo "  ✗ $name"
        FAIL=$((FAIL + 1))
    fi
}

echo "================================================================"
echo "Phase 1: Install attempt logs"
echo "================================================================"
for log in /test-logs/*.log; do
    echo "--- $log ---"
    cat "$log"
done

echo
echo "================================================================"
echo "Phase 2: Seed config dirs (real-or-stub) so skillinject detects each"
echo "================================================================"

# Claude Code: if `claude` is on PATH, run `claude --help` once to make sure
# ~/.claude/ exists; otherwise create it.
if command -v claude >/dev/null 2>&1; then
    claude --help >/dev/null 2>&1 || true
fi
mkdir -p "$HOME/.claude"

# OpenClaw / PicoClaw / Hermes: if the binary exists try `<tool> onboard`;
# otherwise simulate by creating the workspace dir + a minimal seeded file.
seed_openclaw() {
    mkdir -p "$HOME/.openclaw/workspace"
    if [ ! -f "$HOME/.openclaw/workspace/AGENTS.md" ]; then
        cat > "$HOME/.openclaw/workspace/AGENTS.md" <<'EOF'
# OpenClaw

Existing agent instructions go here.
EOF
    fi
}
seed_picoclaw() {
    mkdir -p "$HOME/.picoclaw/workspace"
    if [ ! -f "$HOME/.picoclaw/workspace/AGENT.md" ]; then
        cat > "$HOME/.picoclaw/workspace/AGENT.md" <<'EOF'
---
name: pico
description: PicoClaw agent
---

# PicoClaw

Existing agent instructions go here.
EOF
    fi
}
seed_hermes() {
    mkdir -p "$HOME/.hermes"
    if [ ! -f "$HOME/.hermes/SOUL.md" ]; then
        cat > "$HOME/.hermes/SOUL.md" <<'EOF'
# Hermes Soul

Default identity / voice.
EOF
    fi
}
seed_openclaw
seed_picoclaw
seed_hermes

echo
echo "================================================================"
echo "Phase 3: pilotctl skills check (fetches manifest from live GitHub)"
echo "================================================================"
pilotctl skills check

echo
echo "================================================================"
echo "Phase 4: Per-tool placement"
echo "================================================================"
echo "[claude-code]"
check "skill at ~/.claude/skills/pilotctl/SKILL.md" \
    "[ -s $HOME/.claude/skills/pilotctl/SKILL.md ]"
check "CLAUDE.md marker present" \
    "grep -q '<!-- pilot:begin v=1 hash=' $HOME/.claude/CLAUDE.md"

echo "[openclaw]"
check "skill at ~/.openclaw/skills/pilotctl/SKILL.md" \
    "[ -s $HOME/.openclaw/skills/pilotctl/SKILL.md ]"
check "AGENTS.md (plural) marker present" \
    "grep -q '<!-- pilot:begin v=1 hash=' $HOME/.openclaw/workspace/AGENTS.md"
check "no AGENT.md (singular) leaked into openclaw" \
    "! [ -f $HOME/.openclaw/workspace/AGENT.md ]"

echo "[picoclaw]"
check "skill at ~/.picoclaw/workspace/skills/pilotctl/SKILL.md" \
    "[ -s $HOME/.picoclaw/workspace/skills/pilotctl/SKILL.md ]"
check "AGENT.md (singular) marker present" \
    "grep -q '<!-- pilot:begin v=1 hash=' $HOME/.picoclaw/workspace/AGENT.md"
check "no AGENTS.md (plural) leaked into picoclaw" \
    "! [ -f $HOME/.picoclaw/workspace/AGENTS.md ]"

echo "[hermes]"
check "skill at ~/.hermes/skills/pilotctl/SKILL.md" \
    "[ -s $HOME/.hermes/skills/pilotctl/SKILL.md ]"
check "SOUL.md marker present" \
    "grep -q '<!-- pilot:begin v=1 hash=' $HOME/.hermes/SOUL.md"

echo
echo "================================================================"
echo "Phase 5: Skill content is the LIVE pilotctl entrypoint (not a stub)"
echo "================================================================"
SKILL=$(cat "$HOME/.openclaw/skills/pilotctl/SKILL.md")
check "frontmatter declares name: pilotctl" \
    "echo \"\$SKILL\" | grep -q '^name: pilotctl$'"
check "body mentions Pilot Protocol" \
    "echo \"\$SKILL\" | grep -q 'Pilot Protocol'"
check "auto-generated references block present" \
    "echo \"\$SKILL\" | grep -q 'BEGIN AUTO-GENERATED REFERENCES'"
check "references block lists at least 50 sub-skills" \
    "[ \$(echo \"\$SKILL\" | grep -c '^| \\\`pilot-') -ge 50 ]"

echo
echo "================================================================"
echo "Phase 6: Preservation — heartbeat files keep user content"
echo "================================================================"
check "openclaw AGENTS.md heading preserved" \
    "grep -q '^# OpenClaw$' $HOME/.openclaw/workspace/AGENTS.md"
check "openclaw AGENTS.md body preserved" \
    "grep -q '^Existing agent instructions go here.$' $HOME/.openclaw/workspace/AGENTS.md"
check "picoclaw AGENT.md frontmatter at top" \
    "head -5 $HOME/.picoclaw/workspace/AGENT.md | grep -q 'name: pico'"
check "picoclaw AGENT.md body preserved" \
    "grep -q 'Existing agent instructions go here' $HOME/.picoclaw/workspace/AGENT.md"
check "hermes SOUL.md heading preserved" \
    "grep -q '# Hermes Soul' $HOME/.hermes/SOUL.md"

echo
echo "================================================================"
echo "Phase 7: Idempotence"
echo "================================================================"
SKILL_PATH="$HOME/.picoclaw/workspace/skills/pilotctl/SKILL.md"
M1=$(stat -c %Y "$SKILL_PATH")
sleep 1
pilotctl skills check >/dev/null
M2=$(stat -c %Y "$SKILL_PATH")
check "SKILL.md mtime unchanged across two ticks" "[ $M1 = $M2 ]"

echo
echo "================================================================"
echo "Phase 8: Marker is directive (instructs agent)"
echo "================================================================"
check "marker references 'Pilot Protocol'" \
    "grep -q 'Pilot Protocol' $HOME/.openclaw/workspace/AGENTS.md"
check "marker has trigger keywords (overlay/NAT/peer/pilotctl)" \
    "grep -qE '(overlay|NAT|peer|pilotctl)' $HOME/.openclaw/workspace/AGENTS.md"
check "marker references the SKILL.md path" \
    "grep -q 'pilotctl/SKILL.md' $HOME/.openclaw/workspace/AGENTS.md"

echo
echo "================================================================"
echo "Phase 9: Excerpt of what landed"
echo "================================================================"
for f in \
    "$HOME/.openclaw/workspace/AGENTS.md" \
    "$HOME/.picoclaw/workspace/AGENT.md" \
    "$HOME/.hermes/SOUL.md"; do
    echo "----- $f -----"
    head -15 "$f"
done

echo
echo "================================================================"
echo "Result: $PASS passed, $FAIL failed"
echo "================================================================"
[ $FAIL -eq 0 ]
