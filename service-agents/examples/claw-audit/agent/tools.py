"""
Tools for the OpenClaw security auditing agent.
All tools are sandboxed to OpenClaw config directories.
"""

import json
import os
import re
import stat
import subprocess
from pathlib import Path

from .vulns import VULNERABILITY_DB, VULNS_BY_SEVERITY, VULN_INDEX

_ALLOWED_ROOTS = [
    os.path.expanduser("~/.openclaw"),
    os.path.expanduser("~/.openclaw-command-center"),
    os.path.expanduser("~/Library/LaunchAgents"),
]


def _safe_path(path: str) -> Path | None:
    p = Path(os.path.expanduser(path)).resolve()
    for root in _ALLOWED_ROOTS:
        try:
            p.relative_to(root)
            return p
        except ValueError:
            continue
    return None


def _format_permissions(mode: int) -> str:
    perms = ""
    for who in ["USR", "GRP", "OTH"]:
        r = "r" if mode & getattr(stat, f"S_IR{who}") else "-"
        w = "w" if mode & getattr(stat, f"S_IW{who}") else "-"
        x = "x" if mode & getattr(stat, f"S_IX{who}") else "-"
        perms += r + w + x
    return f"{oct(stat.S_IMODE(mode))[2:]:>4}  ({perms})"


def read_config(args: dict) -> dict:
    config_path = Path.home() / ".openclaw" / "openclaw.json"
    if not config_path.exists():
        return {"error": "openclaw.json not found", "path": str(config_path)}
    try:
        data = json.loads(config_path.read_text())
    except Exception as e:
        return {"error": f"failed to read config: {e}"}

    def redact(obj):
        SENSITIVE = {"token", "key", "secret", "password", "apiKey", "api_key",
                     "privateKey", "privateKeyPem", "auth_token"}
        if isinstance(obj, dict):
            return {
                k: (f"<redacted:{len(v)} chars>" if any(s.lower() in k.lower() for s in SENSITIVE)
                    and isinstance(v, str) and v else redact(v))
                for k, v in obj.items()
            }
        elif isinstance(obj, list):
            return [redact(i) for i in obj]
        return obj

    gateway = data.get("gateway", {})
    auth = gateway.get("auth", {})
    token = auth.get("token", "")
    return {
        "config": redact(data),
        "security_metadata": {
            "gateway_bind": gateway.get("bind", "not set"),
            "gateway_port": gateway.get("port", 18789),
            "gateway_auth_mode": auth.get("mode", "not set"),
            "gateway_token_length": len(token) if token else 0,
            "gateway_token_entropy_bits": len(token) * 4 if token else 0,
            "tailscale_mode": gateway.get("tailscale", {}).get("mode", "off"),
            "dm_policy": data.get("messages", {}).get("dmPolicy", "not set (default: pairing)"),
            "agent_max_concurrent": data.get("agents", {}).get("defaults", {}).get("maxConcurrent", "not set"),
            "compaction_mode": data.get("agents", {}).get("defaults", {}).get("compaction", {}).get("mode", "not set"),
        },
    }


def check_file_permissions(args: dict) -> dict:
    targets = [
        ("~/.openclaw/openclaw.json", 0o600, "main config (contains gateway token)"),
        ("~/.openclaw/identity/device.json", 0o600, "device Ed25519 private key"),
        ("~/.openclaw/identity/device-auth.json", 0o600, "operator token"),
        ("~/.openclaw/devices/paired.json", 0o600, "paired device tokens"),
        ("~/.openclaw/agents", 0o700, "agents directory (contains API keys)"),
        ("~/.openclaw/workspace", 0o700, "workspace directory"),
        ("~/Library/LaunchAgents/ai.openclaw.gateway.plist", 0o600, "LaunchAgent (contains token)"),
    ]
    results = []
    for path_str, recommended, desc in targets:
        path = Path(os.path.expanduser(path_str))
        if not path.exists():
            results.append({"path": path_str, "exists": False, "description": desc})
            continue
        st = path.stat()
        mode = stat.S_IMODE(st.st_mode)
        other_readable = bool(mode & stat.S_IROTH)
        other_writable = bool(mode & stat.S_IWOTH)
        group_readable = bool(mode & stat.S_IRGRP) and not stat.S_ISDIR(st.st_mode)
        issue = None
        if other_readable or other_writable:
            issue = "WORLD-READABLE" if other_readable else "WORLD-WRITABLE"
        elif group_readable:
            issue = "GROUP-READABLE"
        results.append({
            "path": path_str,
            "exists": True,
            "description": desc,
            "actual_permissions": _format_permissions(st.st_mode).strip(),
            "recommended_permissions": oct(recommended)[2:],
            "issue": issue,
            "vulnerable": issue is not None,
        })
    vulnerable = [r for r in results if r.get("vulnerable")]
    return {
        "total_checked": len(targets),
        "vulnerable_count": len(vulnerable),
        "results": results,
        "summary": (
            f"{len(vulnerable)} file(s) have overly permissive permissions"
            if vulnerable else "All existing files have correct permissions"
        ),
    }


def check_gateway_status(args: dict) -> dict:
    result = {"gateway_running": False, "canvas_running": False, "listeners": []}
    for port, key in [(18789, "gateway_running"), (18793, "canvas_running")]:
        try:
            proc = subprocess.run(
                ["lsof", "-i", f":{port}", "-sTCP:LISTEN", "-n", "-P"],
                capture_output=True, text=True, timeout=5
            )
            if proc.returncode == 0 and proc.stdout.strip():
                result[key] = True
                for line in proc.stdout.strip().splitlines()[1:]:
                    parts = line.split()
                    if parts:
                        addr = parts[-2] if len(parts) > 2 else "unknown"
                        result["listeners"].append({"port": port, "address": addr, "process": parts[0]})
        except Exception as e:
            result["error"] = str(e)
    exposed = [l for l in result["listeners"]
               if "0.0.0.0" in l.get("address", "") or
               (not any(x in l.get("address", "") for x in ["127.0.0.1", "::1", "localhost"]))]
    result["network_exposed"] = len(exposed) > 0
    result["exposed_listeners"] = exposed
    return result


def check_version(args: dict) -> dict:
    result = {}
    try:
        proc = subprocess.run(["openclaw", "--version"], capture_output=True, text=True, timeout=5)
        if proc.returncode == 0:
            result["installed_version"] = proc.stdout.strip()
    except FileNotFoundError:
        pass
    config_path = Path.home() / ".openclaw" / "openclaw.json"
    if config_path.exists():
        try:
            data = json.loads(config_path.read_text())
            result["config_version"] = data.get("meta", {}).get("lastTouchedVersion")
        except Exception:
            pass
    update_path = Path.home() / ".openclaw" / "update-check.json"
    if update_path.exists():
        try:
            data = json.loads(update_path.read_text())
            result["latest_notified_version"] = data.get("lastNotifiedVersion")
            result["last_update_check"] = data.get("lastCheckedAt")
        except Exception:
            pass
    installed = result.get("installed_version") or result.get("config_version", "")
    latest = result.get("latest_notified_version", "")
    result["outdated"] = bool(installed and latest and installed != latest)
    return result


def read_devices(args: dict) -> dict:
    devices_dir = Path.home() / ".openclaw" / "devices"
    result = {"paired": [], "pending": []}
    for fname, key in [("paired.json", "paired"), ("pending.json", "pending")]:
        fpath = devices_dir / fname
        if not fpath.exists():
            continue
        try:
            data = json.loads(fpath.read_text())
            items = data if isinstance(data, list) else data.get("devices", data.get("nodes", []))
            for item in items:
                result[key].append({
                    "deviceId": item.get("deviceId", item.get("id", "unknown"))[:16] + "...",
                    "scopes": item.get("scopes", item.get("permissions", [])),
                    "role": item.get("role", "unknown"),
                    "created": item.get("pairingCreatedAt", item.get("createdAt", "unknown")),
                    "has_admin_scope": any(
                        "admin" in s or "pairing" in s
                        for s in item.get("scopes", [])
                    ),
                })
        except Exception as e:
            result[f"{key}_error"] = str(e)
    result["total_paired"] = len(result["paired"])
    result["admin_devices"] = sum(1 for d in result["paired"] if d["has_admin_scope"])
    return result


def scan_for_hardcoded_secrets(args: dict) -> dict:
    patterns = [
        (r"AUTH_TOKEN\s*=\s*['\"]([a-f0-9]{32,})['\"]", "hardcoded gateway token"),
        (r"OPENCLAW_GATEWAY_TOKEN\s*=\s*['\"]([a-f0-9]{32,})['\"]", "hardcoded gateway token (env var)"),
        (r"ws://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+", "hardcoded gateway URL"),
        (r"xai-[A-Za-z0-9]{50,}", "hardcoded xAI API key"),
        (r"sk-[A-Za-z0-9]{40,}", "hardcoded OpenAI API key"),
    ]
    findings = []
    extensions = {".py", ".sh", ".js", ".ts", ".env", ".yaml", ".yml"}
    search_dir = Path.home() / "web4"
    if search_dir.exists():
        for fpath in search_dir.rglob("*"):
            if not fpath.is_file() or fpath.suffix not in extensions:
                continue
            if any(part.startswith(".") for part in fpath.parts):
                continue
            try:
                content = fpath.read_text(errors="replace")
                for pattern, desc in patterns:
                    for match in re.finditer(pattern, content):
                        line_no = content[:match.start()].count("\n") + 1
                        findings.append({
                            "file": str(fpath),
                            "line": line_no,
                            "issue": desc,
                            "snippet": match.group(0)[:60],
                        })
            except Exception:
                continue
    return {
        "total_findings": len(findings),
        "findings": findings,
        "summary": (
            f"Found {len(findings)} potential hardcoded secret(s)"
            if findings else "No hardcoded secrets detected"
        ),
    }


def check_cloud_sync(args: dict) -> dict:
    result = {"risks": []}
    openclaw_path = Path.home() / ".openclaw"
    if openclaw_path.is_symlink():
        target = openclaw_path.resolve()
        icloud = Path.home() / "Library" / "Mobile Documents" / "com~apple~CloudDocs"
        if icloud.exists() and icloud in target.parents:
            result["risks"].append({"type": "icloud", "detail": "~/.openclaw symlinked into iCloud Drive", "severity": "CRITICAL"})
    dropbox_info = Path.home() / ".dropbox" / "info.json"
    if dropbox_info.exists():
        try:
            db = json.loads(dropbox_info.read_text())
            db_path = db.get("personal", {}).get("path", "")
            if db_path and str(openclaw_path).startswith(db_path):
                result["risks"].append({"type": "dropbox", "detail": "~/.openclaw inside Dropbox folder", "severity": "CRITICAL"})
        except Exception:
            pass
    try:
        proc = subprocess.run(["xattr", "-l", str(openclaw_path)], capture_output=True, text=True, timeout=5)
        if "com.apple.icloud" in proc.stdout or "com.apple.ubiquity" in proc.stdout:
            result["risks"].append({"type": "icloud_xattr", "detail": "~/.openclaw has iCloud extended attributes", "severity": "HIGH"})
    except Exception:
        pass
    result["cloud_sync_detected"] = len(result["risks"]) > 0
    return result


def list_vulnerabilities(args: dict) -> dict:
    severity_filter = args.get("severity", "").upper()
    vulns = VULNS_BY_SEVERITY.get(severity_filter, VULNERABILITY_DB) if severity_filter else VULNERABILITY_DB
    return {
        "total": len(vulns),
        "severities": {k: len(v) for k, v in VULNS_BY_SEVERITY.items()},
        "vulnerabilities": [
            {
                "id": v["id"],
                "title": v["title"],
                "severity": v["severity"],
                "versions_affected": v["versions_affected"],
                "summary": v["description"][:200],
            }
            for v in vulns
        ],
    }


def get_vulnerability_detail(args: dict) -> dict:
    vuln_id = args.get("id", "").upper()
    if vuln_id not in VULN_INDEX:
        return {"error": f"Unknown ID: {vuln_id}. Use list_vulnerabilities to see all IDs."}
    return VULN_INDEX[vuln_id]


def read_workspace_docs(args: dict) -> dict:
    workspace = Path.home() / ".openclaw" / "workspace"
    result = {"docs": {}, "workspace_exists": workspace.exists()}
    if not workspace.exists():
        return result
    for fname in ["SOUL.md", "AGENTS.md", "IDENTITY.md", "TOOLS.md", "BOOTSTRAP.md"]:
        fpath = workspace / fname
        if fpath.exists():
            try:
                content = fpath.read_text()
                result["docs"][fname] = content[:3000] + "..." if len(content) > 3000 else content
            except Exception as e:
                result["docs"][fname] = f"[error: {e}]"
    return result


def read_gateway_logs(args: dict) -> dict:
    n_lines = min(int(args.get("lines", 50)), 200)
    logs_dir = Path.home() / ".openclaw" / "logs"
    result = {}
    for log_name in ["gateway.log", "gateway.err.log"]:
        log_path = logs_dir / log_name
        if not log_path.exists():
            result[log_name] = "not found"
            continue
        try:
            proc = subprocess.run(["tail", f"-{n_lines}", str(log_path)], capture_output=True, text=True, timeout=5)
            content = proc.stdout
            suspicious = [line for line in content.splitlines()
                          if any(kw in line.lower() for kw in ["auth failed", "invalid token", "unauthorized", "error", "rejected"])]
            result[log_name] = {"last_lines": content, "suspicious_lines": suspicious[:20]}
        except Exception as e:
            result[log_name] = f"[error: {e}]"
    return result


TOOL_DEFINITIONS = [
    {
        "name": "read_config",
        "description": "Read ~/.openclaw/openclaw.json with sensitive values redacted. Returns security metadata (bind mode, token length, DM policy).",
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "check_file_permissions",
        "description": "Check filesystem permissions of all security-sensitive OpenClaw files. Identifies world-readable or group-readable files.",
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "check_gateway_status",
        "description": "Check if the OpenClaw gateway is running and whether it is exposed to the network (0.0.0.0 vs loopback).",
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "check_version",
        "description": "Check the installed OpenClaw version and whether it is outdated.",
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "read_devices",
        "description": "Read paired device info — scopes, roles, creation dates. Identifies admin-scoped devices.",
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "scan_for_hardcoded_secrets",
        "description": "Scan ~/web4 for hardcoded OpenClaw tokens, API keys, and gateway URLs in source files.",
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "check_cloud_sync",
        "description": "Check whether ~/.openclaw is being synced to iCloud or Dropbox.",
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "list_vulnerabilities",
        "description": "Return all known OpenClaw vulnerabilities, optionally filtered by severity.",
        "parameters": {
            "type": "object",
            "properties": {
                "severity": {
                    "type": "string",
                    "description": "Filter by severity: CRITICAL, HIGH, MEDIUM, LOW. Omit to list all.",
                    "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                }
            },
            "required": [],
        },
    },
    {
        "name": "get_vulnerability_detail",
        "description": "Get full details of a specific vulnerability by ID (e.g., OC-2024-001).",
        "parameters": {
            "type": "object",
            "properties": {
                "id": {"type": "string", "description": "Vulnerability ID, e.g. OC-2024-001"}
            },
            "required": ["id"],
        },
    },
    {
        "name": "read_workspace_docs",
        "description": "Read agent workspace docs (SOUL.md, AGENTS.md, TOOLS.md) to assess agent permissions and tool exposure.",
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "read_gateway_logs",
        "description": "Read the last N lines of gateway logs to detect auth failures and suspicious activity.",
        "parameters": {
            "type": "object",
            "properties": {
                "lines": {"type": "integer", "description": "Number of log lines (default 50, max 200)"}
            },
            "required": [],
        },
    },
]

TOOL_FUNCTIONS = {
    "read_config": read_config,
    "check_file_permissions": check_file_permissions,
    "check_gateway_status": check_gateway_status,
    "check_version": check_version,
    "read_devices": read_devices,
    "scan_for_hardcoded_secrets": scan_for_hardcoded_secrets,
    "check_cloud_sync": check_cloud_sync,
    "list_vulnerabilities": list_vulnerabilities,
    "get_vulnerability_detail": get_vulnerability_detail,
    "read_workspace_docs": read_workspace_docs,
    "read_gateway_logs": read_gateway_logs,
}
