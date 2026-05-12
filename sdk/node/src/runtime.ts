/**
 * Runtime environment seeder for the Pilot Protocol Node SDK.
 *
 * Both the CLI shims (`cli.ts`) and the FFI loader (`ffi.ts:findLibrary`)
 * funnel through `ensureRuntimeSeeded`, which idempotently mirrors the
 * binaries shipped inside the npm package into `~/.pilot/bin/` (the
 * canonical runtime directory shared with `install.sh`).
 *
 * Goals:
 * - The package is the seed cache; `~/.pilot/bin/` is the runtime.
 * - No install-time code runs; seeding happens lazily on first SDK use.
 * - Concurrency-safe via O_EXCL lock + retry; crash-safe via atomic rename.
 * - Never downgrades; never replaces a running daemon binary.
 * - Coexists with `install.sh` — same layout, same `.pilot-version`.
 */

import { Socket } from 'node:net';
import {
  closeSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
  chmodSync,
  accessSync,
  constants as fsConstants,
} from 'node:fs';
import { homedir, arch as osArch, platform as osPlatform } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const BIN_NAMES = ['pilotctl', 'pilot-daemon', 'pilot-gateway', 'pilot-updater'] as const;

const LIB_NAMES: Record<string, string> = {
  darwin: 'libpilot.dylib',
  linux: 'libpilot.so',
  win32: 'libpilot.dll',
};

// node arch ("x64", "arm64") → go arch ("amd64", "arm64") used in bin/<os>-<arch>/
function platformDirName(): string {
  const goOS = osPlatform();
  const goArch = osArch() === 'x64' ? 'amd64' : osArch();
  return `${goOS}-${goArch}`;
}

export const DEFAULT_REGISTRY = '34.71.57.205:9000';
export const DEFAULT_BEACON = '34.71.57.205:9001';
export const DEFAULT_SOCKET = '/tmp/pilot.sock';

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

/**
 * Where the npm package keeps its top-level bin/ directory (containing
 * platform subdirs and the shared `.pilot-version` marker).
 *
 * dist/runtime.js → ../bin/   (npm package layout)
 * src/runtime.ts → ../../bin/ (development layout, run via tsx)
 */
function pkgBinRoot(): string {
  const override = process.env['PILOT_PKG_BIN_ROOT'];
  if (override) return override;

  const thisDir = resolve(fileURLToPath(import.meta.url), '..');

  const compiledBin = resolve(thisDir, '..', 'bin');
  if (existsSync(compiledBin)) return compiledBin;

  const sourceBin = resolve(thisDir, '..', '..', 'bin');
  return sourceBin;
}

/**
 * Where the npm package ships THIS host's bundled binaries (the seed cache):
 * `bin/<os>-<arch>/`. Each platform subdir holds the four binaries and
 * `libpilot.{so|dylib}`. May not exist if the package was built for a
 * different platform — callers must handle missing files.
 */
function pkgBinDir(): string {
  // Test override: a one-shot way to point at a fake bundled bin/ without
  // resorting to vi.spyOn on a live binding. Honored only when set.
  const override = process.env['PILOT_PKG_BIN_DIR'];
  if (override) return override;
  return join(pkgBinRoot(), platformDirName());
}

function runtimeRoot(): string {
  const override = process.env['PILOT_HOME'];
  if (override) return override;
  return join(homedir(), '.pilot');
}

function runtimeBin(): string {
  return join(runtimeRoot(), 'bin');
}

function platformLibName(): string {
  const name = LIB_NAMES[osPlatform()];
  if (!name) throw new Error(`unsupported platform: ${osPlatform()}`);
  return name;
}

// ---------------------------------------------------------------------------
// Version helpers
// ---------------------------------------------------------------------------

function semverTuple(v: string | undefined | null): number[] | null {
  if (!v) return null;
  const cleaned = v.trim().replace(/^v/, '').split('-')[0]?.split('+')[0];
  if (!cleaned) return null;
  const parts = cleaned.split('.').map((p) => Number(p));
  if (parts.some((n) => !Number.isFinite(n))) return null;
  return parts;
}

function compareSemver(a: number[] | null, b: number[] | null): number {
  if (!a && !b) return 0;
  if (!a) return -1;
  if (!b) return 1;
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const ai = a[i] ?? 0;
    const bi = b[i] ?? 0;
    if (ai > bi) return 1;
    if (ai < bi) return -1;
  }
  return 0;
}

function bundledVersion(): string {
  const f = join(pkgBinRoot(), '.pilot-version');
  if (existsSync(f)) {
    try {
      return readFileSync(f, 'utf8').trim();
    } catch {
      // fall through
    }
  }
  // Fallback: read package.json beside dist/
  const thisDir = resolve(fileURLToPath(import.meta.url), '..');
  const candidates = [
    resolve(thisDir, '..', 'package.json'),
    resolve(thisDir, '..', '..', 'package.json'),
  ];
  for (const c of candidates) {
    if (existsSync(c)) {
      try {
        return JSON.parse(readFileSync(c, 'utf8')).version ?? '';
      } catch {
        // ignore
      }
    }
  }
  return '';
}

function runtimeVersion(rt: string): string {
  const f = join(rt, '.pilot-version');
  if (!existsSync(f)) return '';
  try {
    return readFileSync(f, 'utf8').trim();
  } catch {
    return '';
  }
}

// ---------------------------------------------------------------------------
// Daemon liveness
// ---------------------------------------------------------------------------

async function probeDaemonLive(timeoutMs = 200): Promise<boolean> {
  let sockPath = DEFAULT_SOCKET;
  const cfgPath = join(runtimeRoot(), 'config.json');
  if (existsSync(cfgPath)) {
    try {
      const cfg = JSON.parse(readFileSync(cfgPath, 'utf8'));
      if (typeof cfg.socket === 'string' && cfg.socket) sockPath = cfg.socket;
    } catch {
      // ignore
    }
  }
  if (!existsSync(sockPath)) return false;

  return new Promise<boolean>((resolveProbe) => {
    const s = new Socket();
    const finish = (ok: boolean) => {
      try {
        s.destroy();
      } catch {
        // ignore
      }
      resolveProbe(ok);
    };
    s.setTimeout(timeoutMs);
    s.once('connect', () => finish(true));
    s.once('timeout', () => finish(false));
    s.once('error', () => finish(false));
    try {
      s.connect(sockPath);
    } catch {
      finish(false);
    }
  });
}

/** Synchronous probe used by the seeder. Loops on a short setImmediate. */
function probeDaemonLiveSync(): boolean {
  const sockPath = readSocketPath();
  if (!existsSync(sockPath)) return false;
  // Best-effort sync: try connecting via a child process. Falls back to
  // "assume not running" if we can't decide quickly.
  try {
    const { spawnSync } = require('node:child_process') as typeof import('node:child_process');
    // `nc -z -U <sock>` is the cleanest sync probe; fall back to true if nc is missing.
    const r = spawnSync('nc', ['-z', '-U', sockPath], { timeout: 250 });
    if (r.error) return existsSync(sockPath); // nc missing — be conservative
    return r.status === 0;
  } catch {
    // Conservative: if a socket file is present, assume the daemon is up.
    return existsSync(sockPath);
  }
}

function readSocketPath(): string {
  const cfgPath = join(runtimeRoot(), 'config.json');
  if (existsSync(cfgPath)) {
    try {
      const cfg = JSON.parse(readFileSync(cfgPath, 'utf8'));
      if (typeof cfg.socket === 'string' && cfg.socket) return cfg.socket;
    } catch {
      // ignore
    }
  }
  return DEFAULT_SOCKET;
}

// ---------------------------------------------------------------------------
// File ops
// ---------------------------------------------------------------------------

function ensureDirWritable(p: string): void {
  if (!existsSync(p)) mkdirSync(p, { recursive: true });
  try {
    accessSync(p, fsConstants.W_OK);
  } catch {
    throw new Error(
      `${p} is not writable. Repair with: chown -R $USER ${p}`,
    );
  }
}

function atomicInstall(src: string, dst: string): void {
  const tmp = `${dst}.tmp.${process.pid}`;
  if (existsSync(tmp)) unlinkSync(tmp);
  copyFileSync(src, tmp);
  try {
    chmodSync(tmp, 0o755);
    renameSync(tmp, dst);
  } catch (err) {
    try {
      unlinkSync(tmp);
    } catch {
      // ignore
    }
    throw err;
  }
}

function ensureDefaultConfig(): string {
  const root = runtimeRoot();
  ensureDirWritable(root);
  const cfgPath = join(root, 'config.json');
  if (existsSync(cfgPath)) return cfgPath;
  const cfg = {
    registry: DEFAULT_REGISTRY,
    beacon: DEFAULT_BEACON,
    socket: DEFAULT_SOCKET,
    encrypt: true,
    identity: join(root, 'identity.json'),
  };
  const tmp = `${cfgPath}.tmp.${process.pid}`;
  writeFileSync(tmp, JSON.stringify(cfg, null, 2) + '\n');
  renameSync(tmp, cfgPath);
  return cfgPath;
}

// ---------------------------------------------------------------------------
// Lock
// ---------------------------------------------------------------------------

/** O_EXCL-based lockfile with bounded retry. Returns the fd to close. */
function acquireLock(rt: string, timeoutMs = 5000): number {
  const lockPath = join(rt, '.seed.lock');
  const start = Date.now();
  while (true) {
    try {
      return openSync(lockPath, fsConstants.O_RDWR | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o644);
    } catch (err: unknown) {
      const e = err as NodeJS.ErrnoException;
      if (e.code !== 'EEXIST') throw err;
      // Stale lock detection: > 30s old → reclaim.
      try {
        const age = Date.now() - statSync(lockPath).mtimeMs;
        if (age > 30_000) {
          try {
            unlinkSync(lockPath);
          } catch {
            // ignore; race
          }
          continue;
        }
      } catch {
        // ignore
      }
      if (Date.now() - start > timeoutMs) {
        // Last resort: proceed without exclusive lock. Steady state seeders
        // will be no-ops anyway, so worst case is two redundant copies.
        return -1;
      }
      // Busy-wait briefly; this is a *cold* path (first run only).
      const until = Date.now() + 50;
      while (Date.now() < until) {
        // spin
      }
    }
  }
}

function releaseLock(rt: string, fd: number): void {
  if (fd < 0) return;
  try {
    closeSync(fd);
  } catch {
    // ignore
  }
  try {
    unlinkSync(join(rt, '.seed.lock'));
  } catch {
    // ignore
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface SeedReport {
  action: 'noop' | 'seed' | 'upgrade' | 'daemon-skip';
  copied: string[];
  skipped: string[];
  bundledVersion: string;
  installedVersion: string;
  runtimeDir: string;
}

let _seededOnce = false;

export function ensureRuntimeSeeded(force = false): string {
  if (_seededOnce && !force) return runtimeBin();
  const report = runSeeder();
  _seededOnce = true;
  return report.runtimeDir;
}

export function runSeeder(): SeedReport {
  const rtRoot = runtimeRoot();
  const rt = runtimeBin();
  const pkg = pkgBinDir();

  ensureDirWritable(rtRoot);
  ensureDirWritable(rt);
  ensureDefaultConfig();

  const lockFd = acquireLock(rt);
  try {
    const bundledStr = bundledVersion();
    const installedStr = runtimeVersion(rt);
    const report: SeedReport = {
      action: 'noop',
      copied: [],
      skipped: [],
      bundledVersion: bundledStr,
      installedVersion: installedStr,
      runtimeDir: rt,
    };

    const bundled = semverTuple(bundledStr);
    const installed = semverTuple(installedStr);

    const force = process.env['PILOT_FORCE_SEED'] === '1';
    // Same-or-newer already installed → just verify completeness.
    if (!force && installed && bundled && compareSemver(bundled, installed) <= 0) {
      let needSeed = false;
      const required = [...BIN_NAMES, platformLibName()];
      for (const name of required) {
        if (!existsSync(join(rt, name))) {
          needSeed = true;
          break;
        }
      }
      if (!needSeed) {
        report.action = 'noop';
        return report;
      }
    }

    report.action = installedStr ? 'upgrade' : 'seed';
    const daemonBusy = probeDaemonLiveSync();

    const required = [...BIN_NAMES, platformLibName()];
    for (const name of required) {
      const src = join(pkg, name);
      if (!existsSync(src)) {
        // Wrong-platform package or partial bundle.
        continue;
      }
      const dst = join(rt, name);
      if (name === 'pilot-daemon' && daemonBusy && existsSync(dst)) {
        report.skipped.push(name);
        report.action = 'daemon-skip';
        continue;
      }
      try {
        atomicInstall(src, dst);
        report.copied.push(name);
      } catch (err: unknown) {
        const e = err as NodeJS.ErrnoException;
        if (e.code === 'ETXTBSY' || e.code === 'EBUSY') {
          report.skipped.push(name);
          continue;
        }
        throw err;
      }
    }

    if (bundledStr) {
      const verPath = join(rt, '.pilot-version');
      const tmp = `${verPath}.tmp.${process.pid}`;
      writeFileSync(tmp, bundledStr + '\n');
      renameSync(tmp, verPath);
    }

    return report;
  } finally {
    releaseLock(rt, lockFd);
  }
}

export function runtimeBinaryPath(name: string): string {
  const rt = ensureRuntimeSeeded();
  const p = join(rt, name);
  if (existsSync(p)) return p;
  // Last-ditch: run from the package.
  const fallback = join(pkgBinDir(), name);
  if (existsSync(fallback)) return fallback;
  throw new Error(
    `Binary '${name}' not found in ${rt} or ${pkgBinDir()}. ` +
      `This package may be for a different platform.`,
  );
}

export function runtimeLibraryPath(): string {
  const rt = ensureRuntimeSeeded();
  const name = platformLibName();
  const p = join(rt, name);
  if (existsSync(p)) return p;
  const fallback = join(pkgBinDir(), name);
  if (existsSync(fallback)) return fallback;
  throw new Error(`libpilot (${name}) not found in ${rt} or ${pkgBinDir()}.`);
}

/** Test helper. */
export function _resetSeededMarker(): void {
  _seededOnce = false;
}

/** Async daemon probe — exposed for callers that don't want the sync nc spawn. */
export async function isDaemonLive(): Promise<boolean> {
  return probeDaemonLive();
}

/** For tests: expose the raw paths. */
export const _internals = {
  pkgBinDir,
  pkgBinRoot,
  platformDirName,
  runtimeRoot,
  runtimeBin,
  platformLibName,
  bundledVersion,
  runtimeVersion,
  semverTuple,
  compareSemver,
  atomicInstall,
};

// Avoid unused-import warnings when this file is type-only consumed.
void dirname;
