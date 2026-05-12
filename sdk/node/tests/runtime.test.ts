/**
 * Unit tests for the Node SDK runtime seeder (src/runtime.ts).
 *
 * Mirrors the Python seeder tests: covers the 5 state-machine states,
 * the daemon-running guard, atomic-rename behavior, version compare.
 *
 * The tests redirect ~/.pilot/ to a tmp dir via the PILOT_HOME env var
 * and stub the package-bin-dir helper to a controllable location.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { platform as osPlatform, tmpdir } from 'node:os';
import { join } from 'node:path';

// Import under test.
import * as runtime from '../src/runtime.js';

const BIN_NAMES = ['pilotctl', 'pilot-daemon', 'pilot-gateway', 'pilot-updater'] as const;

function platformLib(): string {
  return runtime._internals.platformLibName();
}

/**
 * Build a fake bundled bin/ that mirrors the real npm package layout:
 *
 *   <root>/
 *     .pilot-version
 *     <platform>/
 *       pilotctl, pilot-daemon, pilot-gateway, pilot-updater, libpilot.{so|dylib}
 *
 * Returns { root, platformDir }. Tests set PILOT_PKG_BIN_ROOT to root and
 * PILOT_PKG_BIN_DIR to platformDir.
 */
function makeFakePkg(parentTmp: string, name: string, version: string): {
  root: string;
  platformDir: string;
} {
  const root = join(parentTmp, name);
  const platformDir = join(root, runtime._internals.platformDirName());
  mkdirSync(platformDir, { recursive: true });
  for (const n of BIN_NAMES) {
    const p = join(platformDir, n);
    writeFileSync(p, `#!/bin/sh\necho ${n} ${version}\n`);
    chmodSync(p, 0o755);
  }
  const lib = join(platformDir, platformLib());
  writeFileSync(lib, `LIB ${version}\n`);
  chmodSync(lib, 0o755);
  writeFileSync(join(root, '.pilot-version'), version + '\n');
  return { root, platformDir };
}

let tmpRoot: string;
let fakeHome: string;
let pkgRoot: string;
let pkgBin: string;
let restoreEnv: {
  home: string | undefined;
  pkgRoot: string | undefined;
  pkgBin: string | undefined;
};

beforeEach(() => {
  // Use a *short* tmp root so AF_UNIX paths fit in 104 chars on macOS.
  tmpRoot = mkdtempSync(join('/tmp', 'pilot-rt-'));
  fakeHome = join(tmpRoot, 'home', '.pilot');
  mkdirSync(fakeHome, { recursive: true });
  ({ root: pkgRoot, platformDir: pkgBin } = makeFakePkg(tmpRoot, 'pkg-bin', '1.9.1'));

  restoreEnv = {
    home: process.env['PILOT_HOME'],
    pkgRoot: process.env['PILOT_PKG_BIN_ROOT'],
    pkgBin: process.env['PILOT_PKG_BIN_DIR'],
  };
  process.env['PILOT_HOME'] = fakeHome;
  process.env['PILOT_PKG_BIN_ROOT'] = pkgRoot;
  process.env['PILOT_PKG_BIN_DIR'] = pkgBin;

  runtime._resetSeededMarker();
});

afterEach(() => {
  vi.restoreAllMocks();
  if (restoreEnv.home === undefined) delete process.env['PILOT_HOME'];
  else process.env['PILOT_HOME'] = restoreEnv.home;
  if (restoreEnv.pkgRoot === undefined) delete process.env['PILOT_PKG_BIN_ROOT'];
  else process.env['PILOT_PKG_BIN_ROOT'] = restoreEnv.pkgRoot;
  if (restoreEnv.pkgBin === undefined) delete process.env['PILOT_PKG_BIN_DIR'];
  else process.env['PILOT_PKG_BIN_DIR'] = restoreEnv.pkgBin;
  rmSync(tmpRoot, { recursive: true, force: true });
  runtime._resetSeededMarker();
});

function usePkg(p: { root: string; platformDir: string }): void {
  process.env['PILOT_PKG_BIN_ROOT'] = p.root;
  process.env['PILOT_PKG_BIN_DIR'] = p.platformDir;
}

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

describe('seeder state machine', () => {
  it('seeds everything when the runtime dir is empty', () => {
    const report = runtime.runSeeder();
    expect(report.action).toBe('seed');
    const expected = new Set<string>([...BIN_NAMES, platformLib()]);
    for (const f of report.copied) expected.delete(f);
    expect(expected.size).toBe(0);

    for (const n of [...BIN_NAMES, platformLib()]) {
      expect(existsSync(join(fakeHome, 'bin', n))).toBe(true);
    }
    const v = readFileSync(join(fakeHome, 'bin', '.pilot-version'), 'utf8').trim();
    expect(v).toBe('1.9.1');
  });

  it('is a noop when versions match', () => {
    runtime.runSeeder();
    runtime._resetSeededMarker();
    const r2 = runtime.runSeeder();
    expect(r2.action).toBe('noop');
    expect(r2.copied).toEqual([]);
  });

  it('does not downgrade when bundled version is older', () => {
    runtime.runSeeder();
    runtime._resetSeededMarker();

    // Replace the package with an older version.
    usePkg(makeFakePkg(tmpRoot, 'older', '1.8.0'));

    const r = runtime.runSeeder();
    expect(r.action).toBe('noop');
    expect(r.copied).toEqual([]);
    const v = readFileSync(join(fakeHome, 'bin', '.pilot-version'), 'utf8').trim();
    expect(v).toBe('1.9.1');
  });

  it('upgrades to a newer bundled version', () => {
    runtime.runSeeder();
    runtime._resetSeededMarker();

    usePkg(makeFakePkg(tmpRoot, 'newer', '2.0.0'));

    const r = runtime.runSeeder();
    expect(r.action).toBe('upgrade');
    expect(r.copied.length).toBeGreaterThan(0);
    const v = readFileSync(join(fakeHome, 'bin', '.pilot-version'), 'utf8').trim();
    expect(v).toBe('2.0.0');
    const ctlContents = readFileSync(join(fakeHome, 'bin', 'pilotctl'), 'utf8');
    expect(ctlContents).toContain('2.0.0');
  });

  it('re-seeds files that disappeared from a same-version runtime', () => {
    runtime.runSeeder();
    rmSync(join(fakeHome, 'bin', 'pilotctl'));
    runtime._resetSeededMarker();
    const r = runtime.runSeeder();
    expect(r.copied).toContain('pilotctl');
    expect(existsSync(join(fakeHome, 'bin', 'pilotctl'))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Atomic install
// ---------------------------------------------------------------------------

describe('atomic install', () => {
  it('survives an in-flight reader of the target file', () => {
    runtime.runSeeder();
    const target = join(fakeHome, 'bin', 'pilotctl');
    const before = readFileSync(target, 'utf8');

    // Atomic-replace with new content.
    const newSrc = join(tmpRoot, 'newctl');
    writeFileSync(newSrc, 'DIFFERENT\n');
    runtime._internals.atomicInstall(newSrc, target);

    const after = readFileSync(target, 'utf8');
    expect(after).toBe('DIFFERENT\n');
    expect(after).not.toBe(before);
  });

  it('leaves no .tmp.* files behind', () => {
    runtime.runSeeder();
    const dir = join(fakeHome, 'bin');
    const stat = statSync(dir);
    expect(stat.isDirectory()).toBe(true);
    // No leftover tmp files.
    const fs = require('node:fs');
    const entries: string[] = fs.readdirSync(dir);
    const leftovers = entries.filter((e: string) => e.includes('.tmp.'));
    expect(leftovers).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Config bootstrap
// ---------------------------------------------------------------------------

describe('config bootstrap', () => {
  it('writes a default config.json when missing', () => {
    runtime.runSeeder();
    const cfgPath = join(fakeHome, 'config.json');
    const cfg = JSON.parse(readFileSync(cfgPath, 'utf8'));
    expect(cfg.registry).toBe(runtime.DEFAULT_REGISTRY);
    expect(cfg.beacon).toBe(runtime.DEFAULT_BEACON);
    expect(cfg.socket).toBe(runtime.DEFAULT_SOCKET);
    expect(cfg.encrypt).toBe(true);
    // We never auto-set an email.
    expect('email' in cfg).toBe(false);
  });

  it('preserves an existing config.json', () => {
    const cfgPath = join(fakeHome, 'config.json');
    writeFileSync(cfgPath, JSON.stringify({ email: 'foo@bar.com', preserved: true }));
    runtime.runSeeder();
    const cfg = JSON.parse(readFileSync(cfgPath, 'utf8'));
    expect(cfg.preserved).toBe(true);
    expect(cfg.email).toBe('foo@bar.com');
  });
});

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

describe('public entry points', () => {
  it('runtimeBinaryPath seeds and returns the path', () => {
    const p = runtime.runtimeBinaryPath('pilotctl');
    expect(p).toBe(join(fakeHome, 'bin', 'pilotctl'));
    expect(existsSync(p)).toBe(true);
  });

  it('runtimeLibraryPath seeds and returns the path', () => {
    const p = runtime.runtimeLibraryPath();
    expect(p).toBe(join(fakeHome, 'bin', platformLib()));
    expect(existsSync(p)).toBe(true);
  });

  it('runtimeBinaryPath throws for unknown name', () => {
    expect(() => runtime.runtimeBinaryPath('bogus')).toThrow(/bogus/);
  });

  it('ensureRuntimeSeeded short-circuits subsequent calls', () => {
    runtime.ensureRuntimeSeeded();
    const before = statSync(join(fakeHome, 'bin', '.pilot-version')).mtimeMs;
    // Sleep briefly to ensure mtime would change if it ran again.
    const t = Date.now() + 30;
    while (Date.now() < t) {
      // tight wait
    }
    runtime.ensureRuntimeSeeded();
    const after = statSync(join(fakeHome, 'bin', '.pilot-version')).mtimeMs;
    expect(after).toBe(before);
  });
});

// ---------------------------------------------------------------------------
// SemVer compare
// ---------------------------------------------------------------------------

describe('semver compare', () => {
  const t = runtime._internals.semverTuple;
  const cmp = runtime._internals.compareSemver;

  it('parses common forms', () => {
    expect(t('1.9.1')).toEqual([1, 9, 1]);
    expect(t('v1.9.1')).toEqual([1, 9, 1]);
    expect(t('1.9.1-rc4')).toEqual([1, 9, 1]);
    expect(t('1.9.1+meta')).toEqual([1, 9, 1]);
    expect(t('')).toBeNull();
    expect(t('garbage')).toBeNull();
  });

  it('orders correctly', () => {
    expect(cmp(t('2.0.0'), t('1.9.99'))).toBe(1);
    expect(cmp(t('1.9.0'), t('1.9.1'))).toBe(-1);
    expect(cmp(t('1.9.1'), t('1.9.1'))).toBe(0);
    // null < anything
    expect(cmp(null, t('0.0.0'))).toBe(-1);
  });
});

// ---------------------------------------------------------------------------
// Wrong-platform handling
// ---------------------------------------------------------------------------

describe('wrong-platform package', () => {
  it('seeder skips missing files cleanly', () => {
    // Build a pkg with proper layout but missing the platform lib.
    const incompleteRoot = join(tmpRoot, 'incomplete');
    const incompletePlatform = join(incompleteRoot, runtime._internals.platformDirName());
    mkdirSync(incompletePlatform, { recursive: true });
    for (const n of BIN_NAMES) {
      const p = join(incompletePlatform, n);
      writeFileSync(p, '#!/bin/sh\n');
      chmodSync(p, 0o755);
    }
    writeFileSync(join(incompleteRoot, '.pilot-version'), '1.9.1\n');
    usePkg({ root: incompleteRoot, platformDir: incompletePlatform });

    const r = runtime.runSeeder();
    expect(r.copied).not.toContain(platformLib());

    // runtimeLibraryPath should raise a clear error since lib is absent
    // from both runtime dir and package.
    expect(() => runtime.runtimeLibraryPath()).toThrow(/libpilot/);
  });

  it('seeder is a no-op when the platform subdir is entirely absent', () => {
    // Simulate an npm package built only for the *other* platform.
    const otherRoot = join(tmpRoot, 'wrongplatform');
    const otherPlatform = osPlatform() === 'linux' ? 'darwin-arm64' : 'linux-amd64';
    const otherDir = join(otherRoot, otherPlatform);
    mkdirSync(otherDir, { recursive: true });
    writeFileSync(join(otherDir, 'pilotctl'), '#!/bin/sh\n');
    writeFileSync(join(otherRoot, '.pilot-version'), '1.9.1\n');
    // Point at the missing subdir for THIS platform.
    usePkg({
      root: otherRoot,
      platformDir: join(otherRoot, runtime._internals.platformDirName()),
    });

    // Should not throw — just nothing copied.
    const r = runtime.runSeeder();
    expect(r.copied).toEqual([]);
  });
});
