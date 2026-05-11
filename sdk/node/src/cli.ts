/**
 * CLI wrappers for bundled Pilot Protocol binaries.
 *
 * These functions are used as npm "bin" entry points. Each wrapper:
 * 1. Ensures ~/.pilot/ directory and default config.json exist
 * 2. Locates the bundled Go binary
 * 3. Executes it with all CLI arguments passed through
 *
 * This mirrors the Python SDK's cli.py approach.
 */

import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { arch as osArch, homedir, platform as osPlatform } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// The npm sub-package shipping THIS host's native binaries (esbuild pattern).
// Main `pilotprotocol` declares all 4 as optionalDependencies; npm fetches
// only the one matching this host's os+cpu fields.
function subPackageName(): string {
  return `pilotprotocol-${osPlatform()}-${osArch()}`;
}

/**
 * Ensure ~/.pilot/ directory and config.json exist.
 * Called before every binary execution to initialize the runtime environment.
 */
function ensurePilotEnv(): void {
  const home = homedir();
  const pilotDir = join(home, '.pilot');
  const configFile = join(pilotDir, 'config.json');

  // Create ~/.pilot/ if it doesn't exist
  if (!existsSync(pilotDir)) {
    mkdirSync(pilotDir, { recursive: true });
  }

  // Create default config.json if it doesn't exist
  if (!existsSync(configFile)) {
    const defaultConfig = {
      registry: '34.71.57.205:9000',
      beacon: '34.71.57.205:9001',
      socket: '/tmp/pilot.sock',
      encrypt: true,
      identity: join(pilotDir, 'identity.json'),
    };
    writeFileSync(configFile, JSON.stringify(defaultConfig, null, 2));
  }
}

/**
 * Resolve the absolute path to a bundled binary.
 *
 * Production layout: binaries live in the matching optional sub-package
 *   `pilotprotocol-<os>-<arch>` (npm installs only the one for this host).
 * Local-dev fallbacks (no `npm install` of the sub-package yet):
 *   - in-repo `sdk/node/packages/<os>-<arch>/bin/` (build-binaries.sh writes here)
 *   - legacy `sdk/node/bin/` (old flat layout)
 */
function getBinaryPath(binaryName: string): string {
  // 1. Optional sub-package resolved via Node's module resolver. Works
  //    whether the sub-package is hoisted at the top level of node_modules
  //    or nested next to the main package.
  try {
    const req = createRequire(import.meta.url);
    const subPkgJson = req.resolve(`${subPackageName()}/package.json`);
    const candidate = resolve(dirname(subPkgJson), 'bin', binaryName);
    if (existsSync(candidate)) return candidate;
  } catch {
    // Sub-package not installed (local dev, or wrong-platform host).
  }

  const thisDir = resolve(fileURLToPath(import.meta.url), '..');

  // 2. In-repo sub-package layout — `scripts/build-binaries.sh` writes here
  //    so local dev works without `npm install` of the sub-package itself.
  const inRepoSub = resolve(
    thisDir, '..', '..', 'packages', subPackageName().replace(/^pilotprotocol-/, ''), 'bin', binaryName,
  );
  if (existsSync(inRepoSub)) return inRepoSub;

  // 3. Legacy flat dev layouts.
  const pkgBin = resolve(thisDir, '..', 'bin', binaryName);
  if (existsSync(pkgBin)) return pkgBin;
  const devBin = resolve(thisDir, '..', '..', 'bin', binaryName);
  if (existsSync(devBin)) return devBin;

  throw new Error(
    `Binary '${binaryName}' not found.\n` +
    '\n' +
    'Expected locations:\n' +
    `  - node_modules/${subPackageName()}/bin/${binaryName} (npm sub-package)\n` +
    `  - ${inRepoSub} (in-repo dev sub-package)\n` +
    `  - ${pkgBin} (legacy npm layout)\n` +
    `  - ${devBin} (legacy dev layout)\n` +
    '\n' +
    `If you installed via npm, the sub-package '${subPackageName()}'\n` +
    'should have been installed automatically. Reinstall with:\n' +
    '  npm install pilotprotocol\n' +
    '\n' +
    'For local development, build binaries with:\n' +
    '  cd sdk/node && ./scripts/build-binaries.sh\n',
  );
}

/**
 * Execute a bundled binary with all CLI arguments passed through.
 * Exits with the same code as the binary.
 */
function runBinary(binaryName: string): void {
  ensurePilotEnv();
  const binaryPath = getBinaryPath(binaryName);
  const args = process.argv.slice(2);

  try {
    execFileSync(binaryPath, args, {
      stdio: 'inherit',
      env: process.env,
    });
  } catch (err: unknown) {
    // execFileSync throws on non-zero exit codes
    const exitCode = (err as { status?: number }).status ?? 1;
    process.exit(exitCode);
  }
}

// --- Entry points (one per binary) ---

export function runPilotctl(): void {
  runBinary('pilotctl');
}

export function runDaemon(): void {
  runBinary('pilot-daemon');
}

export function runGateway(): void {
  runBinary('pilot-gateway');
}

export function runUpdater(): void {
  runBinary('pilot-updater');
}
