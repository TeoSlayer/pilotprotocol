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
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

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
 * Get absolute path to a bundled binary.
 * Searches in the package's bin/ directory (relative to this file's location).
 */
function getBinaryPath(binaryName: string): string {
  const thisDir = resolve(fileURLToPath(import.meta.url), '..');

  // When compiled: dist/cli.js → look for ../bin/
  const pkgBin = resolve(thisDir, '..', 'bin', binaryName);
  if (existsSync(pkgBin)) return pkgBin;

  // Development: src/cli.ts → look for ../../bin/ (through sdk/node/)
  const devBin = resolve(thisDir, '..', '..', 'bin', binaryName);
  if (existsSync(devBin)) return devBin;

  throw new Error(
    `Binary '${binaryName}' not found.\n` +
    '\n' +
    'Expected locations:\n' +
    `  - ${pkgBin} (npm package)\n` +
    `  - ${devBin} (development)\n` +
    '\n' +
    'Build binaries with:\n' +
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
