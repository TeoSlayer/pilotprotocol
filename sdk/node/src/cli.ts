/**
 * CLI entry points for the Pilot Protocol Node SDK.
 *
 * Each wrapper:
 *   1. Seeds `~/.pilot/bin/` from the package's bundled binaries (the
 *      `runtime` module is idempotent and concurrency-safe).
 *   2. Execs the seeded binary with all CLI arguments passed through.
 *
 * This keeps a single canonical runtime location at `~/.pilot/bin/`,
 * shared with `install.sh` and any other Pilot SDK install on the host.
 */

import { spawnSync } from 'node:child_process';
import { ensureRuntimeSeeded, runtimeBinaryPath } from './runtime.js';

function runBinary(name: string): void {
  ensureRuntimeSeeded();
  const binary = runtimeBinaryPath(name);
  const args = process.argv.slice(2);
  const r = spawnSync(binary, args, { stdio: 'inherit', env: process.env });
  if (r.error) {
    process.stderr.write(`pilot: failed to launch ${name}: ${String(r.error)}\n`);
    process.exit(1);
  }
  process.exit(r.status ?? 1);
}

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
