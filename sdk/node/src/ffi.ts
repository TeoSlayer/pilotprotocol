/**
 * FFI binding layer — loads libpilot and declares all C function signatures.
 *
 * Uses koffi (pure-JS FFI, no native compilation) to call into the Go
 * shared library that is the single source of truth for the protocol.
 *
 * IMPORTANT: All char* returns from Go are allocated with C.CString (malloc).
 * We MUST call FreeString on every returned pointer to avoid memory leaks.
 * To achieve this, loadLibrary() returns wrapper functions that:
 *   1. Declare return types as 'void *' (not 'char *') to get raw pointers
 *   2. Decode the string with koffi.decode()
 *   3. Free the pointer with FreeString()
 *   4. Return clean JS types (string | null, Buffer)
 *
 * This mirrors the Python SDK's approach of using c_void_p instead of c_char_p
 * (see Python client.py lines 122-126).
 */

import koffi from 'koffi';
import { existsSync } from 'node:fs';
import { homedir, platform } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// ---------------------------------------------------------------------------
// Error class (defined here to avoid circular deps with client.ts)
// ---------------------------------------------------------------------------

export class PilotError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PilotError';
  }
}

// ---------------------------------------------------------------------------
// Library discovery
// ---------------------------------------------------------------------------

const LIB_NAMES: Record<string, string> = {
  darwin: 'libpilot.dylib',
  linux: 'libpilot.so',
  win32: 'libpilot.dll',
};

export function findLibrary(): string {
  const libName = LIB_NAMES[platform()];
  if (!libName) {
    throw new Error(`unsupported platform: ${platform()}`);
  }

  // 1. PILOT_LIB_PATH env var
  const envPath = process.env['PILOT_LIB_PATH'];
  if (envPath) {
    if (existsSync(envPath)) return envPath;
    throw new Error(`PILOT_LIB_PATH=${envPath} does not exist`);
  }

  // 2. ~/.pilot/bin/
  const pilotBin = join(homedir(), '.pilot', 'bin', libName);
  if (existsSync(pilotBin)) return pilotBin;

  // 3. <package>/bin/ (npm package layout: dist/ffi.js → ../bin/)
  const thisDir = resolve(fileURLToPath(import.meta.url), '..');
  const pkgBin = resolve(thisDir, '..', 'bin', libName);
  if (existsSync(pkgBin)) return pkgBin;

  // 4. Same directory as this file
  const colocated = join(thisDir, libName);
  if (existsSync(colocated)) return colocated;

  // 5. <repo>/bin/ (development layout — 3 levels up from dist/)
  const repoBin = resolve(thisDir, '..', '..', '..', 'bin', libName);
  if (existsSync(repoBin)) return repoBin;

  throw new Error(
    `Cannot find ${libName}.\n` +
    '\n' +
    'Expected locations:\n' +
    `  - ~/.pilot/bin/${libName}\n` +
    `  - ${pkgBin} (npm package)\n` +
    `  - ${colocated} (colocated)\n` +
    `  - ${repoBin} (development)\n` +
    '\n' +
    'Build it with:\n' +
    '  cd sdk/node && ./scripts/build-binaries.sh\n' +
    '\n' +
    'Or set PILOT_LIB_PATH:\n' +
    `  export PILOT_LIB_PATH=/path/to/${libName}`
  );
}

// ---------------------------------------------------------------------------
// PilotLib interface — clean JS types (all memory management is internal)
// ---------------------------------------------------------------------------

export interface PilotLib {
  // Lifecycle
  PilotConnect(socketPath: string): { handle: bigint; err: string | null };
  PilotClose(h: bigint): string | null;

  // JSON-RPC (return JSON string or null)
  PilotInfo(h: bigint): string | null;
  PilotHandshake(h: bigint, nodeId: number, justification: string): string | null;
  PilotApproveHandshake(h: bigint, nodeId: number): string | null;
  PilotRejectHandshake(h: bigint, nodeId: number, reason: string): string | null;
  PilotPendingHandshakes(h: bigint): string | null;
  PilotTrustedPeers(h: bigint): string | null;
  PilotRevokeTrust(h: bigint, nodeId: number): string | null;
  PilotResolveHostname(h: bigint, hostname: string): string | null;
  PilotSetHostname(h: bigint, hostname: string): string | null;
  PilotSetVisibility(h: bigint, public_: number): string | null;
  PilotSetTaskExec(h: bigint, enabled: number): string | null;
  PilotDeregister(h: bigint): string | null;
  PilotSetTags(h: bigint, tagsJson: string): string | null;
  PilotSetWebhook(h: bigint, url: string): string | null;
  PilotDisconnect(h: bigint, connId: number): string | null;
  PilotRecvFrom(h: bigint): string | null;

  // Stream connections
  PilotDial(h: bigint, addr: string): { handle: bigint; err: string | null };
  PilotListen(h: bigint, port: number): { handle: bigint; err: string | null };
  PilotListenerAccept(h: bigint): { handle: bigint; err: string | null };
  PilotListenerClose(h: bigint): string | null;

  // Conn I/O (data as Buffer, not raw pointer)
  PilotConnRead(h: bigint, bufSize: number): { n: number; data: Buffer | null; err: string | null };
  PilotConnWrite(h: bigint, data: Buffer, dataLen: number): { n: number; err: string | null };
  PilotConnClose(h: bigint): string | null;

  // Datagrams
  PilotSendTo(h: bigint, addr: string, data: Buffer, dataLen: number): string | null;
}

// ---------------------------------------------------------------------------
// Library loading with memory-safe wrappers
// ---------------------------------------------------------------------------

/**
 * Struct definitions use 'void *' for all char* fields to preserve raw
 * pointers. koffi's 'char *' auto-decodes to JS string and discards the
 * pointer — making it impossible to call FreeString. Using 'void *' gives
 * us the raw pointer so we can decode + free explicitly.
 */
const HandleErrStruct = koffi.struct('HandleErr', {
  handle: 'uint64',
  err: 'void *',
});

const ReadResultStruct = koffi.struct('ReadResult', {
  n: 'int',
  data: 'void *',
  err: 'void *',
});

const WriteResultStruct = koffi.struct('WriteResult', {
  n: 'int',
  err: 'void *',
});

export function loadLibrary(path?: string): PilotLib {
  const libPath = path ?? findLibrary();
  const lib = koffi.load(libPath);

  // Raw FFI declarations — all char* returns use 'void *'
  const rawFree = lib.func('FreeString', 'void', ['void *']);
  const rawConnect = lib.func('PilotConnect', HandleErrStruct, ['str']);
  const rawClose = lib.func('PilotClose', 'void *', ['uint64']);
  const rawInfo = lib.func('PilotInfo', 'void *', ['uint64']);
  const rawHandshake = lib.func('PilotHandshake', 'void *', ['uint64', 'uint32', 'str']);
  const rawApproveHandshake = lib.func('PilotApproveHandshake', 'void *', ['uint64', 'uint32']);
  const rawRejectHandshake = lib.func('PilotRejectHandshake', 'void *', ['uint64', 'uint32', 'str']);
  const rawPendingHandshakes = lib.func('PilotPendingHandshakes', 'void *', ['uint64']);
  const rawTrustedPeers = lib.func('PilotTrustedPeers', 'void *', ['uint64']);
  const rawRevokeTrust = lib.func('PilotRevokeTrust', 'void *', ['uint64', 'uint32']);
  const rawResolveHostname = lib.func('PilotResolveHostname', 'void *', ['uint64', 'str']);
  const rawSetHostname = lib.func('PilotSetHostname', 'void *', ['uint64', 'str']);
  const rawSetVisibility = lib.func('PilotSetVisibility', 'void *', ['uint64', 'int']);
  const rawSetTaskExec = lib.func('PilotSetTaskExec', 'void *', ['uint64', 'int']);
  const rawDeregister = lib.func('PilotDeregister', 'void *', ['uint64']);
  const rawSetTags = lib.func('PilotSetTags', 'void *', ['uint64', 'str']);
  const rawSetWebhook = lib.func('PilotSetWebhook', 'void *', ['uint64', 'str']);
  const rawDisconnect = lib.func('PilotDisconnect', 'void *', ['uint64', 'uint32']);
  const rawRecvFrom = lib.func('PilotRecvFrom', 'void *', ['uint64']);
  const rawDial = lib.func('PilotDial', HandleErrStruct, ['uint64', 'str']);
  const rawListen = lib.func('PilotListen', HandleErrStruct, ['uint64', 'uint16']);
  const rawListenerAccept = lib.func('PilotListenerAccept', HandleErrStruct, ['uint64']);
  const rawListenerClose = lib.func('PilotListenerClose', 'void *', ['uint64']);
  const rawConnRead = lib.func('PilotConnRead', ReadResultStruct, ['uint64', 'int']);
  const rawConnWrite = lib.func('PilotConnWrite', WriteResultStruct, ['uint64', 'void *', 'int']);
  const rawConnClose = lib.func('PilotConnClose', 'void *', ['uint64']);
  const rawSendTo = lib.func('PilotSendTo', 'void *', ['uint64', 'str', 'void *', 'int']);

  /** Decode a void* C string, free the pointer, return JS string. */
  function decodeAndFree(ptr: unknown): string | null {
    if (!ptr) return null;
    const str: string = koffi.decode(ptr, 'char', -1);
    rawFree(ptr);
    return str;
  }

  /** Unwrap a HandleErr struct: decode+free err, return clean result. */
  function unwrapHandle(res: { handle: unknown; err: unknown }): { handle: bigint; err: string | null } {
    return { handle: res.handle as bigint, err: decodeAndFree(res.err) };
  }

  /** Wrap a raw FFI function that returns void* (JSON char*). */
  function wrapJSON(fn: (...args: unknown[]) => unknown) {
    return (...args: unknown[]): string | null => decodeAndFree(fn(...args));
  }

  return {
    PilotConnect: (socketPath) => unwrapHandle(rawConnect(socketPath)),
    PilotClose: (h) => decodeAndFree(rawClose(h)),
    PilotInfo: wrapJSON(rawInfo),
    PilotHandshake: wrapJSON(rawHandshake),
    PilotApproveHandshake: wrapJSON(rawApproveHandshake),
    PilotRejectHandshake: wrapJSON(rawRejectHandshake),
    PilotPendingHandshakes: wrapJSON(rawPendingHandshakes),
    PilotTrustedPeers: wrapJSON(rawTrustedPeers),
    PilotRevokeTrust: wrapJSON(rawRevokeTrust),
    PilotResolveHostname: wrapJSON(rawResolveHostname),
    PilotSetHostname: wrapJSON(rawSetHostname),
    PilotSetVisibility: wrapJSON(rawSetVisibility),
    PilotSetTaskExec: wrapJSON(rawSetTaskExec),
    PilotDeregister: wrapJSON(rawDeregister),
    PilotSetTags: wrapJSON(rawSetTags),
    PilotSetWebhook: wrapJSON(rawSetWebhook),
    PilotDisconnect: wrapJSON(rawDisconnect),
    PilotRecvFrom: wrapJSON(rawRecvFrom),
    PilotDial: (h, addr) => unwrapHandle(rawDial(h, addr)),
    PilotListen: (h, port) => unwrapHandle(rawListen(h, port)),
    PilotListenerAccept: (h) => unwrapHandle(rawListenerAccept(h)),
    PilotListenerClose: (h) => decodeAndFree(rawListenerClose(h)),
    PilotConnRead(h, bufSize) {
      const res = rawConnRead(h, bufSize);
      const err = decodeAndFree(res.err);
      let data: Buffer | null = null;
      if (res.data && res.n > 0) {
        // Decode n bytes from the C.CBytes-allocated pointer into a Buffer
        const bytes: number[] = koffi.decode(res.data, 'uint8', res.n);
        data = Buffer.from(bytes);
        rawFree(res.data); // Free the C.CBytes allocation
      }
      return { n: res.n as number, data, err };
    },
    PilotConnWrite(h, buf, dataLen) {
      // Pass Buffer directly — koffi handles byteOffset correctly for void*
      const res = rawConnWrite(h, buf, dataLen);
      return { n: res.n as number, err: decodeAndFree(res.err) };
    },
    PilotConnClose: (h) => decodeAndFree(rawConnClose(h)),
    PilotSendTo(h, addr, buf, dataLen) {
      // Pass Buffer directly — koffi handles byteOffset correctly for void*
      return decodeAndFree(rawSendTo(h, addr, buf, dataLen));
    },
  };
}

// ---------------------------------------------------------------------------
// Helpers (operate on clean JS types, not raw pointers)
// ---------------------------------------------------------------------------

/** Parse a JSON string return. Raises PilotError if it contains {"error": ...}. */
export function parseJSON(str: string | null): Record<string, unknown> {
  if (!str) return {};
  const obj = JSON.parse(str);
  if (obj.error) {
    throw new PilotError(obj.error);
  }
  return obj;
}

/** Check a string error result. Raises PilotError if non-null. */
export function checkErr(str: string | null): void {
  if (!str) return;
  const obj = JSON.parse(str);
  if (obj.error) {
    throw new PilotError(obj.error);
  }
}

/** Check HandleErr result and throw if err is set. Returns handle. */
export function unwrapHandleErr(res: { handle: bigint; err: string | null }): bigint {
  if (res.err) {
    const obj = JSON.parse(res.err);
    throw new PilotError(obj.error ?? 'unknown error');
  }
  return res.handle;
}
