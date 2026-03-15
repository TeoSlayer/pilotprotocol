/**
 * Unit tests for the Node.js SDK.
 *
 * These tests mock the FFI boundary (the koffi-loaded library) so they run
 * without a real daemon or shared library. They verify:
 *   - Library discovery logic
 *   - JSON error parsing helpers
 *   - Driver / Conn / Listener wrappers behave correctly
 *   - Argument marshalling and error handling
 */

import { describe, it, expect, beforeEach } from 'vitest';
import type { PilotLib } from '../src/ffi.js';

import {
  Driver,
  Conn,
  Listener,
  PilotError,
  DEFAULT_SOCKET_PATH,
  _setLib,
} from '../src/client.js';
import { parseJSON, checkErr, findLibrary } from '../src/ffi.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function jsonErr(msg: string): string {
  return JSON.stringify({ error: msg });
}

function jsonOk(data: Record<string, unknown>): string {
  return JSON.stringify(data);
}

/**
 * Create a fake PilotLib that returns controllable values.
 *
 * All methods return clean JS types (string | null, Buffer) matching the
 * PilotLib interface — the real loadLibrary() wrappers handle the C memory
 * management internally, so the mock doesn't need to simulate pointers.
 */
function createFakeLib(): PilotLib & {
  _connectResult: { handle: bigint; err: string | null };
  _jsonReturns: Record<string, string | null>;
} {
  const fake = {
    _connectResult: { handle: 1n, err: null } as { handle: bigint; err: string | null },
    _jsonReturns: {} as Record<string, string | null>,

    PilotConnect(_path: string) { return fake._connectResult; },
    PilotClose(_h: bigint) { return null as string | null; },
    PilotInfo(_h: bigint) { return fake._jsonReturns['PilotInfo'] ?? jsonOk({ node_id: 42 }); },
    PilotPendingHandshakes(_h: bigint) { return fake._jsonReturns['PilotPendingHandshakes'] ?? jsonOk({ pending: [] }); },
    PilotTrustedPeers(_h: bigint) { return fake._jsonReturns['PilotTrustedPeers'] ?? jsonOk({ peers: [] }); },
    PilotDeregister(_h: bigint) { return fake._jsonReturns['PilotDeregister'] ?? jsonOk({ status: 'ok' }); },
    PilotHandshake(_h: bigint, _nodeId: number, _j: string) { return fake._jsonReturns['PilotHandshake'] ?? jsonOk({ status: 'sent' }); },
    PilotApproveHandshake(_h: bigint, _nodeId: number) { return fake._jsonReturns['PilotApproveHandshake'] ?? jsonOk({ status: 'approved' }); },
    PilotRejectHandshake(_h: bigint, _nodeId: number, _r: string) { return fake._jsonReturns['PilotRejectHandshake'] ?? jsonOk({ status: 'rejected' }); },
    PilotRevokeTrust(_h: bigint, _nodeId: number) { return fake._jsonReturns['PilotRevokeTrust'] ?? jsonOk({ status: 'revoked' }); },
    PilotResolveHostname(_h: bigint, _hostname: string) { return fake._jsonReturns['PilotResolveHostname'] ?? jsonOk({ node_id: 7 }); },
    PilotSetHostname(_h: bigint, _hostname: string) { return fake._jsonReturns['PilotSetHostname'] ?? jsonOk({ status: 'ok' }); },
    PilotSetVisibility(_h: bigint, _pub: number) { return fake._jsonReturns['PilotSetVisibility'] ?? jsonOk({ status: 'ok' }); },
    PilotSetTaskExec(_h: bigint, _en: number) { return fake._jsonReturns['PilotSetTaskExec'] ?? jsonOk({ status: 'ok' }); },
    PilotSetTags(_h: bigint, _tags: string) { return fake._jsonReturns['PilotSetTags'] ?? jsonOk({ status: 'ok' }); },
    PilotSetWebhook(_h: bigint, _url: string) { return fake._jsonReturns['PilotSetWebhook'] ?? jsonOk({ status: 'ok' }); },
    PilotDisconnect(_h: bigint, _connId: number) { return null as string | null; },
    PilotRecvFrom(_h: bigint) {
      return fake._jsonReturns['PilotRecvFrom'] ?? jsonOk({
        src_addr: '0:0001.0000.0001',
        src_port: 8080,
        dst_port: 9090,
        data: 'aGVsbG8=',
      });
    },
    PilotDial(_h: bigint, _addr: string) { return { handle: 10n, err: null as string | null }; },
    PilotListen(_h: bigint, _port: number) { return { handle: 20n, err: null as string | null }; },
    PilotListenerAccept(_h: bigint) { return { handle: 30n, err: null as string | null }; },
    PilotListenerClose(_h: bigint) { return null as string | null; },
    PilotConnRead(_h: bigint, _size: number) {
      return { n: 5, data: Buffer.from('hello') as Buffer | null, err: null as string | null };
    },
    PilotConnWrite(_h: bigint, _data: Buffer, dataLen: number) {
      return { n: dataLen, err: null as string | null };
    },
    PilotConnClose(_h: bigint) { return null as string | null; },
    PilotSendTo(_h: bigint, _addr: string, _data: Buffer, _len: number) { return null as string | null; },
  };

  return fake;
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

let fakeLib: ReturnType<typeof createFakeLib>;

beforeEach(() => {
  fakeLib = createFakeLib();
  _setLib(fakeLib);
});

// ---------------------------------------------------------------------------
// Error helper tests
// ---------------------------------------------------------------------------

describe('checkErr', () => {
  it('does nothing for null', () => {
    expect(() => checkErr(null)).not.toThrow();
  });

  it('throws PilotError for JSON error', () => {
    expect(() => checkErr(jsonErr('boom'))).toThrow(PilotError);
    expect(() => checkErr(jsonErr('boom'))).toThrow('boom');
  });
});

describe('parseJSON', () => {
  it('returns empty object for null', () => {
    expect(parseJSON(null)).toEqual({});
  });

  it('parses valid JSON', () => {
    expect(parseJSON(jsonOk({ a: 1 }))).toEqual({ a: 1 });
  });

  it('throws on error JSON', () => {
    expect(() => parseJSON(jsonErr('fail'))).toThrow(PilotError);
    expect(() => parseJSON(jsonErr('fail'))).toThrow('fail');
  });
});

// ---------------------------------------------------------------------------
// Driver lifecycle tests
// ---------------------------------------------------------------------------

describe('Driver lifecycle', () => {
  it('connects with default path', () => {
    const d = new Driver();
    expect(d).toBeInstanceOf(Driver);
    d.close();
  });

  it('connects with custom path', () => {
    const d = new Driver('/custom/pilot.sock');
    expect(d).toBeInstanceOf(Driver);
    d.close();
  });

  it('throws on connect error', () => {
    fakeLib._connectResult = { handle: 0n, err: jsonErr('no daemon') };
    expect(() => new Driver()).toThrow(PilotError);
    expect(() => {
      fakeLib._connectResult = { handle: 0n, err: jsonErr('no daemon') };
      return new Driver();
    }).toThrow('no daemon');
  });

  it('close is idempotent', () => {
    const d = new Driver();
    d.close();
    d.close(); // should not throw
  });

  it('Symbol.dispose closes', () => {
    const d = new Driver();
    d[Symbol.dispose]();
    d.close(); // idempotent
  });
});

// ---------------------------------------------------------------------------
// Driver info tests
// ---------------------------------------------------------------------------

describe('Driver info', () => {
  it('returns info', () => {
    const d = new Driver();
    const result = d.info();
    expect(result).toEqual({ node_id: 42 });
    d.close();
  });

  it('throws on info error', () => {
    fakeLib._jsonReturns['PilotInfo'] = jsonErr('daemon unreachable');
    const d = new Driver();
    expect(() => d.info()).toThrow('daemon unreachable');
    d.close();
  });
});

// ---------------------------------------------------------------------------
// Driver handshake tests
// ---------------------------------------------------------------------------

describe('Driver handshake', () => {
  it('handshake', () => {
    const d = new Driver();
    expect(d.handshake(42, 'test')).toEqual({ status: 'sent' });
    d.close();
  });

  it('approve', () => {
    const d = new Driver();
    expect(d.approveHandshake(42)).toEqual({ status: 'approved' });
    d.close();
  });

  it('reject', () => {
    const d = new Driver();
    expect(d.rejectHandshake(42, 'no thanks')).toEqual({ status: 'rejected' });
    d.close();
  });

  it('pending', () => {
    const d = new Driver();
    const r = d.pendingHandshakes();
    expect(r).toHaveProperty('pending');
    d.close();
  });

  it('trusted', () => {
    const d = new Driver();
    const r = d.trustedPeers();
    expect(r).toHaveProperty('peers');
    d.close();
  });

  it('revoke', () => {
    const d = new Driver();
    expect(d.revokeTrust(42)).toEqual({ status: 'revoked' });
    d.close();
  });
});

// ---------------------------------------------------------------------------
// Driver hostname tests
// ---------------------------------------------------------------------------

describe('Driver hostname', () => {
  it('resolve', () => {
    const d = new Driver();
    expect(d.resolveHostname('myhost')).toEqual({ node_id: 7 });
    d.close();
  });

  it('set hostname', () => {
    const d = new Driver();
    expect(d.setHostname('newhost')).toEqual({ status: 'ok' });
    d.close();
  });
});

// ---------------------------------------------------------------------------
// Driver settings tests
// ---------------------------------------------------------------------------

describe('Driver settings', () => {
  it('set visibility', () => {
    const d = new Driver();
    expect(d.setVisibility(true)).toEqual({ status: 'ok' });
    d.close();
  });

  it('set task exec', () => {
    const d = new Driver();
    expect(d.setTaskExec(false)).toEqual({ status: 'ok' });
    d.close();
  });

  it('deregister', () => {
    const d = new Driver();
    expect(d.deregister()).toEqual({ status: 'ok' });
    d.close();
  });

  it('set tags', () => {
    const d = new Driver();
    expect(d.setTags(['gpu', 'cuda'])).toEqual({ status: 'ok' });
    d.close();
  });

  it('set webhook', () => {
    const d = new Driver();
    expect(d.setWebhook('https://example.com/hook')).toEqual({ status: 'ok' });
    d.close();
  });
});

// ---------------------------------------------------------------------------
// Driver disconnect tests
// ---------------------------------------------------------------------------

describe('Driver disconnect', () => {
  it('disconnect', () => {
    const d = new Driver();
    d.disconnect(123); // should not throw
    d.close();
  });
});

// ---------------------------------------------------------------------------
// Stream tests — Dial
// ---------------------------------------------------------------------------

describe('Driver dial', () => {
  it('returns a Conn', () => {
    const d = new Driver();
    const conn = d.dial('0:0001.0000.0002:8080');
    expect(conn).toBeInstanceOf(Conn);
    conn.close();
    d.close();
  });

  it('throws on dial error', () => {
    fakeLib.PilotDial = (_h: bigint, _addr: string) => ({
      handle: 0n,
      err: jsonErr('unreachable'),
    });
    const d = new Driver();
    expect(() => d.dial('bad:addr')).toThrow('unreachable');
    d.close();
  });
});

// ---------------------------------------------------------------------------
// Stream tests — Listen
// ---------------------------------------------------------------------------

describe('Driver listen', () => {
  it('returns a Listener', () => {
    const d = new Driver();
    const ln = d.listen(8080);
    expect(ln).toBeInstanceOf(Listener);
    ln.close();
    d.close();
  });

  it('throws on listen error', () => {
    fakeLib.PilotListen = (_h: bigint, _port: number) => ({
      handle: 0n,
      err: jsonErr('port in use'),
    });
    const d = new Driver();
    expect(() => d.listen(8080)).toThrow('port in use');
    d.close();
  });
});

// ---------------------------------------------------------------------------
// Conn tests
// ---------------------------------------------------------------------------

describe('Conn', () => {
  it('read returns Buffer with correct data', () => {
    const conn = new Conn(10n);
    const data = conn.read(4096);
    expect(Buffer.isBuffer(data)).toBe(true);
    expect(data.toString()).toBe('hello');
    conn.close();
  });

  it('read closed throws', () => {
    const conn = new Conn(10n);
    conn.close();
    expect(() => conn.read()).toThrow('connection closed');
  });

  it('write', () => {
    const conn = new Conn(10n);
    const n = conn.write(Buffer.from('world'));
    expect(n).toBe(5);
    conn.close();
  });

  it('write string', () => {
    const conn = new Conn(10n);
    const n = conn.write('hello');
    expect(n).toBe(5);
    conn.close();
  });

  it('write closed throws', () => {
    const conn = new Conn(10n);
    conn.close();
    expect(() => conn.write(Buffer.from('x'))).toThrow('connection closed');
  });

  it('close is idempotent', () => {
    const conn = new Conn(10n);
    conn.close();
    conn.close(); // no error
  });

  it('Symbol.dispose closes', () => {
    const conn = new Conn(10n);
    conn[Symbol.dispose]();
    conn.close(); // idempotent
  });
});

// ---------------------------------------------------------------------------
// Conn error paths
// ---------------------------------------------------------------------------

describe('Conn error paths', () => {
  it('read error from Go', () => {
    fakeLib.PilotConnRead = (_h: bigint, _size: number) => ({
      n: 0,
      data: null,
      err: jsonErr('connection reset'),
    });
    const conn = new Conn(10n);
    expect(() => conn.read()).toThrow('connection reset');
  });

  it('read empty response', () => {
    fakeLib.PilotConnRead = (_h: bigint, _size: number) => ({
      n: 0,
      data: null,
      err: null,
    });
    const conn = new Conn(10n);
    const result = conn.read();
    expect(result.length).toBe(0);
    conn.close();
  });

  it('write error from Go', () => {
    fakeLib.PilotConnWrite = (_h: bigint, _data: Buffer, _len: number) => ({
      n: 0,
      err: jsonErr('broken pipe'),
    });
    const conn = new Conn(10n);
    expect(() => conn.write(Buffer.from('data'))).toThrow('broken pipe');
  });

  it('close with error response', () => {
    fakeLib.PilotConnClose = (_h: bigint) => jsonErr('already closed');
    const conn = new Conn(10n);
    expect(() => conn.close()).toThrow('already closed');
  });
});

// ---------------------------------------------------------------------------
// Listener tests
// ---------------------------------------------------------------------------

describe('Listener', () => {
  it('accept', () => {
    const ln = new Listener(20n);
    const conn = ln.accept();
    expect(conn).toBeInstanceOf(Conn);
    conn.close();
    ln.close();
  });

  it('accept closed throws', () => {
    const ln = new Listener(20n);
    ln.close();
    expect(() => ln.accept()).toThrow('listener closed');
  });

  it('close is idempotent', () => {
    const ln = new Listener(20n);
    ln.close();
    ln.close();
  });

  it('Symbol.dispose closes', () => {
    const ln = new Listener(20n);
    ln[Symbol.dispose]();
    ln.close();
  });
});

// ---------------------------------------------------------------------------
// Listener error paths
// ---------------------------------------------------------------------------

describe('Listener error paths', () => {
  it('accept error from Go', () => {
    fakeLib.PilotListenerAccept = (_h: bigint) => ({
      handle: 0n,
      err: jsonErr('listener closed'),
    });
    const ln = new Listener(20n);
    expect(() => ln.accept()).toThrow('listener closed');
  });

  it('close with error response', () => {
    fakeLib.PilotListenerClose = (_h: bigint) => jsonErr('already closed');
    const ln = new Listener(20n);
    expect(() => ln.close()).toThrow('already closed');
  });
});

// ---------------------------------------------------------------------------
// Datagram tests
// ---------------------------------------------------------------------------

describe('Datagrams', () => {
  it('send_to', () => {
    const d = new Driver();
    d.sendTo('0:0001.0000.0002:9090', Buffer.from('payload'));
    d.close();
  });

  it('recv_from', () => {
    const d = new Driver();
    const dg = d.recvFrom();
    expect(dg['src_port']).toBe(8080);
    expect(dg['dst_port']).toBe(9090);
    d.close();
  });
});

// ---------------------------------------------------------------------------
// Library discovery tests
// ---------------------------------------------------------------------------

describe('findLibrary', () => {
  it('uses PILOT_LIB_PATH env var', () => {
    const origEnv = process.env['PILOT_LIB_PATH'];
    try {
      // Use the test file itself as a stand-in for an existing file
      const testPath = new URL(import.meta.url).pathname;
      process.env['PILOT_LIB_PATH'] = testPath;
      const result = findLibrary();
      expect(result).toBe(testPath);
    } finally {
      if (origEnv !== undefined) {
        process.env['PILOT_LIB_PATH'] = origEnv;
      } else {
        delete process.env['PILOT_LIB_PATH'];
      }
    }
  });

  it('throws on missing PILOT_LIB_PATH', () => {
    const origEnv = process.env['PILOT_LIB_PATH'];
    try {
      process.env['PILOT_LIB_PATH'] = '/nonexistent/libpilot.dylib';
      expect(() => findLibrary()).toThrow('does not exist');
    } finally {
      if (origEnv !== undefined) {
        process.env['PILOT_LIB_PATH'] = origEnv;
      } else {
        delete process.env['PILOT_LIB_PATH'];
      }
    }
  });

  it('throws on not found when all paths fail', () => {
    const origEnv = process.env['PILOT_LIB_PATH'];
    try {
      delete process.env['PILOT_LIB_PATH'];
      // This will fail because no library exists in any search path
      // (but only if none of the default locations have the file)
      // We at least verify it doesn't crash with an unexpected error
      try {
        findLibrary();
      } catch (e) {
        expect(e).toBeInstanceOf(Error);
        expect(String(e)).toMatch(/Cannot find|unsupported platform/);
      }
    } finally {
      if (origEnv !== undefined) {
        process.env['PILOT_LIB_PATH'] = origEnv;
      } else {
        delete process.env['PILOT_LIB_PATH'];
      }
    }
  });
});

// ---------------------------------------------------------------------------
// DEFAULT_SOCKET_PATH constant
// ---------------------------------------------------------------------------

describe('constants', () => {
  it('DEFAULT_SOCKET_PATH', () => {
    expect(DEFAULT_SOCKET_PATH).toBe('/tmp/pilot.sock');
  });
});

// ---------------------------------------------------------------------------
// sendFile file existence check
// ---------------------------------------------------------------------------

describe('Driver sendFile', () => {
  it('throws PilotError for missing file', () => {
    const d = new Driver();
    expect(() => d.sendFile('0:0001.0000.0001', '/nonexistent/file.txt')).toThrow(PilotError);
    expect(() => d.sendFile('0:0001.0000.0001', '/nonexistent/file.txt')).toThrow('File not found');
    d.close();
  });
});
