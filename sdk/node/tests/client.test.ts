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

    // ---- 1.9.1 additions ----

    // Captured-arg fields for assertions (typed loosely on purpose)
    _lastDialTimeout: null as null | { addr: string; ms: bigint },
    _lastSetReadDeadline: null as bigint | null,
    _lastBroadcast: null as null | {
      networkId: number;
      port: number;
      dataLen: number;
      adminToken: string;
      payload: Buffer;
    },
    _lastNetworkJoin: null as null | { networkId: number; token: string },
    _lastNetworkInvite: null as null | { networkId: number; targetNodeId: number },
    _lastNetworkRespond: null as null | { networkId: number; accept: number },
    _lastManagedScore: null as null | {
      networkId: number;
      nodeId: number;
      delta: number;
      topic: string;
    },
    _lastPolicySet: null as null | { networkId: number; policyJson: string },
    _lastMemberTagsSet: null as null | {
      networkId: number;
      nodeId: number;
      tagsJson: string;
    },

    PilotHealth(_h: bigint) {
      return fake._jsonReturns['PilotHealth'] ?? jsonOk({ ok: true, uptime_s: 42 });
    },
    PilotRotateKey(_h: bigint) {
      return fake._jsonReturns['PilotRotateKey'] ?? jsonOk({ new_pubkey: 'abc' });
    },
    PilotDialTimeout(_h: bigint, addr: string, timeoutMs: bigint) {
      fake._lastDialTimeout = { addr, ms: timeoutMs };
      return { handle: 11n, err: null as string | null };
    },
    PilotConnSetReadDeadline(_h: bigint, deadlineUnixNanos: bigint) {
      fake._lastSetReadDeadline = deadlineUnixNanos;
      return null as string | null;
    },
    PilotBroadcast(
      _h: bigint,
      networkId: number,
      port: number,
      data: Buffer,
      dataLen: number,
      adminToken: string,
    ) {
      fake._lastBroadcast = {
        networkId,
        port,
        dataLen,
        adminToken,
        payload: Buffer.from(data.subarray(0, dataLen)),
      };
      return fake._jsonReturns['PilotBroadcast'] ?? null;
    },
    PilotNetworkList(_h: bigint) {
      return fake._jsonReturns['PilotNetworkList'] ?? jsonOk({ networks: [{ id: 0 }] });
    },
    PilotNetworkJoin(_h: bigint, networkId: number, token: string) {
      fake._lastNetworkJoin = { networkId, token };
      return fake._jsonReturns['PilotNetworkJoin'] ?? jsonOk({ status: 'joined' });
    },
    PilotNetworkLeave(_h: bigint, _networkId: number) {
      return fake._jsonReturns['PilotNetworkLeave'] ?? jsonOk({ status: 'left' });
    },
    PilotNetworkMembers(_h: bigint, _networkId: number) {
      return fake._jsonReturns['PilotNetworkMembers'] ?? jsonOk({ members: [] });
    },
    PilotNetworkInvite(_h: bigint, networkId: number, targetNodeId: number) {
      fake._lastNetworkInvite = { networkId, targetNodeId };
      return fake._jsonReturns['PilotNetworkInvite'] ?? jsonOk({ status: 'invited' });
    },
    PilotNetworkPollInvites(_h: bigint) {
      return fake._jsonReturns['PilotNetworkPollInvites'] ?? jsonOk({ invites: [] });
    },
    PilotNetworkRespondInvite(_h: bigint, networkId: number, accept: number) {
      fake._lastNetworkRespond = { networkId, accept };
      return fake._jsonReturns['PilotNetworkRespondInvite'] ?? jsonOk({ status: 'responded' });
    },
    PilotManagedScore(
      _h: bigint,
      networkId: number,
      nodeId: number,
      delta: number,
      topic: string,
    ) {
      fake._lastManagedScore = { networkId, nodeId, delta, topic };
      return fake._jsonReturns['PilotManagedScore'] ?? jsonOk({ status: 'ok' });
    },
    PilotManagedStatus(_h: bigint, networkId: number) {
      return fake._jsonReturns['PilotManagedStatus'] ?? jsonOk({ network_id: networkId });
    },
    PilotManagedRankings(_h: bigint, _networkId: number) {
      return fake._jsonReturns['PilotManagedRankings'] ?? jsonOk({ rankings: [] });
    },
    PilotManagedForceCycle(_h: bigint, _networkId: number) {
      return fake._jsonReturns['PilotManagedForceCycle'] ?? jsonOk({ status: 'cycled' });
    },
    PilotManagedReconcile(_h: bigint, networkId: number) {
      return (
        fake._jsonReturns['PilotManagedReconcile'] ??
        jsonOk({ network_id: networkId, peers: [] })
      );
    },
    PilotPolicyGet(_h: bigint, networkId: number) {
      return (
        fake._jsonReturns['PilotPolicyGet'] ??
        jsonOk({ network_id: networkId, policy: {} })
      );
    },
    PilotPolicySet(_h: bigint, networkId: number, policyJson: string) {
      fake._lastPolicySet = { networkId, policyJson };
      return fake._jsonReturns['PilotPolicySet'] ?? jsonOk({ status: 'applied' });
    },
    PilotMemberTagsGet(_h: bigint, _networkId: number, _nodeId: number) {
      return fake._jsonReturns['PilotMemberTagsGet'] ?? jsonOk({ tags: [] });
    },
    PilotMemberTagsSet(_h: bigint, networkId: number, nodeId: number, tagsJson: string) {
      fake._lastMemberTagsSet = { networkId, nodeId, tagsJson };
      return fake._jsonReturns['PilotMemberTagsSet'] ?? jsonOk({ status: 'ok' });
    },
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

// ---------------------------------------------------------------------------
// 1.9.1 additions: health / rotate-key
// ---------------------------------------------------------------------------

describe('Driver health', () => {
  it('returns the daemon health blob', () => {
    const d = new Driver();
    const r = d.health();
    expect(r['ok']).toBe(true);
    expect(r['uptime_s']).toBe(42);
    d.close();
  });

  it('throws on health error', () => {
    fakeLib._jsonReturns['PilotHealth'] = jsonErr('daemon down');
    const d = new Driver();
    expect(() => d.health()).toThrow('daemon down');
    d.close();
  });
});

describe('Driver rotateKey', () => {
  it('returns new key info', () => {
    const d = new Driver();
    expect(d.rotateKey()).toEqual({ new_pubkey: 'abc' });
    d.close();
  });

  it('throws on error', () => {
    fakeLib._jsonReturns['PilotRotateKey'] = jsonErr('registry rejected');
    const d = new Driver();
    expect(() => d.rotateKey()).toThrow('registry rejected');
    d.close();
  });
});

// ---------------------------------------------------------------------------
// 1.9.1 additions: dial timeout
// ---------------------------------------------------------------------------

describe('Driver dial timeout', () => {
  it('uses PilotDial when no timeout', () => {
    const d = new Driver();
    const conn = d.dial('0:0001.0000.0002:8080');
    // Default PilotDial returns handle 10
    expect(conn).toBeInstanceOf(Conn);
    expect(fakeLib._lastDialTimeout).toBeNull();
    conn.close();
    d.close();
  });

  it('uses PilotDialTimeout when timeoutMs is given', () => {
    const d = new Driver();
    const conn = d.dial('0:0001.0000.0002:8080', 2500);
    expect(conn).toBeInstanceOf(Conn);
    expect(fakeLib._lastDialTimeout).not.toBeNull();
    expect(fakeLib._lastDialTimeout?.addr).toBe('0:0001.0000.0002:8080');
    expect(fakeLib._lastDialTimeout?.ms).toBe(2500n);
    conn.close();
    d.close();
  });

  it('clamps negative timeoutMs to 0', () => {
    const d = new Driver();
    d.dial('0:0001.0000.0002:8080', -10);
    expect(fakeLib._lastDialTimeout?.ms).toBe(0n);
    d.close();
  });

  it('throws on dial-timeout error', () => {
    fakeLib.PilotDialTimeout = (_h: bigint, _addr: string, _ms: bigint) => ({
      handle: 0n,
      err: jsonErr('dial timeout'),
    });
    const d = new Driver();
    expect(() => d.dial('bad:addr', 1000)).toThrow('dial timeout');
    d.close();
  });
});

// ---------------------------------------------------------------------------
// 1.9.1 additions: Conn.setReadDeadline
// ---------------------------------------------------------------------------

describe('Conn setReadDeadline', () => {
  it('clears the deadline with null', () => {
    const conn = new Conn(10n);
    conn.setReadDeadline(null);
    expect(fakeLib._lastSetReadDeadline).toBe(0n);
  });

  it('converts a Date to nanoseconds', () => {
    const conn = new Conn(10n);
    const d = new Date(1700000000500); // 1.7e12 ms = 1.7e21 ns? No: 1.7e12 ms * 1e6 = 1.7e18 ns
    conn.setReadDeadline(d);
    expect(fakeLib._lastSetReadDeadline).toBe(BigInt(1700000000500) * 1_000_000n);
  });

  it('treats a number as ms-from-now', () => {
    const before = Date.now();
    const conn = new Conn(10n);
    conn.setReadDeadline(5000);
    const after = Date.now();
    const got = fakeLib._lastSetReadDeadline ?? 0n;
    // Expected nanos must be in [before+5000, after+5000] ms range
    const lo = BigInt(before + 5000) * 1_000_000n;
    const hi = BigInt(after + 5000) * 1_000_000n;
    expect(got >= lo).toBe(true);
    expect(got <= hi).toBe(true);
  });

  it('throws if the connection is closed', () => {
    const conn = new Conn(10n);
    conn.close();
    expect(() => conn.setReadDeadline(null)).toThrow('connection closed');
  });

  it('propagates errors from Go', () => {
    fakeLib.PilotConnSetReadDeadline = (_h: bigint, _d: bigint) => jsonErr('bad handle');
    const conn = new Conn(10n);
    expect(() => conn.setReadDeadline(null)).toThrow('bad handle');
  });
});

// ---------------------------------------------------------------------------
// 1.9.1 additions: broadcast
// ---------------------------------------------------------------------------

describe('Driver broadcast', () => {
  it('passes networkId, port, payload, and admin token', () => {
    const d = new Driver();
    d.broadcast(7, 1234, Buffer.from('hello'), 'secret');
    expect(fakeLib._lastBroadcast).not.toBeNull();
    expect(fakeLib._lastBroadcast?.networkId).toBe(7);
    expect(fakeLib._lastBroadcast?.port).toBe(1234);
    expect(fakeLib._lastBroadcast?.dataLen).toBe(5);
    expect(fakeLib._lastBroadcast?.adminToken).toBe('secret');
    expect(fakeLib._lastBroadcast?.payload.toString()).toBe('hello');
    d.close();
  });

  it('accepts a string payload', () => {
    const d = new Driver();
    d.broadcast(0, 9999, 'ping', 'tok');
    expect(fakeLib._lastBroadcast?.payload.toString()).toBe('ping');
    d.close();
  });

  it('throws when daemon rejects the broadcast', () => {
    fakeLib._jsonReturns['PilotBroadcast'] = jsonErr('admin token required');
    const d = new Driver();
    expect(() => d.broadcast(0, 9000, Buffer.from('x'), '')).toThrow('admin token required');
    d.close();
  });
});

// ---------------------------------------------------------------------------
// 1.9.1 additions: networks
// ---------------------------------------------------------------------------

describe('Driver networks', () => {
  it('networkList', () => {
    const d = new Driver();
    const r = d.networkList();
    expect(r).toHaveProperty('networks');
    d.close();
  });

  it('networkJoin passes networkId and token', () => {
    const d = new Driver();
    expect(d.networkJoin(7, 'joinme')).toEqual({ status: 'joined' });
    expect(fakeLib._lastNetworkJoin).toEqual({ networkId: 7, token: 'joinme' });
    d.close();
  });

  it('networkJoin defaults token to empty string', () => {
    const d = new Driver();
    d.networkJoin(2);
    expect(fakeLib._lastNetworkJoin?.token).toBe('');
    d.close();
  });

  it('networkLeave', () => {
    const d = new Driver();
    expect(d.networkLeave(7)).toEqual({ status: 'left' });
    d.close();
  });

  it('networkMembers', () => {
    const d = new Driver();
    expect(d.networkMembers(7)).toHaveProperty('members');
    d.close();
  });

  it('networkInvite captures both ids', () => {
    const d = new Driver();
    expect(d.networkInvite(7, 4242)).toEqual({ status: 'invited' });
    expect(fakeLib._lastNetworkInvite).toEqual({ networkId: 7, targetNodeId: 4242 });
    d.close();
  });

  it('networkPollInvites', () => {
    const d = new Driver();
    expect(d.networkPollInvites()).toHaveProperty('invites');
    d.close();
  });

  it('networkRespondInvite accept=true → 1', () => {
    const d = new Driver();
    d.networkRespondInvite(7, true);
    expect(fakeLib._lastNetworkRespond).toEqual({ networkId: 7, accept: 1 });
    d.close();
  });

  it('networkRespondInvite accept=false → 0', () => {
    const d = new Driver();
    d.networkRespondInvite(7, false);
    expect(fakeLib._lastNetworkRespond).toEqual({ networkId: 7, accept: 0 });
    d.close();
  });

  it('networkJoin propagates daemon error', () => {
    fakeLib._jsonReturns['PilotNetworkJoin'] = jsonErr('token rejected');
    const d = new Driver();
    expect(() => d.networkJoin(7, 'wrong')).toThrow('token rejected');
    d.close();
  });
});

// ---------------------------------------------------------------------------
// 1.9.1 additions: managed
// ---------------------------------------------------------------------------

describe('Driver managed', () => {
  it('managedScore captures all args', () => {
    const d = new Driver();
    d.managedScore(7, 4242, -3, 'spam');
    expect(fakeLib._lastManagedScore).toEqual({
      networkId: 7,
      nodeId: 4242,
      delta: -3,
      topic: 'spam',
    });
    d.close();
  });

  it('managedScore default topic is empty', () => {
    const d = new Driver();
    d.managedScore(0, 1, 5);
    expect(fakeLib._lastManagedScore?.topic).toBe('');
    d.close();
  });

  it('managedStatus echoes networkId', () => {
    const d = new Driver();
    expect(d.managedStatus(42)).toEqual({ network_id: 42 });
    d.close();
  });

  it('managedRankings', () => {
    const d = new Driver();
    expect(d.managedRankings(42)).toHaveProperty('rankings');
    d.close();
  });

  it('managedForceCycle', () => {
    const d = new Driver();
    expect(d.managedForceCycle(42)).toEqual({ status: 'cycled' });
    d.close();
  });

  it('managedReconcile', () => {
    const d = new Driver();
    const r = d.managedReconcile(42);
    expect(r['network_id']).toBe(42);
    expect(r['peers']).toEqual([]);
    d.close();
  });
});

// ---------------------------------------------------------------------------
// 1.9.1 additions: policy
// ---------------------------------------------------------------------------

describe('Driver policy', () => {
  it('policyGet', () => {
    const d = new Driver();
    expect(d.policyGet(7)).toEqual({ network_id: 7, policy: {} });
    d.close();
  });

  it('policySet serializes a dict to JSON', () => {
    const d = new Driver();
    d.policySet(7, { min_score: 3, tags: ['good'] });
    expect(fakeLib._lastPolicySet?.networkId).toBe(7);
    expect(JSON.parse(fakeLib._lastPolicySet?.policyJson ?? '')).toEqual({
      min_score: 3,
      tags: ['good'],
    });
    d.close();
  });

  it('policySet passes a string through unchanged', () => {
    const d = new Driver();
    d.policySet(0, '{"raw":true}');
    expect(fakeLib._lastPolicySet?.policyJson).toBe('{"raw":true}');
    d.close();
  });

  it('policySet decodes a Buffer to UTF-8', () => {
    const d = new Driver();
    d.policySet(0, Buffer.from('{"raw":1}'));
    expect(fakeLib._lastPolicySet?.policyJson).toBe('{"raw":1}');
    d.close();
  });

  it('policySet propagates daemon error', () => {
    fakeLib._jsonReturns['PilotPolicySet'] = jsonErr('invalid policy');
    const d = new Driver();
    expect(() => d.policySet(0, {})).toThrow('invalid policy');
    d.close();
  });
});

// ---------------------------------------------------------------------------
// 1.9.1 additions: member tags
// ---------------------------------------------------------------------------

describe('Driver memberTags', () => {
  it('memberTagsGet', () => {
    const d = new Driver();
    expect(d.memberTagsGet(7, 4242)).toHaveProperty('tags');
    d.close();
  });

  it('memberTagsSet serializes the list', () => {
    const d = new Driver();
    d.memberTagsSet(7, 4242, ['gpu', 'fast']);
    expect(fakeLib._lastMemberTagsSet?.networkId).toBe(7);
    expect(fakeLib._lastMemberTagsSet?.nodeId).toBe(4242);
    expect(JSON.parse(fakeLib._lastMemberTagsSet?.tagsJson ?? '')).toEqual(['gpu', 'fast']);
    d.close();
  });

  it('memberTagsSet handles empty list', () => {
    const d = new Driver();
    d.memberTagsSet(7, 4242, []);
    expect(JSON.parse(fakeLib._lastMemberTagsSet?.tagsJson ?? '')).toEqual([]);
    d.close();
  });

  it('memberTagsSet propagates daemon error', () => {
    fakeLib._jsonReturns['PilotMemberTagsSet'] = jsonErr('not admin');
    const d = new Driver();
    expect(() => d.memberTagsSet(7, 1, ['x'])).toThrow('not admin');
    d.close();
  });
});
