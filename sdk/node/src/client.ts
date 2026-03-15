/**
 * Pilot Protocol Node.js SDK — koffi wrapper around libpilot shared library.
 *
 * This module provides a TypeScript/JavaScript interface to the Pilot Protocol
 * daemon by calling into the Go driver compiled as a C-shared library
 * (.so/.dylib/.dll). The Go library is the *single source of truth*; this
 * wrapper is a thin FFI boundary that marshals arguments and unmarshals JSON.
 *
 * Usage:
 *
 *   import { Driver } from 'pilotprotocol';
 *
 *   const d = new Driver();          // connects to /tmp/pilot.sock
 *   console.log(d.info());           // returns object
 *   d.close();
 *
 * Or with explicit resource management:
 *
 *   using d = new Driver();
 *   console.log(d.info());
 *   // auto-closed at end of scope
 */

import { existsSync, readFileSync } from 'node:fs';
import { basename } from 'node:path';
import type { PilotLib } from './ffi.js';
import {
  PilotError,
  checkErr,
  loadLibrary,
  parseJSON,
  unwrapHandleErr,
} from './ffi.js';

// Re-export PilotError for public API
export { PilotError } from './ffi.js';

export const DEFAULT_SOCKET_PATH = '/tmp/pilot.sock';

// Module-level singleton for the loaded library
let _lib: PilotLib | null = null;

function getLib(): PilotLib {
  if (!_lib) {
    _lib = loadLibrary();
  }
  return _lib;
}

/** Override the library instance (for testing). */
export function _setLib(lib: PilotLib | null): void {
  _lib = lib;
}

/** Get the current library instance (for testing). */
export function _getLib(): PilotLib | null {
  return _lib;
}

// ---------------------------------------------------------------------------
// Conn — stream connection wrapper
// ---------------------------------------------------------------------------

export class Conn {
  private _h: bigint;
  private _closed = false;

  constructor(handle: bigint) {
    this._h = handle;
  }

  /** Read up to `size` bytes. Blocks until data arrives. */
  read(size = 4096): Buffer {
    if (this._closed) throw new PilotError('connection closed');
    if (size <= 0) return Buffer.alloc(0);
    if (size > 16 * 1024 * 1024) size = 16 * 1024 * 1024; // cap at 16MB
    const lib = getLib();
    const res = lib.PilotConnRead(this._h, size);
    if (res.err) {
      const obj = JSON.parse(res.err);
      throw new PilotError(obj.error ?? 'read error');
    }
    if (res.n === 0 || !res.data) return Buffer.alloc(0);
    return res.data;
  }

  /** Write bytes to the connection. Returns bytes written. */
  write(data: Buffer | Uint8Array | string): number {
    if (this._closed) throw new PilotError('connection closed');
    const lib = getLib();
    // Allocate a dedicated Buffer to avoid shared-pool byteOffset issues
    const src = typeof data === 'string' ? Buffer.from(data) : data;
    const buf = Buffer.allocUnsafe(src.length);
    Buffer.from(src).copy(buf);
    const res = lib.PilotConnWrite(this._h, buf, buf.length);
    if (res.err) {
      const obj = JSON.parse(res.err);
      throw new PilotError(obj.error ?? 'write error');
    }
    return res.n;
  }

  /** Close the connection. Idempotent. */
  close(): void {
    if (this._closed) return;
    this._closed = true;
    const lib = getLib();
    const ptr = lib.PilotConnClose(this._h);
    checkErr(ptr);
  }

  /** Support TC39 explicit resource management. */
  [Symbol.dispose](): void {
    this.close();
  }
}

// ---------------------------------------------------------------------------
// Listener — server socket wrapper
// ---------------------------------------------------------------------------

export class Listener {
  private _h: bigint;
  private _closed = false;

  constructor(handle: bigint) {
    this._h = handle;
  }

  /** Block until a new connection arrives and return it. */
  accept(): Conn {
    if (this._closed) throw new PilotError('listener closed');
    const lib = getLib();
    const res = lib.PilotListenerAccept(this._h);
    const handle = unwrapHandleErr(res);
    return new Conn(handle);
  }

  /** Close the listener. Idempotent. */
  close(): void {
    if (this._closed) return;
    this._closed = true;
    const lib = getLib();
    const ptr = lib.PilotListenerClose(this._h);
    checkErr(ptr);
  }

  /** Support TC39 explicit resource management. */
  [Symbol.dispose](): void {
    this.close();
  }
}

// ---------------------------------------------------------------------------
// Driver — main SDK entry point
// ---------------------------------------------------------------------------

export class Driver {
  private _h: bigint;
  private _closed = false;

  constructor(socketPath: string = DEFAULT_SOCKET_PATH) {
    const lib = getLib();
    const res = lib.PilotConnect(socketPath);
    this._h = unwrapHandleErr(res);
  }

  /** Disconnect from the daemon. Idempotent. */
  close(): void {
    if (this._closed) return;
    this._closed = true;
    const lib = getLib();
    const ptr = lib.PilotClose(this._h);
    checkErr(ptr);
  }

  /** Support TC39 explicit resource management. */
  [Symbol.dispose](): void {
    this.close();
  }

  // -- JSON-RPC helper --

  private _callJSON(fnName: keyof PilotLib, ...args: unknown[]): Record<string, unknown> {
    const lib = getLib();
    const fn = lib[fnName] as (...a: unknown[]) => string | null;
    const str = fn(this._h, ...args);
    return parseJSON(str);
  }

  // -- Info --

  /** Return the daemon's status information. */
  info(): Record<string, unknown> {
    return this._callJSON('PilotInfo');
  }

  // -- Handshake / Trust --

  /** Send a trust handshake request to a remote node. */
  handshake(nodeId: number, justification = ''): Record<string, unknown> {
    return this._callJSON('PilotHandshake', nodeId, justification);
  }

  /** Approve a pending handshake request. */
  approveHandshake(nodeId: number): Record<string, unknown> {
    return this._callJSON('PilotApproveHandshake', nodeId);
  }

  /** Reject a pending handshake request. */
  rejectHandshake(nodeId: number, reason = ''): Record<string, unknown> {
    return this._callJSON('PilotRejectHandshake', nodeId, reason);
  }

  /** Return pending trust handshake requests. */
  pendingHandshakes(): Record<string, unknown> {
    return this._callJSON('PilotPendingHandshakes');
  }

  /** Return all trusted peers. */
  trustedPeers(): Record<string, unknown> {
    return this._callJSON('PilotTrustedPeers');
  }

  /** Remove a peer from the trusted set. */
  revokeTrust(nodeId: number): Record<string, unknown> {
    return this._callJSON('PilotRevokeTrust', nodeId);
  }

  // -- Hostname --

  /** Resolve a hostname to node info. */
  resolveHostname(hostname: string): Record<string, unknown> {
    return this._callJSON('PilotResolveHostname', hostname);
  }

  /** Set or clear the daemon's hostname. */
  setHostname(hostname: string): Record<string, unknown> {
    return this._callJSON('PilotSetHostname', hostname);
  }

  // -- Visibility / capabilities --

  /** Set the daemon's visibility on the registry. */
  setVisibility(isPublic: boolean): Record<string, unknown> {
    return this._callJSON('PilotSetVisibility', isPublic ? 1 : 0);
  }

  /** Enable or disable task execution capability. */
  setTaskExec(enabled: boolean): Record<string, unknown> {
    return this._callJSON('PilotSetTaskExec', enabled ? 1 : 0);
  }

  /** Remove the daemon from the registry. */
  deregister(): Record<string, unknown> {
    return this._callJSON('PilotDeregister');
  }

  /** Set capability tags for this node. */
  setTags(tags: string[]): Record<string, unknown> {
    return this._callJSON('PilotSetTags', JSON.stringify(tags));
  }

  /** Set or clear the webhook URL. */
  setWebhook(url: string): Record<string, unknown> {
    return this._callJSON('PilotSetWebhook', url);
  }

  // -- Connection management --

  /** Close a connection by ID (administrative). */
  disconnect(connId: number): void {
    const lib = getLib();
    const ptr = lib.PilotDisconnect(this._h, connId);
    checkErr(ptr);
  }

  // -- Streams --

  /** Open a stream connection to addr (format: "N:XXXX.YYYY.YYYY:PORT"). */
  dial(addr: string): Conn {
    const lib = getLib();
    const res = lib.PilotDial(this._h, addr);
    const handle = unwrapHandleErr(res);
    return new Conn(handle);
  }

  /** Bind a port and return a Listener that accepts connections. */
  listen(port: number): Listener {
    const lib = getLib();
    const res = lib.PilotListen(this._h, port);
    const handle = unwrapHandleErr(res);
    return new Listener(handle);
  }

  // -- Datagrams --

  /** Send an unreliable datagram. addr = "N:XXXX.YYYY.YYYY:PORT". */
  sendTo(addr: string, data: Buffer | Uint8Array): void {
    const lib = getLib();
    // Allocate a dedicated Buffer to avoid shared-pool byteOffset issues
    const buf = Buffer.allocUnsafe(data.length);
    Buffer.from(data).copy(buf);
    const ptr = lib.PilotSendTo(this._h, addr, buf, buf.length);
    checkErr(ptr);
  }

  /** Receive the next incoming datagram (blocks). */
  recvFrom(): Record<string, unknown> {
    return this._callJSON('PilotRecvFrom');
  }

  // -- High-level service methods --

  /** Resolve a target to a protocol address. Passes through if already an address. */
  private _resolveTarget(target: string): string {
    if (!target.startsWith('0:')) {
      const result = this.resolveHostname(target);
      const addr = result['address'] as string;
      if (!addr) throw new PilotError(`Could not resolve hostname: ${target}`);
      return addr;
    }
    return target;
  }

  /**
   * Send a message via the data exchange service (port 1001).
   *
   * @param target - Hostname or protocol address (N:XXXX.YYYY.YYYY)
   * @param data - Message data
   * @param msgType - Message type: "text", "json", or "binary"
   */
  sendMessage(target: string, data: Buffer | string, msgType: 'text' | 'json' | 'binary' = 'text'): Record<string, unknown> {
    const buf = typeof data === 'string' ? Buffer.from(data) : Buffer.from(data);
    const addr = this._resolveTarget(target);

    // Map type to frame type: 1=text, 2=binary, 3=json, 4=file
    const typeMap: Record<string, number> = { text: 1, binary: 2, json: 3, file: 4 };
    const frameType = typeMap[msgType] ?? 1;

    // Build frame: [4-byte type][4-byte length][payload]
    const header = Buffer.alloc(8);
    header.writeUInt32BE(frameType, 0);
    header.writeUInt32BE(buf.length, 4);
    const frame = Buffer.concat([header, buf]);

    const conn = this.dial(`${addr}:1001`);
    try {
      conn.write(frame);

      try {
        const ackHeader = conn.read(8);
        if (ackHeader && ackHeader.length === 8) {
          const ackLen = ackHeader.readUInt32BE(4);
          const ackPayload = conn.read(ackLen);
          if (ackPayload && ackPayload.length > 0) {
            const ackMsg = ackPayload.toString('utf-8');
            return { sent: buf.length, type: msgType, target: addr, ack: ackMsg };
          }
        }
      } catch {
        // ACK read failed, but message was sent
      }

      return { sent: buf.length, type: msgType, target: addr };
    } finally {
      conn.close();
    }
  }

  /**
   * Send a file via the data exchange service (port 1001).
   *
   * @param target - Hostname or protocol address
   * @param filePath - Path to file to send
   */
  sendFile(target: string, filePath: string): Record<string, unknown> {
    if (!existsSync(filePath)) {
      throw new PilotError(`File not found: ${filePath}`);
    }

    const fileData = readFileSync(filePath);
    const filename = basename(filePath);
    const filenameBytes = Buffer.from(filename, 'utf-8');

    // For TypeFile: payload = [2-byte name len][name][file data]
    const nameHeader = Buffer.alloc(2);
    nameHeader.writeUInt16BE(filenameBytes.length, 0);
    const payload = Buffer.concat([nameHeader, filenameBytes, fileData]);

    // Build frame: [4-byte type=4][4-byte length][payload]
    const header = Buffer.alloc(8);
    header.writeUInt32BE(4, 0);
    header.writeUInt32BE(payload.length, 4);
    const frame = Buffer.concat([header, payload]);

    const addr = this._resolveTarget(target);
    const conn = this.dial(`${addr}:1001`);
    try {
      conn.write(frame);

      try {
        const ackHeader = conn.read(8);
        if (ackHeader && ackHeader.length === 8) {
          const ackLen = ackHeader.readUInt32BE(4);
          const ackPayload = conn.read(ackLen);
          if (ackPayload && ackPayload.length > 0) {
            const ackMsg = ackPayload.toString('utf-8');
            return { sent: fileData.length, filename, target: addr, ack: ackMsg };
          }
        }
      } catch {
        // ACK read failed, but file was sent
      }

      return { sent: fileData.length, filename, target: addr };
    } finally {
      conn.close();
    }
  }

  /**
   * Publish an event via the event stream service (port 1002).
   *
   * Wire format: [2-byte topic len][topic][4-byte payload len][payload]
   * Protocol: first event = subscribe, subsequent events = publish
   *
   * @param target - Hostname or protocol address of event stream server
   * @param topic - Event topic (e.g., "sensor/temperature")
   * @param data - Event payload
   */
  publishEvent(target: string, topic: string, data: Buffer | string): Record<string, unknown> {
    const addr = this._resolveTarget(target);
    const payload = typeof data === 'string' ? Buffer.from(data) : Buffer.from(data);

    const conn = this.dial(`${addr}:1002`);
    try {
      // Subscribe to topic first (empty payload)
      conn.write(buildEventFrame(topic, Buffer.alloc(0)));
      // Now publish the actual event
      conn.write(buildEventFrame(topic, payload));
      return { status: 'published', topic, bytes: payload.length };
    } finally {
      conn.close();
    }
  }

  /**
   * Subscribe to events from the event stream service (port 1002).
   *
   * @param target - Hostname or protocol address
   * @param topic - Topic pattern to subscribe to (use "*" for all)
   * @param callback - Callback function(topic, data) for each event
   * @param timeout - Timeout in seconds (default: 30)
   */
  subscribeEvent(
    target: string,
    topic: string,
    callback: (eventTopic: string, eventData: Buffer) => void,
    timeout = 30,
  ): void {
    const addr = this._resolveTarget(target);
    const conn = this.dial(`${addr}:1002`);
    try {
      // Send subscription (empty payload)
      conn.write(buildEventFrame(topic, Buffer.alloc(0)));

      const deadline = Date.now() + timeout * 1000;
      while (Date.now() < deadline) {
        try {
          const event = readEventFrame(conn);
          if (!event) break;
          callback(event.topic, event.data);
        } catch (e) {
          const msg = String(e);
          if (msg.includes('connection closed') || msg.includes('EOF')) break;
          throw e;
        }
      }
    } finally {
      conn.close();
    }
  }

  /**
   * Submit a task via the task submit service (port 1003).
   *
   * @param target - Hostname or protocol address of task execution server
   * @param taskData - Task specification. Must include 'task_description'.
   */
  submitTask(target: string, taskData: Record<string, unknown>): Record<string, unknown> {
    const addr = this._resolveTarget(target);
    const nodeInfo = this.info();
    const fromAddr = (nodeInfo['address'] as string) ?? 'unknown';

    const submitReq = {
      task_id: taskData['task_id'] ?? crypto.randomUUID(),
      task_description: taskData['task_description'] ?? JSON.stringify(taskData),
      from_addr: fromAddr,
      to_addr: addr,
    };

    const taskJson = Buffer.from(JSON.stringify(submitReq), 'utf-8');

    // Build submit frame: [4-byte type=1][4-byte length][JSON payload]
    const header = Buffer.alloc(8);
    header.writeUInt32BE(1, 0);
    header.writeUInt32BE(taskJson.length, 4);
    const frame = Buffer.concat([header, taskJson]);

    const conn = this.dial(`${addr}:1003`);
    try {
      conn.write(frame);

      // Read response frame: [4-byte type][4-byte length][JSON payload]
      const respHeader = conn.read(8);
      if (!respHeader || respHeader.length < 8) {
        throw new PilotError('No response from task submit service');
      }
      const respLen = respHeader.readUInt32BE(4);
      const respData = conn.read(respLen);
      if (!respData || respData.length < respLen) {
        throw new PilotError('Incomplete response from task submit service');
      }

      return JSON.parse(respData.toString('utf-8'));
    } finally {
      conn.close();
    }
  }
}

// ---------------------------------------------------------------------------
// Event stream helpers
// ---------------------------------------------------------------------------

/** Build an event frame: [2-byte topic len][topic][4-byte payload len][payload]. */
function buildEventFrame(topic: string, payload: Buffer): Buffer {
  const topicBytes = Buffer.from(topic, 'utf-8');
  const header = Buffer.alloc(2 + topicBytes.length + 4);
  header.writeUInt16BE(topicBytes.length, 0);
  topicBytes.copy(header, 2);
  header.writeUInt32BE(payload.length, 2 + topicBytes.length);
  return Buffer.concat([header, payload]);
}

/** Read an event frame from a connection. Returns null on incomplete read. */
function readEventFrame(conn: Conn): { topic: string; data: Buffer } | null {
  const topicLenBuf = conn.read(2);
  if (!topicLenBuf || topicLenBuf.length < 2) return null;
  const topicLen = topicLenBuf.readUInt16BE(0);

  const topicBuf = conn.read(topicLen);
  if (!topicBuf || topicBuf.length < topicLen) return null;
  const topic = topicBuf.toString('utf-8');

  const payloadLenBuf = conn.read(4);
  if (!payloadLenBuf || payloadLenBuf.length < 4) return null;
  const payloadLen = payloadLenBuf.readUInt32BE(0);

  const data = conn.read(payloadLen);
  if (!data || data.length < payloadLen) return null;

  return { topic, data };
}
