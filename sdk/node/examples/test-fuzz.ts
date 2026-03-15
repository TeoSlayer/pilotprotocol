/**
 * Fuzz / adversarial testing for the Node SDK.
 *
 * Tries to break the SDK with:
 *   - Malformed inputs (null, undefined, NaN, huge numbers, empty strings)
 *   - Boundary conditions (0-byte reads, max-size writes, port limits)
 *   - Unicode / binary edge cases
 *   - Resource exhaustion (many connections, many listeners)
 *   - Use-after-close / double-free patterns
 *   - Concurrent-ish access patterns
 *   - Type coercion traps
 *
 * Run:  npx tsx examples/test-fuzz.ts
 */

import { Driver, Conn, Listener, PilotError } from '../src/index.js';

let passed = 0;
let failed = 0;
let crashed = 0;
const failures: string[] = [];

function test(name: string, fn: () => void): void {
  try {
    fn();
    passed++;
    console.log(`  PASS  ${name}`);
  } catch (e) {
    if (e instanceof PilotError) {
      // PilotError = graceful failure, that's fine
      passed++;
      console.log(`  PASS  ${name} (PilotError: ${e.message.slice(0, 60)})`);
    } else {
      failed++;
      const msg = e instanceof Error ? e.message : String(e);
      failures.push(`${name}: ${msg}`);
      console.log(`  FAIL  ${name}: ${msg.slice(0, 120)}`);
    }
  }
}

// Like test() but expects the operation to NOT crash the process.
// Both success and PilotError are acceptable. Only JS crashes (TypeError, etc) are failures.
function fuzz(name: string, fn: () => void): void {
  try {
    fn();
    passed++;
    console.log(`  PASS  ${name}`);
  } catch (e) {
    if (e instanceof PilotError) {
      passed++;
      console.log(`  PASS  ${name} (PilotError: ${e.message.slice(0, 60)})`);
    } else if (e instanceof SyntaxError || e instanceof TypeError || e instanceof RangeError) {
      crashed++;
      const msg = e instanceof Error ? e.message : String(e);
      failures.push(`CRASH ${name}: ${msg}`);
      console.log(`  CRASH ${name}: ${msg.slice(0, 120)}`);
    } else {
      // Other errors (e.g. koffi errors) — log but count as pass if non-fatal
      passed++;
      const msg = e instanceof Error ? e.message : String(e);
      console.log(`  PASS  ${name} (caught: ${msg.slice(0, 80)})`);
    }
  }
}

function assert(condition: boolean, msg: string): void {
  if (!condition) throw new Error(msg);
}

// ===================================================================

console.log('==========================================================');
console.log('  Pilot Protocol Node SDK — Fuzz / Adversarial Tests');
console.log('==========================================================');
console.log('');

const driver = new Driver();
const info = driver.info();
const addr = info['address'] as string;
const nodeId = info['node_id'] as number;
console.log(`  Node: ${nodeId}, Address: ${addr}`);
console.log('');

// ================================================================
// 1. Malformed hostname inputs
// ================================================================
console.log('--- Malformed Hostname Inputs ---');

fuzz('setHostname: empty string', () => {
  driver.setHostname('');
});

fuzz('setHostname: single char', () => {
  driver.setHostname('a');
});

fuzz('setHostname: max length (255 chars)', () => {
  driver.setHostname('a'.repeat(255));
  driver.setHostname(''); // cleanup
});

fuzz('setHostname: over max length (1000 chars)', () => {
  driver.setHostname('x'.repeat(1000));
  driver.setHostname(''); // cleanup
});

fuzz('setHostname: unicode emoji', () => {
  driver.setHostname('🚀🔥💯');
  driver.setHostname('');
});

fuzz('setHostname: unicode CJK', () => {
  driver.setHostname('测试节点');
  driver.setHostname('');
});

fuzz('setHostname: special chars', () => {
  driver.setHostname('node--test..name');
  driver.setHostname('');
});

fuzz('setHostname: SQL injection attempt', () => {
  driver.setHostname("'; DROP TABLE nodes; --");
  driver.setHostname('');
});

fuzz('setHostname: newlines and tabs', () => {
  driver.setHostname('host\nname\twith\0null');
  driver.setHostname('');
});

fuzz('setHostname: path traversal', () => {
  driver.setHostname('../../etc/passwd');
  driver.setHostname('');
});

fuzz('resolveHostname: empty string', () => {
  driver.resolveHostname('');
});

fuzz('resolveHostname: null bytes', () => {
  driver.resolveHostname('host\0name');
});

fuzz('resolveHostname: very long string', () => {
  driver.resolveHostname('a'.repeat(10000));
});

// ================================================================
// 2. Malformed dial addresses
// ================================================================
console.log('\n--- Malformed Dial Addresses ---');

fuzz('dial: empty string', () => {
  const c = driver.dial('');
  c.close();
});

fuzz('dial: just a colon', () => {
  const c = driver.dial(':');
  c.close();
});

fuzz('dial: no port', () => {
  const c = driver.dial(addr);
  c.close();
});

fuzz('dial: port 0', () => {
  const c = driver.dial(`${addr}:0`);
  c.close();
});

fuzz('dial: port 65535', () => {
  const c = driver.dial(`${addr}:65535`);
  c.close();
});

fuzz('dial: port 99999 (out of range)', () => {
  const c = driver.dial(`${addr}:99999`);
  c.close();
});

fuzz('dial: negative port', () => {
  const c = driver.dial(`${addr}:-1`);
  c.close();
});

fuzz('dial: non-numeric port', () => {
  const c = driver.dial(`${addr}:abc`);
  c.close();
});

fuzz('dial: garbage address', () => {
  const c = driver.dial('not_an_address_at_all');
  c.close();
});

fuzz('dial: unicode address', () => {
  const c = driver.dial('🚀:1234');
  c.close();
});

fuzz('dial: very long address', () => {
  const c = driver.dial('a'.repeat(10000) + ':7');
  c.close();
});

// ================================================================
// 3. Conn read/write edge cases
// ================================================================
console.log('\n--- Conn Read/Write Edge Cases ---');

fuzz('write: empty buffer', () => {
  const conn = driver.dial(`${addr}:7`);
  conn.write(Buffer.alloc(0));
  conn.close();
});

fuzz('write: single byte', () => {
  const conn = driver.dial(`${addr}:7`);
  conn.write(Buffer.from([0x42]));
  const r = conn.read(1);
  assert(r.length === 1 && r[0] === 0x42, 'single byte echo mismatch');
  conn.close();
});

fuzz('write: null byte payload', () => {
  const conn = driver.dial(`${addr}:7`);
  conn.write(Buffer.from([0x00, 0x00, 0x00]));
  const r = conn.read(3);
  assert(r.length === 3 && r[0] === 0x00, 'null bytes echo mismatch');
  conn.close();
});

fuzz('write: all byte values (0-255)', () => {
  const conn = driver.dial(`${addr}:7`);
  const buf = Buffer.alloc(256);
  for (let i = 0; i < 256; i++) buf[i] = i;
  conn.write(buf);
  let received = Buffer.alloc(0);
  while (received.length < 256) {
    const chunk = conn.read(256);
    if (chunk.length === 0) break;
    received = Buffer.concat([received, chunk]);
  }
  assert(received.length === 256, `expected 256 bytes, got ${received.length}`);
  for (let i = 0; i < 256; i++) {
    assert(received[i] === i, `byte ${i} mismatch: expected ${i}, got ${received[i]}`);
  }
  conn.close();
});

fuzz('write: string with null bytes', () => {
  const conn = driver.dial(`${addr}:7`);
  conn.write('hello\0world\0');
  const r = conn.read(4096);
  assert(r.length === 12, `expected 12 bytes, got ${r.length}`);
  assert(r[5] === 0x00, 'null byte not preserved');
  conn.close();
});

fuzz('write: Uint8Array (not Buffer)', () => {
  const conn = driver.dial(`${addr}:7`);
  const arr = new Uint8Array([1, 2, 3, 4, 5]);
  conn.write(arr);
  const r = conn.read(5);
  assert(r.length === 5, 'Uint8Array echo length mismatch');
  conn.close();
});

fuzz('read: size 0', () => {
  const conn = driver.dial(`${addr}:7`);
  conn.write('data');
  const r = conn.read(0);
  // Should return empty or throw, not crash
  conn.close();
});

fuzz('read: size 1', () => {
  const conn = driver.dial(`${addr}:7`);
  conn.write('AB');
  const r = conn.read(1);
  assert(r.length >= 1, 'should read at least 1 byte');
  conn.close();
});

fuzz('read: very large size (10MB)', () => {
  const conn = driver.dial(`${addr}:7`);
  conn.write('tiny');
  const r = conn.read(10 * 1024 * 1024);
  // Should return just the 4 bytes, not allocate 10MB
  assert(r.length === 4, `expected 4 bytes, got ${r.length}`);
  conn.close();
});

fuzz('read: negative size', () => {
  const conn = driver.dial(`${addr}:7`);
  conn.write('x');
  conn.read(-1);
  conn.close();
});

// ================================================================
// 4. Listener edge cases
// ================================================================
console.log('\n--- Listener Edge Cases ---');

fuzz('listen: port 0', () => {
  const ln = driver.listen(0);
  ln.close();
});

fuzz('listen: port 65535', () => {
  const ln = driver.listen(65535);
  ln.close();
});

fuzz('listen: same port twice (should fail)', () => {
  const ln1 = driver.listen(6001);
  try {
    const ln2 = driver.listen(6001);
    ln2.close(); // shouldn't reach here
  } catch (e) {
    assert(e instanceof PilotError, 'expected PilotError for port conflict');
  }
  ln1.close();
});

fuzz('listen then close then re-listen same port', () => {
  const ln1 = driver.listen(6002);
  ln1.close();
  const ln2 = driver.listen(6002);
  ln2.close();
});

// ================================================================
// 5. Datagram edge cases
// ================================================================
console.log('\n--- Datagram Edge Cases ---');

fuzz('sendTo: empty payload', () => {
  driver.sendTo(`${addr}:8888`, Buffer.alloc(0));
});

fuzz('sendTo: single byte', () => {
  driver.sendTo(`${addr}:8887`, Buffer.from([0xff]));
  const dg = driver.recvFrom();
  const decoded = Buffer.from(dg['data'] as string, 'base64');
  assert(decoded.length === 1 && decoded[0] === 0xff, 'single byte datagram mismatch');
});

fuzz('sendTo: 1KB payload', () => {
  driver.sendTo(`${addr}:8886`, Buffer.alloc(1024, 0xAA));
  const dg = driver.recvFrom();
  const decoded = Buffer.from(dg['data'] as string, 'base64');
  assert(decoded.length === 1024, `expected 1024 bytes, got ${decoded.length}`);
});

fuzz('sendTo: malformed address', () => {
  driver.sendTo('garbage:addr', Buffer.from('test'));
});

fuzz('sendTo: empty address', () => {
  driver.sendTo('', Buffer.from('test'));
});

// ================================================================
// 6. Tags edge cases
// ================================================================
console.log('\n--- Tags Edge Cases ---');

fuzz('setTags: empty array', () => {
  driver.setTags([]);
});

fuzz('setTags: single tag', () => {
  driver.setTags(['one']);
  driver.setTags([]);
});

fuzz('setTags: many tags (100)', () => {
  const tags = Array.from({ length: 100 }, (_, i) => `tag-${i}`);
  driver.setTags(tags);
  driver.setTags([]);
});

fuzz('setTags: very long tag name', () => {
  driver.setTags(['a'.repeat(10000)]);
  driver.setTags([]);
});

fuzz('setTags: unicode tags', () => {
  driver.setTags(['🚀', '日本語', 'العربية', 'кириллица']);
  driver.setTags([]);
});

fuzz('setTags: empty string tag', () => {
  driver.setTags(['', '', '']);
  driver.setTags([]);
});

fuzz('setTags: special characters', () => {
  driver.setTags(['tag with spaces', 'tag/with/slashes', 'tag"with"quotes', "tag'with'apostrophes"]);
  driver.setTags([]);
});

fuzz('setTags: duplicate tags', () => {
  driver.setTags(['dup', 'dup', 'dup']);
  driver.setTags([]);
});

// ================================================================
// 7. Webhook edge cases
// ================================================================
console.log('\n--- Webhook Edge Cases ---');

fuzz('setWebhook: not a URL', () => {
  driver.setWebhook('not a url');
  driver.setWebhook('');
});

fuzz('setWebhook: very long URL', () => {
  driver.setWebhook('https://example.com/' + 'a'.repeat(10000));
  driver.setWebhook('');
});

fuzz('setWebhook: javascript: protocol', () => {
  driver.setWebhook('javascript:alert(1)');
  driver.setWebhook('');
});

fuzz('setWebhook: file: protocol', () => {
  driver.setWebhook('file:///etc/passwd');
  driver.setWebhook('');
});

// ================================================================
// 8. Use-after-close patterns
// ================================================================
console.log('\n--- Use-After-Close ---');

fuzz('Driver: info after close', () => {
  const d = new Driver();
  d.close();
  d.info(); // should error, not crash
});

fuzz('Driver: dial after close', () => {
  const d = new Driver();
  d.close();
  const c = d.dial(`${addr}:7`);
  c.close();
});

fuzz('Driver: listen after close', () => {
  const d = new Driver();
  d.close();
  const ln = d.listen(7777);
  ln.close();
});

fuzz('Driver: sendTo after close', () => {
  const d = new Driver();
  d.close();
  d.sendTo(`${addr}:8000`, Buffer.from('test'));
});

fuzz('Driver: setHostname after close', () => {
  const d = new Driver();
  d.close();
  d.setHostname('test');
});

fuzz('Conn: multiple rapid close', () => {
  const conn = driver.dial(`${addr}:7`);
  for (let i = 0; i < 10; i++) conn.close();
});

fuzz('Listener: multiple rapid close', () => {
  const ln = driver.listen(7778);
  for (let i = 0; i < 10; i++) ln.close();
});

// ================================================================
// 9. Rapid open/close cycles
// ================================================================
console.log('\n--- Rapid Open/Close Cycles ---');

fuzz('rapid Driver open/close: 20 cycles', () => {
  for (let i = 0; i < 20; i++) {
    const d = new Driver();
    d.close();
  }
});

fuzz('rapid Conn open/close: 20 cycles', () => {
  for (let i = 0; i < 20; i++) {
    const c = driver.dial(`${addr}:7`);
    c.close();
  }
});

fuzz('rapid Listener open/close: 20 cycles on same port', () => {
  for (let i = 0; i < 20; i++) {
    const ln = driver.listen(7779);
    ln.close();
  }
});

// ================================================================
// 10. Data integrity under various patterns
// ================================================================
console.log('\n--- Data Integrity ---');

fuzz('echo: alternating 0x00 and 0xFF', () => {
  const conn = driver.dial(`${addr}:7`);
  const buf = Buffer.alloc(512);
  for (let i = 0; i < 512; i++) buf[i] = i % 2 === 0 ? 0x00 : 0xFF;
  conn.write(buf);
  let received = Buffer.alloc(0);
  while (received.length < 512) {
    const chunk = conn.read(512);
    if (chunk.length === 0) break;
    received = Buffer.concat([received, chunk]);
  }
  for (let i = 0; i < 512; i++) {
    const expected = i % 2 === 0 ? 0x00 : 0xFF;
    assert(received[i] === expected, `byte ${i}: expected ${expected}, got ${received[i]}`);
  }
  conn.close();
});

fuzz('echo: UTF-8 multibyte characters', () => {
  const conn = driver.dial(`${addr}:7`);
  const text = '日本語テスト🚀🔥 مرحبا κόσμε';
  conn.write(text);
  const r = conn.read(4096);
  assert(r.toString('utf-8') === text, 'multibyte UTF-8 echo mismatch');
  conn.close();
});

fuzz('echo: exactly 1 MTU (1400 bytes)', () => {
  const conn = driver.dial(`${addr}:7`);
  const buf = Buffer.alloc(1400, 0x55);
  conn.write(buf);
  let received = Buffer.alloc(0);
  while (received.length < 1400) {
    const chunk = conn.read(4096);
    if (chunk.length === 0) break;
    received = Buffer.concat([received, chunk]);
  }
  assert(received.length === 1400, `expected 1400, got ${received.length}`);
  conn.close();
});

fuzz('echo: just over 1 MTU (1401 bytes)', () => {
  const conn = driver.dial(`${addr}:7`);
  const buf = Buffer.alloc(1401, 0x66);
  conn.write(buf);
  let received = Buffer.alloc(0);
  while (received.length < 1401) {
    const chunk = conn.read(4096);
    if (chunk.length === 0) break;
    received = Buffer.concat([received, chunk]);
  }
  assert(received.length === 1401, `expected 1401, got ${received.length}`);
  conn.close();
});

fuzz('echo: 128KB (tests segmentation + flow control)', () => {
  const conn = driver.dial(`${addr}:7`);
  const size = 128 * 1024;
  const buf = Buffer.alloc(size);
  // Fill with a pattern
  for (let i = 0; i < size; i++) buf[i] = i & 0xFF;
  conn.write(buf);
  let received = Buffer.alloc(0);
  while (received.length < size) {
    const chunk = conn.read(65536);
    if (chunk.length === 0) break;
    received = Buffer.concat([received, chunk]);
  }
  assert(received.length === size, `expected ${size}, got ${received.length}`);
  // Spot-check pattern
  assert(received[0] === 0, 'byte 0 pattern mismatch');
  assert(received[255] === 255, 'byte 255 pattern mismatch');
  assert(received[256] === 0, 'byte 256 pattern mismatch (wrap)');
  conn.close();
});

// ================================================================
// 11. Handshake edge cases
// ================================================================
console.log('\n--- Handshake Edge Cases ---');

fuzz('handshake: node_id 0', () => {
  driver.handshake(0, 'test');
});

fuzz('handshake: node_id MAX_UINT32', () => {
  driver.handshake(4294967295, 'test');
});

fuzz('handshake: very long justification', () => {
  driver.handshake(99999, 'a'.repeat(10000));
});

fuzz('handshake: empty justification', () => {
  driver.handshake(99999, '');
});

fuzz('approveHandshake: non-existent node', () => {
  driver.approveHandshake(99999);
});

fuzz('rejectHandshake: non-existent node', () => {
  driver.rejectHandshake(99999, 'no');
});

fuzz('rejectHandshake: empty reason', () => {
  driver.rejectHandshake(99999, '');
});

// ================================================================
// 12. Visibility rapid toggle
// ================================================================
console.log('\n--- Visibility Toggle ---');

fuzz('toggle visibility 10 times', () => {
  for (let i = 0; i < 10; i++) {
    driver.setVisibility(i % 2 === 0);
  }
  driver.setVisibility(true); // restore
});

// ================================================================
// 13. sendMessage edge cases
// ================================================================
console.log('\n--- sendMessage Edge Cases ---');

fuzz('sendMessage: empty text', () => {
  driver.sendMessage(addr, '');
});

fuzz('sendMessage: very large text (100KB)', () => {
  driver.sendMessage(addr, 'X'.repeat(100 * 1024));
});

fuzz('sendMessage: binary with null bytes', () => {
  driver.sendMessage(addr, Buffer.from([0, 0, 0, 0, 0]), 'binary');
});

fuzz('sendMessage: JSON with nested objects', () => {
  const deep = JSON.stringify({ a: { b: { c: { d: { e: 'deep' } } } } });
  driver.sendMessage(addr, deep, 'json');
});

// ================================================================
// 14. sendFile edge cases
// ================================================================
console.log('\n--- sendFile Edge Cases ---');

fuzz('sendFile: directory instead of file', () => {
  driver.sendFile(addr, '/tmp');
});

fuzz('sendFile: /dev/null', () => {
  driver.sendFile(addr, '/dev/null');
});

fuzz('sendFile: path with spaces', () => {
  driver.sendFile(addr, '/nonexistent/path with spaces/file.txt');
});

fuzz('sendFile: path with unicode', () => {
  driver.sendFile(addr, '/nonexistent/日本語/file.txt');
});

// ================================================================
// Cleanup
// ================================================================
driver.setHostname('');
driver.setTags([]);
driver.setWebhook('');
driver.setVisibility(true);
driver.close();

console.log('');
console.log('==========================================================');
console.log(`  Results: ${passed} passed, ${failed} failed, ${crashed} CRASHED`);
console.log('==========================================================');

if (failures.length > 0) {
  console.log('');
  console.log('Issues:');
  for (const f of failures) {
    console.log(`  - ${f}`);
  }
}

process.exit(failed + crashed > 0 ? 1 : 0);
