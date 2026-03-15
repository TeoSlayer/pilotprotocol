/**
 * Comprehensive integration test for the Node SDK.
 *
 * Runs against a live daemon connected to the global registry.
 * Tests every SDK method end-to-end.
 *
 * Run:  npx tsx examples/test-comprehensive.ts
 */

import { Driver, Conn, Listener, PilotError } from '../src/index.js';

let passed = 0;
let failed = 0;
const failures: string[] = [];

function test(name: string, fn: () => void): void {
  try {
    fn();
    passed++;
    console.log(`  PASS  ${name}`);
  } catch (e) {
    failed++;
    const msg = e instanceof Error ? e.message : String(e);
    failures.push(`${name}: ${msg}`);
    console.log(`  FAIL  ${name}: ${msg}`);
  }
}

function assert(condition: boolean, msg: string): void {
  if (!condition) throw new Error(msg);
}

function assertEqual(a: unknown, b: unknown, msg: string): void {
  if (a !== b) throw new Error(`${msg}: expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`);
}

// ===================================================================

console.log('==========================================================');
console.log('  Pilot Protocol Node SDK — Comprehensive Integration Test');
console.log('==========================================================');
console.log('');

// ---- 1. Connection lifecycle ----
console.log('--- Connection Lifecycle ---');

test('Driver connects to daemon', () => {
  const d = new Driver();
  assert(d instanceof Driver, 'not a Driver');
  d.close();
});

test('Driver close is idempotent', () => {
  const d = new Driver();
  d.close();
  d.close();
  d.close();
});

test('Driver Symbol.dispose works', () => {
  const d = new Driver();
  d[Symbol.dispose]();
});

test('Driver with custom socket path fails cleanly', () => {
  try {
    new Driver('/nonexistent/socket.sock');
    throw new Error('should have thrown');
  } catch (e) {
    assert(e instanceof PilotError, 'expected PilotError');
    assert(String(e).includes('no such file'), `unexpected error: ${e}`);
  }
});

// ---- 2. Node info ----
console.log('\n--- Node Info ---');

const driver = new Driver();
let nodeAddr = '';
let nodeId = 0;

test('info() returns complete node state', () => {
  const info = driver.info();
  nodeAddr = info['address'] as string;
  nodeId = info['node_id'] as number;

  assert(typeof nodeAddr === 'string', 'address should be string');
  assert(nodeAddr.startsWith('0:'), `address should start with 0: got ${nodeAddr}`);
  assert(typeof nodeId === 'number' && nodeId > 0, `node_id should be positive: ${nodeId}`);
  assert(info['encrypt'] === true, 'encrypt should be true');
  assert(typeof info['public_key'] === 'string', 'should have public_key');
  assert(typeof info['uptime_secs'] === 'number', 'should have uptime_secs');
  assert(typeof info['ports'] === 'number' && (info['ports'] as number) >= 5, 'should have >= 5 ports');
  assert(typeof info['pkts_sent'] === 'number', 'should have pkts_sent');
  assert(typeof info['pkts_recv'] === 'number', 'should have pkts_recv');
  assert(typeof info['bytes_sent'] === 'number', 'should have bytes_sent');
  assert(typeof info['bytes_recv'] === 'number', 'should have bytes_recv');
  assert(Array.isArray(info['conn_list']), 'should have conn_list array');
  assert(Array.isArray(info['peer_list']), 'should have peer_list array');
});

test('info() is consistent across calls', () => {
  const info1 = driver.info();
  const info2 = driver.info();
  assertEqual(info1['node_id'], info2['node_id'], 'node_id should be stable');
  assertEqual(info1['address'], info2['address'], 'address should be stable');
  assertEqual(info1['public_key'], info2['public_key'], 'public_key should be stable');
});

console.log(`  (Node: ${nodeId}, Address: ${nodeAddr})`);

// ---- 3. Hostname ----
console.log('\n--- Hostname ---');

test('setHostname() sets a hostname', () => {
  const result = driver.setHostname('sdk-integration-test');
  assert(result['type'] === 'set_hostname_ok', `expected set_hostname_ok, got ${result['type']}`);
  assertEqual(result['hostname'], 'sdk-integration-test', 'hostname mismatch');
});

test('resolveHostname() resolves our hostname', () => {
  const result = driver.resolveHostname('sdk-integration-test');
  assert(result['node_id'] !== undefined, 'should have node_id in resolve result');
  assertEqual(result['node_id'], nodeId, 'resolved node_id should match ours');
});

test('resolveHostname() fails for non-existent hostname', () => {
  try {
    driver.resolveHostname('definitely-does-not-exist-xyz-12345');
    throw new Error('should have thrown');
  } catch (e) {
    assert(e instanceof PilotError, 'expected PilotError');
  }
});

test('setHostname() clears hostname with empty string', () => {
  const result = driver.setHostname('');
  assert(result['type'] === 'set_hostname_ok', 'expected set_hostname_ok');
});

// ---- 4. Visibility ----
console.log('\n--- Visibility ---');

test('setVisibility(true) makes node public', () => {
  const result = driver.setVisibility(true);
  assert(result['type'] === 'set_visibility_ok', `expected set_visibility_ok, got ${result['type']}`);
  assertEqual(result['visibility'], 'public', 'should be public');
});

test('setVisibility(false) makes node private', () => {
  const result = driver.setVisibility(false);
  assert(result['type'] === 'set_visibility_ok', `expected set_visibility_ok, got ${result['type']}`);
  assertEqual(result['visibility'], 'private', 'should be private');
});

test('setVisibility(true) restore public', () => {
  driver.setVisibility(true);
});

// ---- 5. Tags ----
console.log('\n--- Tags ---');

test('setTags() sets capability tags', () => {
  const result = driver.setTags(['nodejs', 'sdk', 'integration-test']);
  assert(result['type'] === 'set_tags_ok', `expected set_tags_ok, got ${result['type']}`);
  const tags = result['tags'] as string[];
  assert(Array.isArray(tags), 'tags should be array');
  assert(tags.includes('nodejs'), 'should contain "nodejs"');
  assert(tags.includes('sdk'), 'should contain "sdk"');
  assert(tags.includes('integration-test'), 'should contain "integration-test"');
});

test('setTags([]) clears tags', () => {
  const result = driver.setTags([]);
  assert(result['type'] === 'set_tags_ok', 'expected set_tags_ok');
  // Daemon returns null for empty tags, not []
  const tags = result['tags'];
  assert(tags === null || (Array.isArray(tags) && tags.length === 0), 'tags should be null or empty');
});

// ---- 6. Task exec ----
console.log('\n--- Task Exec ---');

test('setTaskExec(true) enables task execution', () => {
  const result = driver.setTaskExec(true);
  assert(result['type'] === 'set_task_exec_ok', `expected set_task_exec_ok, got ${result['type']}`);
});

test('setTaskExec(false) disables task execution', () => {
  const result = driver.setTaskExec(false);
  assert(result['type'] === 'set_task_exec_ok', `expected set_task_exec_ok, got ${result['type']}`);
});

// ---- 7. Webhook ----
console.log('\n--- Webhook ---');

test('setWebhook() sets webhook URL', () => {
  const result = driver.setWebhook('https://example.com/pilot-hook');
  assertEqual(result['webhook'], 'https://example.com/pilot-hook', 'webhook URL mismatch');
});

test('setWebhook("") clears webhook', () => {
  const result = driver.setWebhook('');
  assertEqual(result['webhook'], '', 'webhook should be empty');
});

// ---- 8. Echo service (stream) ----
console.log('\n--- Echo Service (port 7) ---');

test('echo: short string', () => {
  const conn = driver.dial(`${nodeAddr}:7`);
  conn.write('hello');
  const data = conn.read(4096);
  assertEqual(data.toString(), 'hello', 'echo mismatch');
  conn.close();
});

test('echo: empty string', () => {
  const conn = driver.dial(`${nodeAddr}:7`);
  conn.write('');
  // Empty write should still work (0 bytes)
  conn.close();
});

test('echo: binary data', () => {
  const conn = driver.dial(`${nodeAddr}:7`);
  const bin = Buffer.from([0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd]);
  conn.write(bin);
  const data = conn.read(4096);
  assertEqual(data.length, 6, 'binary echo length mismatch');
  assert(data[0] === 0x00, 'byte 0 mismatch');
  assert(data[3] === 0xff, 'byte 3 mismatch');
  assert(data[5] === 0xfd, 'byte 5 mismatch');
  conn.close();
});

test('echo: large payload (64KB)', () => {
  const conn = driver.dial(`${nodeAddr}:7`);
  const payload = Buffer.alloc(65536, 0x42); // 64KB of 'B'
  conn.write(payload);
  let received = Buffer.alloc(0);
  while (received.length < payload.length) {
    const chunk = conn.read(65536);
    if (chunk.length === 0) break;
    received = Buffer.concat([received, chunk]);
  }
  assertEqual(received.length, payload.length, 'large echo length mismatch');
  assert(received[0] === 0x42, 'first byte mismatch');
  assert(received[65535] === 0x42, 'last byte mismatch');
  conn.close();
});

test('echo: multiple writes on same connection', () => {
  const conn = driver.dial(`${nodeAddr}:7`);
  conn.write('one');
  const r1 = conn.read(4096);
  assertEqual(r1.toString(), 'one', 'first echo mismatch');

  conn.write('two');
  const r2 = conn.read(4096);
  assertEqual(r2.toString(), 'two', 'second echo mismatch');

  conn.write('three');
  const r3 = conn.read(4096);
  assertEqual(r3.toString(), 'three', 'third echo mismatch');

  conn.close();
});

test('echo: Conn close is idempotent', () => {
  const conn = driver.dial(`${nodeAddr}:7`);
  conn.write('x');
  conn.close();
  conn.close();
  conn.close();
});

test('echo: read after close throws', () => {
  const conn = driver.dial(`${nodeAddr}:7`);
  conn.close();
  try {
    conn.read();
    throw new Error('should have thrown');
  } catch (e) {
    assert(e instanceof PilotError, 'expected PilotError');
    assert(String(e).includes('closed'), `expected 'closed' in error: ${e}`);
  }
});

test('echo: write after close throws', () => {
  const conn = driver.dial(`${nodeAddr}:7`);
  conn.close();
  try {
    conn.write('x');
    throw new Error('should have thrown');
  } catch (e) {
    assert(e instanceof PilotError, 'expected PilotError');
    assert(String(e).includes('closed'), `expected 'closed' in error: ${e}`);
  }
});

// ---- 9. Custom port listener ----
console.log('\n--- Custom Listener (port 5555) ---');

test('listen + dial + bidirectional data', () => {
  const listener = driver.listen(5555);
  const client = driver.dial(`${nodeAddr}:5555`);
  const server = listener.accept();

  // Client → Server
  client.write('request');
  const req = server.read(4096);
  assertEqual(req.toString(), 'request', 'server should receive request');

  // Server → Client
  server.write('response');
  const resp = client.read(4096);
  assertEqual(resp.toString(), 'response', 'client should receive response');

  client.close();
  server.close();
  listener.close();
});

test('listen + multiple accepts', () => {
  const listener = driver.listen(5556);

  // Connection 1
  const c1 = driver.dial(`${nodeAddr}:5556`);
  const s1 = listener.accept();
  c1.write('conn1');
  assertEqual(s1.read(4096).toString(), 'conn1', 'conn1 mismatch');
  c1.close();
  s1.close();

  // Connection 2
  const c2 = driver.dial(`${nodeAddr}:5556`);
  const s2 = listener.accept();
  c2.write('conn2');
  assertEqual(s2.read(4096).toString(), 'conn2', 'conn2 mismatch');
  c2.close();
  s2.close();

  listener.close();
});

test('listener close is idempotent', () => {
  const listener = driver.listen(5557);
  listener.close();
  listener.close();
  listener.close();
});

test('accept after close throws', () => {
  const listener = driver.listen(5558);
  listener.close();
  try {
    listener.accept();
    throw new Error('should have thrown');
  } catch (e) {
    assert(e instanceof PilotError, 'expected PilotError');
    assert(String(e).includes('closed'), `expected 'closed' in error: ${e}`);
  }
});

// ---- 10. Datagrams ----
console.log('\n--- Datagrams ---');

test('sendTo + recvFrom round-trip', () => {
  const payload = Buffer.from('datagram-test-payload');
  driver.sendTo(`${nodeAddr}:9999`, payload);
  const dg = driver.recvFrom();
  assert(typeof dg['src_addr'] === 'string', 'should have src_addr');
  assert(typeof dg['src_port'] === 'number', 'should have src_port');
  assertEqual(dg['dst_port'], 9999, 'dst_port mismatch');
  // data is base64 encoded
  const decodedData = Buffer.from(dg['data'] as string, 'base64');
  assertEqual(decodedData.toString(), 'datagram-test-payload', 'datagram payload mismatch');
});

test('sendTo with binary data', () => {
  const payload = Buffer.from([0xDE, 0xAD, 0xBE, 0xEF]);
  driver.sendTo(`${nodeAddr}:9998`, payload);
  const dg = driver.recvFrom();
  assertEqual(dg['dst_port'], 9998, 'dst_port mismatch');
  const decoded = Buffer.from(dg['data'] as string, 'base64');
  assertEqual(decoded.length, 4, 'binary datagram length mismatch');
  assert(decoded[0] === 0xDE, 'byte 0 mismatch');
  assert(decoded[3] === 0xEF, 'byte 3 mismatch');
});

// ---- 11. Data exchange service (port 1001) ----
console.log('\n--- Data Exchange (port 1001) ---');

test('sendMessage: text', () => {
  const result = driver.sendMessage(nodeAddr, 'Hello from integration test!');
  assertEqual(result['type'], 'text', 'type should be text');
  assert((result['sent'] as number) > 0, 'should have sent bytes');
  assertEqual(result['target'], nodeAddr, 'target should match');
  assert(typeof result['ack'] === 'string', 'should have ack');
  assert((result['ack'] as string).includes('ACK'), `ack should contain ACK: ${result['ack']}`);
});

test('sendMessage: json', () => {
  const payload = JSON.stringify({ test: true, value: 42 });
  const result = driver.sendMessage(nodeAddr, payload, 'json');
  assertEqual(result['type'], 'json', 'type should be json');
  assert((result['sent'] as number) > 0, 'should have sent bytes');
  assert((result['ack'] as string).includes('ACK JSON'), 'should get JSON ACK');
});

test('sendMessage: binary', () => {
  const payload = Buffer.from([1, 2, 3, 4, 5]);
  const result = driver.sendMessage(nodeAddr, payload, 'binary');
  assertEqual(result['type'], 'binary', 'type should be binary');
  assertEqual(result['sent'], 5, 'should have sent 5 bytes');
});

// ---- 12. sendFile ----
console.log('\n--- sendFile ---');

test('sendFile: sends a real file', () => {
  // Use our own package.json as the test file
  const result = driver.sendFile(nodeAddr, '/Users/calinteodor/Development/web4/sdk/node/package.json');
  assert((result['sent'] as number) > 0, 'should have sent bytes');
  assertEqual(result['filename'], 'package.json', 'filename should be package.json');
  assertEqual(result['target'], nodeAddr, 'target should match');
});

test('sendFile: non-existent file throws PilotError', () => {
  try {
    driver.sendFile(nodeAddr, '/nonexistent/file.txt');
    throw new Error('should have thrown');
  } catch (e) {
    assert(e instanceof PilotError, 'expected PilotError');
    assert(String(e).includes('File not found'), `expected File not found: ${e}`);
  }
});

// ---- 13. Hostname-based targeting ----
console.log('\n--- Hostname-based Targeting ---');

test('sendMessage via hostname', () => {
  driver.setHostname('sdk-test-node');
  const result = driver.sendMessage('sdk-test-node', 'message via hostname');
  assertEqual(result['type'], 'text', 'type should be text');
  assert((result['sent'] as number) > 0, 'should have sent bytes');
  // Clean up
  driver.setHostname('');
});

// ---- 14. Trust operations ----
console.log('\n--- Trust Operations ---');

test('pendingHandshakes returns array', () => {
  const result = driver.pendingHandshakes();
  assert(result['pending'] !== undefined || result['handshakes'] !== undefined, 'should have pending/handshakes field');
});

test('trustedPeers returns array', () => {
  const result = driver.trustedPeers();
  assert(result['peers'] !== undefined || result['trusted'] !== undefined, 'should have peers/trusted field');
});

test('handshake to non-existent node fails gracefully', () => {
  try {
    driver.handshake(999999, 'test justification');
    // may succeed (queued) or fail, both are acceptable
  } catch (e) {
    assert(e instanceof PilotError, 'should be PilotError if it fails');
  }
});

test('revokeTrust on non-trusted node fails gracefully', () => {
  try {
    driver.revokeTrust(999999);
  } catch (e) {
    assert(e instanceof PilotError, 'should be PilotError');
  }
});

// ---- 15. Connection stats ----
console.log('\n--- Connection Stats ---');

test('info shows connection stats', () => {
  const info = driver.info();
  assert(typeof info['pkts_sent'] === 'number', 'should have pkts_sent');
  assert((info['pkts_sent'] as number) > 0, 'should have sent some packets');
  assert(typeof info['bytes_sent'] === 'number', 'should have bytes_sent');
  assert((info['bytes_sent'] as number) > 0, 'should have sent some bytes');
});

// ---- 16. Error class ----
console.log('\n--- PilotError ---');

test('PilotError is instanceof Error', () => {
  const err = new PilotError('test');
  assert(err instanceof Error, 'should be Error');
  assert(err instanceof PilotError, 'should be PilotError');
  assertEqual(err.name, 'PilotError', 'name should be PilotError');
  assertEqual(err.message, 'test', 'message should match');
});

test('PilotError has stack trace', () => {
  const err = new PilotError('test');
  assert(typeof err.stack === 'string', 'should have stack');
  assert(err.stack!.includes('PilotError'), 'stack should contain PilotError');
});

// ---- 17. Stress test ----
console.log('\n--- Stress Test ---');

test('rapid echo: 20 sequential connections', () => {
  for (let i = 0; i < 20; i++) {
    const conn = driver.dial(`${nodeAddr}:7`);
    const msg = `stress-${i}`;
    conn.write(msg);
    const resp = conn.read(4096);
    assertEqual(resp.toString(), msg, `stress echo #${i} mismatch`);
    conn.close();
  }
});

test('large pipeline: 10 writes then 10 reads on echo', () => {
  const conn = driver.dial(`${nodeAddr}:7`);
  const messages = Array.from({ length: 10 }, (_, i) => `msg-${i.toString().padStart(3, '0')}`);

  for (const msg of messages) {
    conn.write(msg);
  }

  let allData = '';
  while (allData.length < messages.join('').length) {
    const chunk = conn.read(4096);
    if (chunk.length === 0) break;
    allData += chunk.toString();
  }

  const expected = messages.join('');
  assertEqual(allData, expected, 'pipeline data mismatch');
  conn.close();
});

// ---- 18. Multiple drivers ----
console.log('\n--- Multiple Drivers ---');

test('two drivers can coexist', () => {
  const d1 = new Driver();
  const d2 = new Driver();
  const i1 = d1.info();
  const i2 = d2.info();
  assertEqual(i1['node_id'], i2['node_id'], 'same daemon, same node_id');
  d1.close();
  d2.close();
});

// ===================================================================
// Cleanup
driver.close();

console.log('');
console.log('==========================================================');
console.log(`  Results: ${passed} passed, ${failed} failed`);
console.log('==========================================================');

if (failures.length > 0) {
  console.log('');
  console.log('Failures:');
  for (const f of failures) {
    console.log(`  - ${f}`);
  }
}

process.exit(failed > 0 ? 1 : 0);
