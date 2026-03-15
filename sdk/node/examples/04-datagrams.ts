/**
 * Example 4: Datagrams (unreliable messages)
 *
 * Sends a datagram to our own node and receives it.
 * Datagrams are fire-and-forget — no connection needed.
 *
 * Run:  npx tsx examples/04-datagrams.ts
 */

import { Driver } from '../src/index.js';

const driver = new Driver();

try {
  const info = driver.info();
  const addr = info['address'] as string;
  console.log(`Our address: ${addr}`);

  // Send a datagram to ourselves on port 9090
  const message = Buffer.from('Hello via datagram!');
  driver.sendTo(`${addr}:9090`, message);
  console.log(`Sent datagram: "${message.toString()}" (${message.length} bytes)`);

  // Receive it
  const dg = driver.recvFrom();
  console.log('Received datagram:');
  console.log(JSON.stringify(dg, null, 2));
} finally {
  driver.close();
}
