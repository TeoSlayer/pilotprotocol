/**
 * Example 2: Echo service
 *
 * Connects to the echo service (port 7) on our own node,
 * sends a message, and reads back the echo.
 *
 * Run:  npx tsx examples/02-echo-service.ts
 */

import { Driver } from '../src/index.js';

const driver = new Driver();

try {
  // Get our own address
  const info = driver.info();
  const addr = info['address'] as string;
  console.log(`Our address: ${addr}`);

  // Dial the echo service on our own node
  const conn = driver.dial(`${addr}:7`);
  try {
    const message = 'Hello from Node SDK!';
    console.log(`Sending: "${message}"`);

    conn.write(message);
    const response = conn.read(4096);
    console.log(`Received: "${response.toString()}"`);

    if (response.toString() === message) {
      console.log('Echo verified!');
    }
  } finally {
    conn.close();
  }
} finally {
  driver.close();
}
