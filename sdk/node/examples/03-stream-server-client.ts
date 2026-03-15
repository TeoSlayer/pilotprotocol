/**
 * Example 3: Stream server and client
 *
 * Opens a listener on a custom port, then dials it from the same
 * node. Demonstrates bidirectional stream communication.
 *
 * Run:  npx tsx examples/03-stream-server-client.ts
 */

import { Driver } from '../src/index.js';

const driver = new Driver();

try {
  const info = driver.info();
  const addr = info['address'] as string;
  console.log(`Our address: ${addr}`);

  // Start a listener on port 5000
  const listener = driver.listen(5000);
  console.log('Listening on port 5000...');

  // Dial ourselves (client side)
  const client = driver.dial(`${addr}:5000`);

  // Accept the connection (server side)
  const server = listener.accept();
  console.log('Connection accepted!');

  // Client sends a message
  client.write('ping');
  console.log('Client sent: "ping"');

  // Server receives and replies
  const received = server.read(4096);
  console.log(`Server received: "${received.toString()}"`);

  server.write('pong');
  console.log('Server sent: "pong"');

  // Client reads the reply
  const reply = client.read(4096);
  console.log(`Client received: "${reply.toString()}"`);

  // Cleanup
  client.close();
  server.close();
  listener.close();

  console.log('Stream round-trip complete!');
} finally {
  driver.close();
}
