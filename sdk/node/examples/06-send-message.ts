/**
 * Example 6: High-level message sending (data exchange service)
 *
 * Uses the sendMessage() helper to send a structured message
 * through the data exchange service on port 1001.
 *
 * Run:  npx tsx examples/06-send-message.ts
 */

import { Driver } from '../src/index.js';

const driver = new Driver();

try {
  const info = driver.info();
  const addr = info['address'] as string;
  console.log(`Our address: ${addr}`);

  // Send a text message to ourselves
  console.log('\n=== Sending text message ===');
  const result = driver.sendMessage(addr, 'Hello from Node.js SDK!');
  console.log(JSON.stringify(result, null, 2));

  // Send a JSON message
  console.log('\n=== Sending JSON message ===');
  const jsonResult = driver.sendMessage(
    addr,
    JSON.stringify({ action: 'greet', name: 'Pilot' }),
    'json',
  );
  console.log(JSON.stringify(jsonResult, null, 2));
} finally {
  driver.close();
}
