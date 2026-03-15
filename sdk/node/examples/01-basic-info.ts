/**
 * Example 1: Basic connection and node info
 *
 * Connects to the local daemon and prints node information.
 *
 * Run:  npx tsx examples/01-basic-info.ts
 */

import { Driver } from '../src/index.js';

const driver = new Driver();

try {
  const info = driver.info();
  console.log('Node info:');
  console.log(JSON.stringify(info, null, 2));
} finally {
  driver.close();
}
