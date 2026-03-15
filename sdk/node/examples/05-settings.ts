/**
 * Example 5: Node settings and visibility
 *
 * Demonstrates setting hostname, visibility, tags, and other
 * node configuration via the SDK.
 *
 * Run:  npx tsx examples/05-settings.ts
 */

import { Driver } from '../src/index.js';

const driver = new Driver();

try {
  // Show initial info
  console.log('=== Initial info ===');
  console.log(JSON.stringify(driver.info(), null, 2));

  // Set hostname
  console.log('\n=== Setting hostname ===');
  const hostResult = driver.setHostname('node-sdk-test');
  console.log(JSON.stringify(hostResult, null, 2));

  // Set visibility to public
  console.log('\n=== Setting visibility (public) ===');
  const visResult = driver.setVisibility(true);
  console.log(JSON.stringify(visResult, null, 2));

  // Set capability tags
  console.log('\n=== Setting tags ===');
  const tagResult = driver.setTags(['nodejs', 'sdk', 'test']);
  console.log(JSON.stringify(tagResult, null, 2));

  // Show updated info
  console.log('\n=== Updated info ===');
  console.log(JSON.stringify(driver.info(), null, 2));

  // Clean up: remove hostname and go private
  driver.setHostname('');
  driver.setVisibility(false);
  driver.setTags([]);
  console.log('\n=== Cleaned up ===');
} finally {
  driver.close();
}
