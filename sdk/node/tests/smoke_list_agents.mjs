#!/usr/bin/env node
/**
 * End-to-end smoke test for the Node SDK against a real daemon.
 *
 * Identical contract to the Python smoke script (sdk/python/scripts/
 * smoke_list_agents.py): construct Driver → info → handshake list-agents
 * → send_message('/data {...}') → poll ~/.pilot/inbox/ for the reply.
 *
 * Run with the just-built SDK:
 *   cd sdk/node && npx tsc && node scripts/smoke_list_agents.mjs
 */

import { homedir } from 'node:os';
import { join } from 'node:path';
import { readdirSync, readFileSync, statSync } from 'node:fs';

import { Driver, PilotError } from '../dist/client.js';

const LIST_AGENTS_HOST = 'list-agents';
const LIST_AGENTS_NODE_ID = 16398;
const INBOX_DIR = join(homedir(), '.pilot', 'inbox');
const WAIT_MS = 8_000;

function newestInboxFileSince(afterMtime) {
  let best = null;
  let bestMtime = 0;
  for (const name of readdirSync(INBOX_DIR)) {
    if (!name.endsWith('.json')) continue;
    const p = join(INBOX_DIR, name);
    const st = statSync(p);
    if (st.mtimeMs > afterMtime && st.mtimeMs > bestMtime) {
      best = p;
      bestMtime = st.mtimeMs;
    }
  }
  return best;
}

async function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function main() {
  console.log('[1/5] Constructing Driver…');
  let d;
  try {
    d = new Driver();
  } catch (e) {
    if (e instanceof PilotError) {
      console.log(`  FAIL: cannot reach daemon: ${e.message}`);
      process.exit(2);
    }
    throw e;
  }
  console.log('  OK');

  console.log('[2/5] Calling info()…');
  const info = d.info();
  console.log(
    `  node_id=${info.node_id} addr=${info.address} peers=${info.peers}`,
  );

  console.log(`[3/5] Handshake list-agents (node ${LIST_AGENTS_NODE_ID})…`);
  try {
    const h = d.handshake(LIST_AGENTS_NODE_ID, 'node sdk smoke test');
    console.log(`  OK: ${JSON.stringify(h)}`);
  } catch (e) {
    const msg = String(e?.message ?? e).toLowerCase();
    if (msg.includes('already') || msg.includes('trust')) {
      console.log(`  OK (already trusted): ${e}`);
    } else {
      console.log(`  FAIL: ${e}`);
      process.exit(3);
    }
  }

  console.log('[4/5] sendMessage → list-agents …');
  const tStart = Date.now() / 1000 - 1;
  let result;
  try {
    result = d.sendMessage(
      LIST_AGENTS_HOST,
      '/data {"search":"","limit":1}',
      'text',
    );
  } catch (e) {
    console.log(`  FAIL: sendMessage: ${e}`);
    process.exit(4);
  }
  console.log(`  sent: ${JSON.stringify(result)}`);

  console.log(`[5/5] Waiting up to ${WAIT_MS / 1000}s for inbox reply…`);
  const deadline = Date.now() + WAIT_MS;
  let replyFile = null;
  while (Date.now() < deadline) {
    replyFile = newestInboxFileSince(tStart * 1000);
    if (replyFile) break;
    await sleep(500);
  }
  if (!replyFile) {
    console.log('  FAIL: no inbox reply within window');
    process.exit(5);
  }
  console.log(`  reply file: ${replyFile}`);

  let envelope;
  try {
    envelope = JSON.parse(readFileSync(replyFile, 'utf8'));
  } catch (e) {
    console.log(`  FAIL: cannot parse reply: ${e}`);
    process.exit(6);
  }
  console.log(
    `  agent=${envelope.agent} command=${envelope.command} ok=${envelope.ok}`,
  );

  if (typeof envelope.data === 'string') {
    try {
      const payload = JSON.parse(envelope.data);
      const total =
        payload.total ?? payload.count ?? (payload.tiers?.free?.items?.length ?? null);
      if (total !== null) console.log(`  list-agents total: ${total}`);
    } catch {
      console.log('  (data not JSON; envelope OK)');
    }
  }

  d.close();
  console.log('\nSMOKE TEST PASSED (node)');
  process.exit(0);
}

main().catch((e) => {
  console.error(`unhandled: ${e}`);
  process.exit(99);
});
