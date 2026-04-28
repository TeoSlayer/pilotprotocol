#!/usr/bin/env node
// ga-daily.mjs - terminal digest of GA4 traffic for pilotprotocol.network.
//
// Auth:     service-account key at ~/.config/gcp-keys/ga-reader-key.json
// Property: 530680522 (pilotprotocol.network)
// Docs:     ../ANALYTICS.md (taxonomy this report consumes)
//
// Usage:    node web/scripts/ga-daily.mjs [--days N] [--json] [--source S] [--funnel install]
//             --days 1|7|28|...   default 7
//             --json              raw JSON for piping into jq / dashboards
//             --source S          filter cohort to traffic source S (e.g. google, trendshift.io)
//             --funnel install    print install funnel: home view → cta_click(install)
//                                 → /docs/getting-started view → install_command_copy
//
// First-run note: the per-event params (`target`, `location`, `value`) are
// only queryable once they're registered as Custom Definitions in GA4
// Admin → Custom Definitions. Until then, those panes will print "(custom
// dimensions not registered yet)". Register at:
//   https://analytics.google.com/  →  Admin  →  Custom definitions  →  Create
//   Type: Event-scoped, Parameter: target / location / value

import { readFileSync, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { createSign } from 'node:crypto';
import { resolve } from 'node:path';
import process from 'node:process';

const argv = process.argv.slice(2);
function flagValue(name, fallback) {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : fallback;
}
const DAYS = Math.max(1, Number(flagValue('--days', 7)) || 7);
const JSON_OUT = argv.includes('--json');
const SOURCE = flagValue('--source', null); // e.g. "google", "trendshift.io"
const FUNNEL = flagValue('--funnel', null);  // currently only "install" supported

const KEY_PATH = resolve(homedir(), '.config/gcp-keys/ga-reader-key.json');
const PROPERTY_ID = '530680522';
const SCOPE = 'https://www.googleapis.com/auth/analytics.readonly';

function loadKey() {
  if (!existsSync(KEY_PATH)) {
    console.error(`Service-account key not found at ${KEY_PATH}`);
    console.error('See ANALYTICS.md → "Read access for dashboards".');
    process.exit(1);
  }
  return JSON.parse(readFileSync(KEY_PATH, 'utf8'));
}

function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

async function getAccessToken(key) {
  const now = Math.floor(Date.now() / 1000);
  const header = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claim = b64url(JSON.stringify({
    iss: key.client_email,
    scope: SCOPE,
    aud: 'https://oauth2.googleapis.com/token',
    exp: now + 3600,
    iat: now,
  }));
  const sig = b64url(createSign('RSA-SHA256').update(`${header}.${claim}`).sign(key.private_key));
  const jwt = `${header}.${claim}.${sig}`;
  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt,
    }),
  });
  if (!res.ok) throw new Error(`token exchange failed: ${res.status} ${await res.text()}`);
  const j = await res.json();
  return j.access_token;
}

async function runReport(token, body) {
  const res = await fetch(
    `https://analyticsdata.googleapis.com/v1beta/properties/${PROPERTY_ID}:runReport`,
    {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    },
  );
  if (!res.ok) {
    const text = await res.text();
    // Custom dim missing → mark this report as "not registered"
    if (
      res.status === 400 &&
      /(Field [^"]+ not found|not a valid dimension|is not registered)/i.test(text)
    ) {
      return { __unregistered: true, error: text };
    }
    throw new Error(`runReport failed: ${res.status} ${text}`);
  }
  return await res.json();
}

const dateRange = { startDate: `${DAYS}daysAgo`, endDate: 'today' };

const REPORTS = {
  totals: {
    dateRanges: [dateRange],
    metrics: [
      { name: 'sessions' },
      { name: 'totalUsers' },
      { name: 'screenPageViews' },
      { name: 'engagementRate' },
      { name: 'averageSessionDuration' },
    ],
  },
  topPages: {
    dateRanges: [dateRange],
    dimensions: [{ name: 'pagePath' }],
    metrics: [{ name: 'screenPageViews' }, { name: 'sessions' }],
    orderBys: [{ metric: { metricName: 'screenPageViews' }, desc: true }],
    limit: 10,
  },
  topEvents: {
    dateRanges: [dateRange],
    dimensions: [{ name: 'eventName' }],
    metrics: [{ name: 'eventCount' }],
    orderBys: [{ metric: { metricName: 'eventCount' }, desc: true }],
    limit: 20,
  },
  topReferrers: {
    dateRanges: [dateRange],
    dimensions: [{ name: 'sessionSource' }],
    metrics: [{ name: 'sessions' }],
    orderBys: [{ metric: { metricName: 'sessions' }, desc: true }],
    limit: 10,
  },
  ctaTargets: {
    dateRanges: [dateRange],
    dimensions: [
      { name: 'customEvent:target' },
      { name: 'customEvent:location' },
    ],
    metrics: [{ name: 'eventCount' }],
    dimensionFilter: {
      filter: { fieldName: 'eventName', stringFilter: { matchType: 'EXACT', value: 'cta_click' } },
    },
    orderBys: [{ metric: { metricName: 'eventCount' }, desc: true }],
    limit: 20,
  },
  outboundDestinations: {
    dateRanges: [dateRange],
    dimensions: [{ name: 'customEvent:target' }],
    metrics: [{ name: 'eventCount' }],
    dimensionFilter: {
      filter: { fieldName: 'eventName', stringFilter: { matchType: 'EXACT', value: 'outbound_click' } },
    },
    orderBys: [{ metric: { metricName: 'eventCount' }, desc: true }],
    limit: 15,
  },
  scrollDepth: {
    dateRanges: [dateRange],
    dimensions: [{ name: 'customEvent:value' }],
    metrics: [{ name: 'eventCount' }],
    dimensionFilter: {
      filter: { fieldName: 'eventName', stringFilter: { matchType: 'EXACT', value: 'scroll_depth' } },
    },
  },
  sectionViews: {
    dateRanges: [dateRange],
    dimensions: [{ name: 'customEvent:target' }],
    metrics: [{ name: 'eventCount' }],
    dimensionFilter: {
      filter: { fieldName: 'eventName', stringFilter: { matchType: 'EXACT', value: 'section_view' } },
    },
    orderBys: [{ metric: { metricName: 'eventCount' }, desc: true }],
    limit: 10,
  },
};

function row(r) { return { dims: (r.dimensionValues || []).map((v) => v.value), mets: (r.metricValues || []).map((v) => v.value) }; }
function rows(report) { return report?.__unregistered ? null : (report?.rows || []).map(row); }
function pad(s, n) { return String(s).padEnd(n); }
function num(s) { return Number(s || 0).toLocaleString('en-US'); }
function withSource(report, source) {
  if (!source) return report;
  const expr = { filter: { fieldName: 'sessionSource', stringFilter: { matchType: 'EXACT', value: source } } };
  if (report.dimensionFilter) {
    return { ...report, dimensionFilter: { andGroup: { expressions: [report.dimensionFilter, expr] } } };
  }
  return { ...report, dimensionFilter: expr };
}
function bar(v, max, w = 20) {
  if (max <= 0) return '·'.repeat(w);
  const filled = Math.round((v / max) * w);
  return '▇'.repeat(filled) + '·'.repeat(w - filled);
}

// ---- Funnel mode -------------------------------------------------------
// Approximate funnel: counts SESSIONS that hit each step. Sessions metric
// stitches across pages within the same visit, so this is meaningful even
// without runFunnelReport. Conversion = (step N sessions / step 1 sessions).

const FUNNELS = {
  install: [
    {
      label: 'Home page view',
      filter: { filter: { fieldName: 'pagePath', stringFilter: { matchType: 'EXACT', value: '/' } } },
    },
    {
      label: 'cta_click target=install',
      filter: {
        andGroup: {
          expressions: [
            { filter: { fieldName: 'eventName', stringFilter: { matchType: 'EXACT', value: 'cta_click' } } },
            { filter: { fieldName: 'customEvent:target', stringFilter: { matchType: 'EXACT', value: 'install' } } },
          ],
        },
      },
    },
    {
      label: 'Visit /docs/getting-started',
      filter: { filter: { fieldName: 'pagePath', stringFilter: { matchType: 'BEGINS_WITH', value: '/docs/getting-started' } } },
    },
    {
      label: 'install_command_copy',
      filter: { filter: { fieldName: 'eventName', stringFilter: { matchType: 'EXACT', value: 'install_command_copy' } } },
    },
  ],
};

async function runFunnel(token, name, source) {
  const steps = FUNNELS[name];
  if (!steps) {
    console.error(`Unknown funnel "${name}". Supported: ${Object.keys(FUNNELS).join(', ')}`);
    process.exit(1);
  }
  const results = [];
  for (const step of steps) {
    const body = withSource({
      dateRanges: [dateRange],
      metrics: [{ name: 'sessions' }],
      dimensionFilter: step.filter,
    }, source);
    let n;
    let unreg = false;
    try {
      const r = await runReport(token, body);
      if (r.__unregistered) {
        unreg = true;
      } else {
        n = Number(r.rows?.[0]?.metricValues?.[0]?.value || 0);
      }
    } catch (e) {
      console.error(`step "${step.label}" failed: ${e.message}`);
      n = 0;
    }
    results.push({ label: step.label, sessions: n, unreg });
  }
  const last = `last ${DAYS} day${DAYS === 1 ? '' : 's'}`;
  const srcLabel = source ? ` · source=${source}` : '';
  console.log(`\nFunnel: ${name} · ${last}${srcLabel}\n`);
  const top = results.find((r) => !r.unreg && r.sessions !== undefined)?.sessions || 0;
  let prev = top;
  for (let i = 0; i < results.length; i++) {
    const r = results[i];
    if (r.unreg) {
      console.log(`  ${i + 1}. ${pad(r.label, 36)} (custom dim not registered)`);
      continue;
    }
    const pctOfPrev = i === 0 || prev === 0 ? 100 : (r.sessions / prev) * 100;
    const pctOfTop = top === 0 ? 0 : (r.sessions / top) * 100;
    const conv = i === 0 ? '' : `→ ${pctOfPrev.toFixed(1)}% of prev · ${pctOfTop.toFixed(1)}% of top`;
    console.log(`  ${i + 1}. ${pad(r.label, 36)} ${pad(num(r.sessions), 8)} ${conv}`);
    prev = r.sessions;
  }
  console.log();
  const anyUnreg = results.some((r) => r.unreg);
  if (anyUnreg) {
    console.log('Some steps need custom dim "target" registered in GA4 Admin.');
    console.log();
  }
}

const key = loadKey();
const token = await getAccessToken(key);

if (FUNNEL) {
  await runFunnel(token, FUNNEL, SOURCE);
  process.exit(0);
}

const reports = {};
for (const [name, body] of Object.entries(REPORTS)) {
  try {
    reports[name] = await runReport(token, withSource(body, SOURCE));
  } catch (e) {
    reports[name] = { __error: String(e.message || e) };
  }
}

if (JSON_OUT) {
  console.log(JSON.stringify({ days: DAYS, property: PROPERTY_ID, source: SOURCE, reports }, null, 2));
  process.exit(0);
}

const last = `last ${DAYS} day${DAYS === 1 ? '' : 's'}`;
const sourceLabel = SOURCE ? ` · source=${SOURCE}` : '';
console.log(`\nPilot Protocol website · ${last}${sourceLabel}`);
console.log(`property ${PROPERTY_ID}\n`);

// Totals
const totals = rows(reports.totals)?.[0];
if (totals) {
  const [sessions, users, pv, eng, dur] = totals.mets;
  console.log('Totals');
  console.log(`  sessions:        ${num(sessions)}`);
  console.log(`  users:           ${num(users)}`);
  console.log(`  page views:      ${num(pv)}`);
  console.log(`  engagement rate: ${(Number(eng) * 100).toFixed(1)}%`);
  console.log(`  avg session:     ${Number(dur).toFixed(0)}s`);
  console.log();
}

console.log('Top pages');
for (const r of rows(reports.topPages) || []) {
  const [path] = r.dims;
  const [pv, sessions] = r.mets;
  console.log(`  ${pad(num(pv), 8)} ${pad(path, 50)} ${num(sessions)} sess`);
}
console.log();

console.log('Top events');
const evRows = rows(reports.topEvents) || [];
const evMax = Math.max(...evRows.map((r) => Number(r.mets[0])), 1);
for (const r of evRows) {
  const [name] = r.dims;
  const count = Number(r.mets[0]);
  console.log(`  ${pad(name, 28)} ${pad(num(count), 8)} ${bar(count, evMax)}`);
}
console.log();

function printCustom(title, key, formatRow, footnote) {
  console.log(title);
  if (reports[key]?.__unregistered) {
    console.log('  (custom dimensions not registered yet — see footer)');
  } else {
    const rs = rows(reports[key]) || [];
    if (rs.length === 0) console.log('  (no events in window)');
    for (const r of rs) console.log('  ' + formatRow(r));
  }
  if (footnote) console.log('  ' + footnote);
  console.log();
}

printCustom('CTA clicks (target × location)', 'ctaTargets', (r) => {
  const [target, loc] = r.dims;
  return `${pad(num(r.mets[0]), 6)} target=${pad(target || '(none)', 18)} loc=${loc || '(none)'}`;
});

printCustom('Outbound destinations', 'outboundDestinations', (r) =>
  `${pad(num(r.mets[0]), 6)} ${r.dims[0] || '(none)'}`,
);

if (rows(reports.scrollDepth)) {
  console.log('Scroll depth distribution');
  const sd = (rows(reports.scrollDepth) || []).slice().sort(
    (a, b) => Number(a.dims[0] || 0) - Number(b.dims[0] || 0),
  );
  if (sd.length === 0) console.log('  (no events in window)');
  const max = Math.max(...sd.map((r) => Number(r.mets[0])), 1);
  for (const r of sd) {
    console.log(`  ${pad(r.dims[0] + '%', 6)} ${pad(num(r.mets[0]), 6)} ${bar(Number(r.mets[0]), max)}`);
  }
  console.log();
} else if (reports.scrollDepth?.__unregistered) {
  console.log('Scroll depth distribution');
  console.log('  (custom dimensions not registered yet — see footer)\n');
}

printCustom('Section views (homepage)', 'sectionViews', (r) =>
  `${pad(num(r.mets[0]), 6)} ${r.dims[0] || '(none)'}`,
);

console.log('Top referrers');
for (const r of rows(reports.topReferrers) || []) {
  console.log(`  ${pad(num(r.mets[0]), 6)} ${r.dims[0]}`);
}
console.log();

const anyUnreg = Object.values(reports).some((r) => r?.__unregistered);
if (anyUnreg) {
  console.log('───');
  console.log('Some panes need custom dimensions registered in GA4 first.');
  console.log('GA4 Admin → Custom definitions → Create custom dimension:');
  console.log('  • parameter "target"   (event-scoped)');
  console.log('  • parameter "location" (event-scoped)');
  console.log('  • parameter "value"    (event-scoped)');
  console.log('Data starts flowing into reports ~24h after registration.');
  console.log();
}
