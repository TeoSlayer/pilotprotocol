import { describe, it, expect } from 'vitest';
import { computeSignature } from '../src/auth';
import { env, SELF } from 'cloudflare:test';

const SECRET = 'test-publish-secret';

async function publishRequest(
  body: Record<string, unknown>,
  opts?: { skipAuth?: boolean; badSig?: boolean; oldTimestamp?: boolean },
): Promise<Response> {
  const rawBody = JSON.stringify(body);
  const ts = opts?.oldTimestamp
    ? Math.floor(Date.now() / 1000 - 600).toString()
    : Math.floor(Date.now() / 1000).toString();

  let sig: string;
  if (opts?.skipAuth) {
    sig = '';
  } else if (opts?.badSig) {
    sig = 'sha256=' + '0'.repeat(64);
  } else {
    sig = await computeSignature(rawBody, ts, SECRET);
  }

  return SELF.fetch('https://worker.test/api/publish', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Publish-Signature': sig,
      'X-Publish-Timestamp': ts,
    },
    body: rawBody,
  });
}

const validBody = {
  slug: 'test-auto-post',
  title: 'Test Auto Post',
  description: 'A test post published via webhook.',
  date: 'Mar 27',
  date_full: 'March 27, 2026',
  category: 'Tutorial',
  tags: ['test'],
  body_html: '<p>Hello world.</p>',
};

describe('POST /api/publish', () => {
  it('rejects missing auth headers', async () => {
    const res = await publishRequest(validBody, { skipAuth: true });
    expect(res.status).toBe(401);
    const data = await res.json<{ error: string }>();
    expect(data.error).toContain('Missing signature');
  });

  it('rejects bad signature', async () => {
    const res = await publishRequest(validBody, { badSig: true });
    expect(res.status).toBe(401);
  });

  it('rejects expired timestamp', async () => {
    const res = await publishRequest(validBody, { oldTimestamp: true });
    expect(res.status).toBe(401);
    const data = await res.json<{ error: string }>();
    expect(data.error).toContain('expired');
  });

  it('rejects invalid JSON fields', async () => {
    const res = await publishRequest({ slug: 'AB' });
    expect(res.status).toBe(400);
  });

  it('rejects empty body_html', async () => {
    const res = await publishRequest({ ...validBody, body_html: '' });
    expect(res.status).toBe(400);
  });

  it('rejects empty tags', async () => {
    const res = await publishRequest({ ...validBody, tags: [] });
    expect(res.status).toBe(400);
  });
});

describe('GET /health', () => {
  it('returns ok', async () => {
    const res = await SELF.fetch('https://worker.test/health');
    expect(res.status).toBe(200);
    const data = await res.json<{ status: string }>();
    expect(data.status).toBe('ok');
  });
});

describe('404', () => {
  it('returns 404 for unknown routes', async () => {
    const res = await SELF.fetch('https://worker.test/unknown');
    expect(res.status).toBe(404);
  });
});
