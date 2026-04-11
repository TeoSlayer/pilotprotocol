import { describe, it, expect } from 'vitest';
import { verifySignature, computeSignature } from '../src/auth';

const SECRET = 'test-secret-key-for-hmac';

describe('auth', () => {
  describe('computeSignature', () => {
    it('returns sha256= prefixed hex', async () => {
      const sig = await computeSignature('hello', '1700000000', SECRET);
      expect(sig).toMatch(/^sha256=[0-9a-f]{64}$/);
    });

    it('is deterministic', async () => {
      const a = await computeSignature('body', '123', SECRET);
      const b = await computeSignature('body', '123', SECRET);
      expect(a).toBe(b);
    });

    it('changes with different body', async () => {
      const a = await computeSignature('body1', '123', SECRET);
      const b = await computeSignature('body2', '123', SECRET);
      expect(a).not.toBe(b);
    });

    it('changes with different timestamp', async () => {
      const a = await computeSignature('body', '100', SECRET);
      const b = await computeSignature('body', '200', SECRET);
      expect(a).not.toBe(b);
    });

    it('changes with different secret', async () => {
      const a = await computeSignature('body', '123', 'secret-a');
      const b = await computeSignature('body', '123', 'secret-b');
      expect(a).not.toBe(b);
    });
  });

  describe('verifySignature', () => {
    function nowTimestamp(): string {
      return Math.floor(Date.now() / 1000).toString();
    }

    it('accepts valid signature', async () => {
      const body = '{"slug":"test"}';
      const ts = nowTimestamp();
      const sig = await computeSignature(body, ts, SECRET);
      const result = await verifySignature(body, sig, ts, SECRET);
      expect(result.valid).toBe(true);
    });

    it('rejects missing signature', async () => {
      const result = await verifySignature('body', null, nowTimestamp(), SECRET);
      expect(result.valid).toBe(false);
      expect(result.error).toBe('Missing signature or timestamp header');
    });

    it('rejects missing timestamp', async () => {
      const result = await verifySignature('body', 'sha256=abc', null, SECRET);
      expect(result.valid).toBe(false);
      expect(result.error).toBe('Missing signature or timestamp header');
    });

    it('rejects expired timestamp', async () => {
      const oldTs = Math.floor(Date.now() / 1000 - 600).toString(); // 10 min ago
      const sig = await computeSignature('body', oldTs, SECRET);
      const result = await verifySignature('body', sig, oldTs, SECRET);
      expect(result.valid).toBe(false);
      expect(result.error).toBe('Timestamp expired');
    });

    it('rejects invalid timestamp', async () => {
      const result = await verifySignature('body', 'sha256=abc', 'not-a-number', SECRET);
      expect(result.valid).toBe(false);
      expect(result.error).toBe('Invalid timestamp');
    });

    it('rejects wrong signature format', async () => {
      const result = await verifySignature('body', 'md5=abc', nowTimestamp(), SECRET);
      expect(result.valid).toBe(false);
      expect(result.error).toBe('Invalid signature format');
    });

    it('rejects wrong signature value', async () => {
      const ts = nowTimestamp();
      const result = await verifySignature('body', 'sha256=' + '0'.repeat(64), ts, SECRET);
      expect(result.valid).toBe(false);
      expect(result.error).toBe('Invalid signature');
    });

    it('rejects tampered body', async () => {
      const ts = nowTimestamp();
      const sig = await computeSignature('original', ts, SECRET);
      const result = await verifySignature('tampered', sig, ts, SECRET);
      expect(result.valid).toBe(false);
    });

    it('rejects wrong secret', async () => {
      const body = 'test';
      const ts = nowTimestamp();
      const sig = await computeSignature(body, ts, 'wrong-secret');
      const result = await verifySignature(body, sig, ts, SECRET);
      expect(result.valid).toBe(false);
    });
  });
});
