const MAX_TIMESTAMP_AGE_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Verify HMAC-SHA256 signature on a publish request.
 * Mirrors Stripe webhook verification pattern.
 *
 * Header format:
 *   X-Publish-Signature: sha256=<hex>
 *   X-Publish-Timestamp: <unix-seconds>
 *
 * Signed payload: `${timestamp}.${rawBody}`
 */
export async function verifySignature(
  rawBody: string,
  signature: string | null,
  timestamp: string | null,
  secret: string,
): Promise<{ valid: boolean; error?: string }> {
  if (!signature || !timestamp) {
    return { valid: false, error: 'Missing signature or timestamp header' };
  }

  // Replay protection: reject timestamps older than 5 minutes
  const ts = parseInt(timestamp, 10);
  if (isNaN(ts)) {
    return { valid: false, error: 'Invalid timestamp' };
  }
  const age = Math.abs(Date.now() - ts * 1000);
  if (age > MAX_TIMESTAMP_AGE_MS) {
    return { valid: false, error: 'Timestamp expired' };
  }

  // Extract hex digest from "sha256=<hex>"
  if (!signature.startsWith('sha256=')) {
    return { valid: false, error: 'Invalid signature format' };
  }
  const providedHex = signature.slice(7);

  // Compute expected HMAC-SHA256
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );

  const signed = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(`${timestamp}.${rawBody}`),
  );

  const expectedHex = Array.from(new Uint8Array(signed))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  // Constant-time comparison
  const a = new TextEncoder().encode(providedHex);
  const b = new TextEncoder().encode(expectedHex);
  if (a.byteLength !== b.byteLength) {
    return { valid: false, error: 'Invalid signature' };
  }

  const match = crypto.subtle.timingSafeEqual(a, b);
  if (!match) {
    return { valid: false, error: 'Invalid signature' };
  }

  return { valid: true };
}

/**
 * Compute HMAC-SHA256 for testing / client use.
 * Returns the full header value: "sha256=<hex>"
 */
export async function computeSignature(
  rawBody: string,
  timestamp: string,
  secret: string,
): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );

  const signed = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(`${timestamp}.${rawBody}`),
  );

  const hex = Array.from(new Uint8Array(signed))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  return `sha256=${hex}`;
}
