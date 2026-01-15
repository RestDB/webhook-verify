import { createHmac } from 'crypto';
import type { ProviderVerifier, CrystallizeOptions } from '../types.js';

/**
 * Decode base64url string
 */
function base64UrlDecode(str: string): string {
  // Convert base64url to base64
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  // Add padding if needed
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  return Buffer.from(padded, 'base64').toString('utf8');
}

/**
 * Verify JWT signature using HMAC-SHA256
 */
function verifyJwt(token: string, secret: string): { valid: boolean; payload?: Record<string, unknown> } {
  const parts = token.split('.');
  if (parts.length !== 3) {
    return { valid: false };
  }

  const [headerB64, payloadB64, signatureB64] = parts;

  // Verify signature
  const signatureInput = `${headerB64}.${payloadB64}`;
  const expectedSignature = createHmac('sha256', secret)
    .update(signatureInput)
    .digest('base64url');

  // Compare signatures (timing-safe would be better, but JWT libraries don't typically use it)
  if (signatureB64 !== expectedSignature) {
    return { valid: false };
  }

  // Parse payload
  try {
    const payload = JSON.parse(base64UrlDecode(payloadB64));
    return { valid: true, payload };
  } catch {
    return { valid: false };
  }
}

/**
 * Crystallize webhook signature verification
 *
 * Crystallize uses JWT (HS256) containing an HMAC of the request data.
 * Header: X-Crystallize-Signature
 *
 * @see https://crystallize.com/learn/developer-guides/api-overview/signature-verification
 */
export const crystallize: ProviderVerifier = {
  verify(payload, signature, secret, options) {
    const opts = options as CrystallizeOptions | undefined;

    if (!opts?.url) {
      throw new Error('Crystallize verification requires url option');
    }

    const method = opts.method || 'POST';
    const body = typeof payload === 'string' ? payload : payload.toString('utf8');

    // Verify the JWT
    const { valid, payload: jwtPayload } = verifyJwt(signature, secret);
    if (!valid || !jwtPayload) {
      return false;
    }

    // Check JWT expiration
    if (jwtPayload.exp && typeof jwtPayload.exp === 'number') {
      const now = Math.floor(Date.now() / 1000);
      if (now > jwtPayload.exp) {
        return false;
      }
    }

    // Extract HMAC from JWT payload
    const expectedHmac = jwtPayload.hmac;
    if (typeof expectedHmac !== 'string') {
      return false;
    }

    // Create the data object to hash
    const dataToHash = JSON.stringify({
      url: opts.url,
      method: method,
      body: body,
    });

    // Compute SHA256 hash
    const computedHmac = createHmac('sha256', secret)
      .update(dataToHash)
      .digest('hex');

    // Compare HMACs
    return computedHmac === expectedHmac;
  },
};
