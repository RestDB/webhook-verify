import { createHmac } from 'crypto';
import { secureCompare } from '../utils/crypto.js';
import type { ProviderVerifier } from '../types.js';

/**
 * Segment webhook verification
 *
 * Segment sends webhooks with X-Signature header containing
 * a hex-encoded HMAC-SHA1 signature of the request body.
 *
 * @see https://segment.com/docs/connections/destinations/catalog/webhooks/
 */
export const segment: ProviderVerifier = {
  verify(payload, signature, secret) {
    if (!payload || !signature || !secret) {
      return false;
    }

    // Compute expected signature: hex(HMACSHA1(body))
    const payloadString = typeof payload === 'string' ? payload : payload.toString('utf8');
    const computed = createHmac('sha1', secret).update(payloadString).digest('hex');

    return secureCompare(computed, signature.toLowerCase());
  },
};
