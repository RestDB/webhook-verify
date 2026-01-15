import { createHmac } from 'crypto';
import { secureCompare } from '../utils/crypto.js';
import type { ProviderVerifier } from '../types.js';

/**
 * Zendesk webhook verification
 *
 * Zendesk sends webhooks with:
 * - X-Zendesk-Webhook-Signature: base64-encoded HMAC-SHA256 signature
 * - X-Zendesk-Webhook-Signature-Timestamp: Unix timestamp
 *
 * The signature is computed as: base64(HMACSHA256(timestamp + body))
 *
 * @see https://developer.zendesk.com/documentation/webhooks/verifying/
 */
export const zendesk: ProviderVerifier = {
  verify(payload, signature, secret, options) {
    if (!payload || !signature || !secret) {
      return false;
    }

    // Parse signature format: "signature,t=timestamp"
    const parts = signature.split(',t=');
    if (parts.length !== 2) {
      return false;
    }

    const [sig, timestamp] = parts;

    if (!sig || !timestamp) {
      return false;
    }

    // Validate timestamp if tolerance is set
    const tolerance = (options as { tolerance?: number })?.tolerance ?? 300;
    const timestampNum = parseInt(timestamp, 10);
    const now = Math.floor(Date.now() / 1000);

    if (Math.abs(now - timestampNum) > tolerance) {
      return false;
    }

    // Compute expected signature: base64(HMACSHA256(timestamp + body))
    const payloadString = typeof payload === 'string' ? payload : payload.toString('utf8');
    const signedPayload = timestamp + payloadString;
    const computed = createHmac('sha256', secret).update(signedPayload).digest('base64');

    return secureCompare(computed, sig);
  },
};
