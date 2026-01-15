import { createHmac } from 'crypto';
import { secureCompare } from '../utils/crypto.js';
import type { ProviderVerifier } from '../types.js';

/**
 * HubSpot webhook verification (v3)
 *
 * HubSpot v3 signatures use HMAC-SHA256 base64 encoded.
 * The signature is computed over: requestMethod + requestUri + requestBody + timestamp
 *
 * Headers:
 * - X-HubSpot-Signature-V3: base64-encoded HMAC-SHA256 signature
 * - X-HubSpot-Request-Timestamp: Unix timestamp in milliseconds
 *
 * Requires options: { url, method }
 *
 * @see https://developers.hubspot.com/docs/api/webhooks/validating-requests
 */
export const hubspot: ProviderVerifier = {
  verify(payload, signature, secret, options) {
    if (!payload || !signature || !secret) {
      return false;
    }

    // Parse signature format: "signature,t=timestamp,m=method,u=url" or just "signature,t=timestamp"
    // When using headers extraction, we format as: signature,t=timestamp
    // The method and url come from options
    const parts = signature.split(',');
    let sig = parts[0];
    let timestamp: string | undefined;

    for (const part of parts.slice(1)) {
      if (part.startsWith('t=')) {
        timestamp = part.slice(2);
      }
    }

    if (!sig || !timestamp) {
      return false;
    }

    const opts = options as { url?: string; method?: string; tolerance?: number };
    const url = opts?.url;
    const method = opts?.method ?? 'POST';

    if (!url) {
      return false;
    }

    // Validate timestamp (HubSpot uses milliseconds)
    const tolerance = opts?.tolerance ?? 300;
    const timestampNum = parseInt(timestamp, 10);
    const now = Date.now();

    // HubSpot timestamp is in milliseconds
    if (Math.abs(now - timestampNum) > tolerance * 1000) {
      return false;
    }

    // Compute expected signature: base64(HMACSHA256(method + uri + body + timestamp))
    const payloadString = typeof payload === 'string' ? payload : payload.toString('utf8');
    const signedPayload = method + url + payloadString + timestamp;
    const computed = createHmac('sha256', secret).update(signedPayload).digest('base64');

    return secureCompare(computed, sig);
  },
};
