import { createHmac } from 'crypto';
import { secureCompare } from '../utils/crypto.js';
import type { ProviderVerifier } from '../types.js';

/**
 * Square webhook verification
 *
 * Square sends webhooks with x-square-hmacsha256-signature header.
 * The signature is HMAC-SHA256 of: webhook URL + raw body
 *
 * Requires the `url` option to be set.
 *
 * @see https://developer.squareup.com/docs/webhooks/step3validate
 */
export const square: ProviderVerifier = {
  verify(payload, signature, secret, options) {
    if (!payload || !signature || !secret) {
      return false;
    }

    const url = (options as { url?: string })?.url;
    if (!url) {
      return false;
    }

    // Compute expected signature: HMAC-SHA256(url + body)
    const payloadString = typeof payload === 'string' ? payload : payload.toString('utf8');
    const signedPayload = url + payloadString;
    const computed = createHmac('sha256', secret).update(signedPayload).digest('base64');

    return secureCompare(computed, signature);
  },
};
