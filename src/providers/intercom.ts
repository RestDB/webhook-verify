import { computeHmacHex, secureCompare } from '../utils/crypto.js';
import type { ProviderVerifier } from '../types.js';

/**
 * Intercom webhook verification
 *
 * Intercom sends webhooks with X-Hub-Signature header containing
 * sha1=<hex-encoded-hmac>
 *
 * @see https://developers.intercom.com/docs/webhooks/webhook-model
 */
export const intercom: ProviderVerifier = {
  verify(payload, signature, secret) {
    if (!payload || !signature || !secret) {
      return false;
    }

    // Handle both full header value and just the hash
    const expectedSig = signature.startsWith('sha1=')
      ? signature.slice(5)
      : signature;

    const computedSig = computeHmacHex('sha1', secret, payload);

    return secureCompare(computedSig, expectedSig.toLowerCase());
  },
};
