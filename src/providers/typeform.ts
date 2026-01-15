import { computeHmacBase64, secureCompare } from '../utils/crypto.js';
import type { ProviderVerifier } from '../types.js';

/**
 * Typeform webhook verification
 *
 * Typeform sends webhooks with Typeform-Signature header containing
 * sha256=<base64-encoded-hmac>
 *
 * @see https://www.typeform.com/developers/webhooks/secure-your-webhooks/
 */
export const typeform: ProviderVerifier = {
  verify(payload, signature, secret) {
    if (!payload || !signature || !secret) {
      return false;
    }

    // Handle both full header value and just the hash
    const expectedSig = signature.startsWith('sha256=')
      ? signature.slice(7)
      : signature;

    const computedSig = computeHmacBase64('sha256', secret, payload);

    return secureCompare(computedSig, expectedSig);
  },
};
