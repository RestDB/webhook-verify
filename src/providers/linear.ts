import { computeHmacHex, secureCompare } from '../utils/crypto.js';
import type { ProviderVerifier } from '../types.js';

/**
 * Linear webhook verification
 *
 * Linear sends webhooks with Linear-Signature header containing
 * a hex-encoded HMAC-SHA256 signature.
 *
 * @see https://developers.linear.app/docs/graphql/webhooks#signature-verification
 */
export const linear: ProviderVerifier = {
  verify(payload, signature, secret) {
    if (!payload || !signature || !secret) {
      return false;
    }

    const computedSig = computeHmacHex('sha256', secret, payload);

    return secureCompare(computedSig, signature.toLowerCase());
  },
};
