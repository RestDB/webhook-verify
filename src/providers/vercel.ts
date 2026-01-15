import { computeHmacHex, secureCompare } from '../utils/crypto.js';
import type { ProviderVerifier } from '../types.js';

/**
 * Vercel webhook verification
 *
 * Vercel sends webhooks with x-vercel-signature header containing
 * a hex-encoded HMAC-SHA1 signature.
 *
 * @see https://vercel.com/docs/observability/webhooks-overview/webhooks-api#securing-webhooks
 */
export const vercel: ProviderVerifier = {
  verify(payload, signature, secret) {
    if (!payload || !signature || !secret) {
      return false;
    }

    const computedSig = computeHmacHex('sha1', secret, payload);

    return secureCompare(computedSig, signature.toLowerCase());
  },
};
