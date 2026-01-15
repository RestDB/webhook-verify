import { computeHmacBase64, secureCompare } from '../utils/crypto.js';
import type { ProviderVerifier } from '../types.js';

/**
 * Shopify webhook verification
 *
 * Shopify sends webhooks with X-Shopify-Hmac-Sha256 header containing
 * a base64-encoded HMAC-SHA256 signature.
 *
 * @see https://shopify.dev/docs/apps/webhooks/configuration/https#step-5-verify-the-webhook
 */
export const shopify: ProviderVerifier = {
  verify(payload, signature, secret) {
    if (!payload || !signature || !secret) {
      return false;
    }

    const computedSig = computeHmacBase64('sha256', secret, payload);

    return secureCompare(computedSig, signature);
  },
};
