import { computeHmacBase64, secureCompare } from '../utils/crypto.js';
import type { ProviderVerifier } from '../types.js';

/**
 * Mailchimp webhook verification
 *
 * Mailchimp sends webhooks with X-Mailchimp-Signature header containing
 * a base64-encoded HMAC-SHA256 signature.
 *
 * @see https://mailchimp.com/developer/transactional/guides/track-respond-activity-webhooks/
 */
export const mailchimp: ProviderVerifier = {
  verify(payload, signature, secret) {
    if (!payload || !signature || !secret) {
      return false;
    }

    const computedSig = computeHmacBase64('sha256', secret, payload);

    return secureCompare(computedSig, signature);
  },
};
