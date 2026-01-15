import { computeHmacBase64, secureCompare } from '../utils/crypto.js';
import type { ProviderVerifier, TwilioOptions } from '../types.js';

/**
 * Twilio webhook verification
 *
 * Twilio sends webhooks with X-Twilio-Signature header containing
 * a base64-encoded HMAC-SHA1 signature.
 *
 * The signature is computed over the full URL + sorted POST parameters.
 *
 * For this library, pass the full URL in options.url and the raw body as payload.
 * The payload should be the URL-encoded form body.
 *
 * @see https://www.twilio.com/docs/usage/security#validating-requests
 */
export const twilio: ProviderVerifier = {
  verify(payload, signature, secret, options?) {
    if (!payload || !signature || !secret) {
      return false;
    }

    const url = (options as TwilioOptions)?.url;
    if (!url) {
      return false;
    }

    // Parse the form body and sort parameters
    const payloadString = typeof payload === 'string' ? payload : payload.toString('utf8');
    const params = new URLSearchParams(payloadString);
    const sortedParams: [string, string][] = [];

    for (const [key, value] of params) {
      sortedParams.push([key, value]);
    }
    sortedParams.sort((a, b) => a[0].localeCompare(b[0]));

    // Build the string to sign: URL + sorted key-value pairs (no separators)
    let signatureBase = url;
    for (const [key, value] of sortedParams) {
      signatureBase += key + value;
    }

    const computedSig = computeHmacBase64('sha1', secret, signatureBase);

    return secureCompare(computedSig, signature);
  },
};
