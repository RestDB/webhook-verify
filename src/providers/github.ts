import { computeHmacHex, secureCompare } from '../utils/crypto.js';
import type { ProviderVerifier } from '../types.js';

/**
 * GitHub webhook verification
 *
 * GitHub sends webhooks with X-Hub-Signature-256 header containing:
 * sha256=<hex-encoded-hmac>
 *
 * @see https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
 */
export const github: ProviderVerifier = {
  verify(payload, signature, secret) {
    if (!payload || !signature || !secret) {
      return false;
    }

    // Handle both full header value and just the hash
    const expectedSig = signature.startsWith('sha256=')
      ? signature.slice(7)
      : signature;

    const computedSig = computeHmacHex('sha256', secret, payload);

    return secureCompare(computedSig, expectedSig.toLowerCase());
  },
};
