import { computeHmacHex, secureCompare, isTimestampValid } from '../utils/crypto.js';
import type { ProviderVerifier, TimestampOptions } from '../types.js';

/**
 * Stripe webhook verification
 *
 * Stripe sends webhooks with Stripe-Signature header containing:
 * t=<timestamp>,v1=<signature>,v0=<legacy-signature>
 *
 * The signature is computed as HMAC-SHA256 of "<timestamp>.<payload>"
 *
 * @see https://stripe.com/docs/webhooks/signatures
 */
export const stripe: ProviderVerifier = {
  verify(payload, signature, secret, options?) {
    if (!payload || !signature || !secret) {
      return false;
    }

    const tolerance = (options as TimestampOptions)?.tolerance ?? 300;

    // Parse the signature header
    const parts = signature.split(',');
    let timestamp: string | undefined;
    let signatures: string[] = [];

    for (const part of parts) {
      const [key, value] = part.split('=');
      if (key === 't') {
        timestamp = value;
      } else if (key === 'v1') {
        signatures.push(value);
      }
    }

    if (!timestamp || signatures.length === 0) {
      return false;
    }

    // Validate timestamp
    if (!isTimestampValid(timestamp, tolerance)) {
      return false;
    }

    // Compute expected signature
    const payloadString = typeof payload === 'string' ? payload : payload.toString('utf8');
    const signedPayload = `${timestamp}.${payloadString}`;
    const expectedSig = computeHmacHex('sha256', secret, signedPayload);

    // Check if any of the signatures match
    return signatures.some((sig) => secureCompare(expectedSig, sig.toLowerCase()));
  },
};
