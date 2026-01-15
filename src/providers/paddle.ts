import { verifyRsa, isTimestampValid } from '../utils/crypto.js';
import type { ProviderVerifier, TimestampOptions } from '../types.js';

/**
 * Paddle webhook verification (Paddle Billing)
 *
 * Paddle sends webhooks with:
 * - Paddle-Signature header: ts=<timestamp>;h1=<signature>
 *
 * The signature is RSA-SHA256 over "<timestamp>:<body>"
 *
 * For this library, pass the Paddle-Signature header value as signature.
 * The secret should be the public key from Paddle.
 *
 * @see https://developer.paddle.com/webhooks/signature-verification
 */
export const paddle: ProviderVerifier = {
  verify(payload, signature, publicKey, options?) {
    if (!payload || !signature || !publicKey) {
      return false;
    }

    const tolerance = (options as TimestampOptions)?.tolerance ?? 300;

    // Parse signature header: ts=<timestamp>;h1=<signature>
    let timestamp: string | undefined;
    let sig: string | undefined;

    const parts = signature.split(';');
    for (const part of parts) {
      if (part.startsWith('ts=')) {
        timestamp = part.slice(3);
      } else if (part.startsWith('h1=')) {
        sig = part.slice(3);
      }
    }

    if (!timestamp || !sig) {
      return false;
    }

    // Validate timestamp
    if (!isTimestampValid(timestamp, tolerance)) {
      return false;
    }

    // Build the signed payload
    const payloadString = typeof payload === 'string' ? payload : payload.toString('utf8');
    const signedPayload = `${timestamp}:${payloadString}`;

    return verifyRsa(publicKey, sig, signedPayload, 'RSA-SHA256');
  },
};
