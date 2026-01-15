import { verifyEd25519 } from '../utils/crypto.js';
import type { ProviderVerifier, TimestampOptions } from '../types.js';

/**
 * Discord webhook/interaction verification
 *
 * Discord sends interactions with:
 * - X-Signature-Ed25519: Hex-encoded Ed25519 signature
 * - X-Signature-Timestamp: Unix timestamp
 *
 * The signature is computed over timestamp + body.
 *
 * For this library, pass signature in format: "<signature>,t=<timestamp>"
 * The secret should be the application's public key.
 *
 * @see https://discord.com/developers/docs/interactions/receiving-and-responding#security-and-authorization
 */
export const discord: ProviderVerifier = {
  verify(payload, signature, publicKey, options?) {
    if (!payload || !signature || !publicKey) {
      return false;
    }

    // Parse signature and timestamp
    let sig: string | undefined;
    let timestamp: string | undefined;

    if (signature.includes(',')) {
      const parts = signature.split(',');
      for (const part of parts) {
        if (part.startsWith('t=')) {
          timestamp = part.slice(2);
        } else {
          sig = part;
        }
      }
    } else {
      sig = signature;
    }

    if (!sig || !timestamp) {
      return false;
    }

    // Build the message to verify
    const payloadString = typeof payload === 'string' ? payload : payload.toString('utf8');
    const message = timestamp + payloadString;

    return verifyEd25519(publicKey, sig, message);
  },
};
