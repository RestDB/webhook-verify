import { createVerify, createPublicKey } from 'node:crypto';
import { isTimestampValid } from '../utils/crypto.js';
import type { ProviderVerifier, TimestampOptions } from '../types.js';

/**
 * SendGrid webhook verification (Event Webhook)
 *
 * SendGrid sends:
 * - X-Twilio-Email-Event-Webhook-Signature: Base64-encoded ECDSA signature
 * - X-Twilio-Email-Event-Webhook-Timestamp: Unix timestamp
 *
 * The signature is computed over timestamp + payload using ECDSA with P-256.
 *
 * For this library, pass signature in format: "<signature>,t=<timestamp>"
 * The secret should be the verification key from SendGrid.
 *
 * @see https://docs.sendgrid.com/for-developers/tracking-events/getting-started-event-webhook-security-features
 */
export const sendgrid: ProviderVerifier = {
  verify(payload, signature, publicKey, options?) {
    if (!payload || !signature || !publicKey) {
      return false;
    }

    const tolerance = (options as TimestampOptions)?.tolerance ?? 300;

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

    if (!sig) {
      return false;
    }

    // Validate timestamp if present
    if (timestamp && !isTimestampValid(timestamp, tolerance)) {
      return false;
    }

    try {
      const payloadString = typeof payload === 'string' ? payload : payload.toString('utf8');
      const signedPayload = timestamp ? `${timestamp}${payloadString}` : payloadString;

      // SendGrid uses ECDSA with P-256 curve
      const key = createPublicKey(publicKey);
      const verify = createVerify('SHA256');
      verify.update(signedPayload);

      return verify.verify(key, sig, 'base64');
    } catch {
      return false;
    }
  },
};
