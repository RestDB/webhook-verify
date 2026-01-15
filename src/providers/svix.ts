import { computeHmacBase64, secureCompare, isTimestampValid } from '../utils/crypto.js';
import type { ProviderVerifier, TimestampOptions } from '../types.js';

/**
 * Svix webhook verification
 *
 * Svix is used by many services (Clerk, Resend, etc.) and sends:
 * - svix-id: Unique message ID
 * - svix-timestamp: Unix timestamp
 * - svix-signature: Comma-separated list of signatures (v1,<base64-sig>)
 *
 * The signature is computed as HMAC-SHA256 of "<msg-id>.<timestamp>.<body>"
 *
 * For this library, pass signature in format: "<svix-signature>,t=<timestamp>,id=<msg-id>"
 *
 * @see https://docs.svix.com/receiving/verifying-payloads/how
 */
export const svix: ProviderVerifier = {
  verify(payload, signature, secret, options?) {
    if (!payload || !signature || !secret) {
      return false;
    }

    const tolerance = (options as TimestampOptions)?.tolerance ?? 300;

    // Parse signature parts
    // Format: "v1,<sig>,t=<timestamp>,id=<msg-id>" or multiple sigs "v1,<sig1> v1,<sig2>,t=...,id=..."
    let signatures: string[] = [];
    let timestamp: string | undefined;
    let msgId: string | undefined;

    const parts = signature.split(',');
    for (let i = 0; i < parts.length; i++) {
      const part = parts[i].trim();
      if (part === 'v1' && i + 1 < parts.length) {
        // v1 is followed by the signature in the next part
        signatures.push(parts[i + 1].trim());
        i++; // skip the signature part
      } else if (part.startsWith('t=')) {
        timestamp = part.slice(2);
      } else if (part.startsWith('id=')) {
        msgId = part.slice(3);
      }
    }

    if (!timestamp || !msgId || signatures.length === 0) {
      return false;
    }

    // Validate timestamp
    if (!isTimestampValid(timestamp, tolerance)) {
      return false;
    }

    // Svix secrets are base64 encoded and prefixed with "whsec_"
    let secretKey: Buffer;
    if (secret.startsWith('whsec_')) {
      secretKey = Buffer.from(secret.slice(6), 'base64');
    } else {
      secretKey = Buffer.from(secret, 'base64');
    }

    // Compute expected signature
    const payloadString = typeof payload === 'string' ? payload : payload.toString('utf8');
    const signedPayload = `${msgId}.${timestamp}.${payloadString}`;
    const expectedSig = computeHmacBase64('sha256', secretKey, signedPayload);

    // Check if any of the signatures match
    return signatures.some((sig) => secureCompare(expectedSig, sig));
  },
};
