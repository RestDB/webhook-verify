import { computeHmacHex, secureCompare, isTimestampValid } from '../utils/crypto.js';
import type { ProviderVerifier, TimestampOptions } from '../types.js';

/**
 * Slack webhook verification
 *
 * Slack sends requests with:
 * - X-Slack-Signature header: v0=<hex-encoded-hmac>
 * - X-Slack-Request-Timestamp header: Unix timestamp
 *
 * The signature is computed as HMAC-SHA256 of "v0:<timestamp>:<body>"
 *
 * For this library, pass the signature in format: "v0=<signature>,t=<timestamp>"
 * or pass timestamp in options.
 *
 * @see https://api.slack.com/authentication/verifying-requests-from-slack
 */
export const slack: ProviderVerifier = {
  verify(payload, signature, secret, options?) {
    if (!payload || !signature || !secret) {
      return false;
    }

    const tolerance = (options as TimestampOptions)?.tolerance ?? 300;

    // Parse signature - can be "v0=<sig>,t=<timestamp>" or just "v0=<sig>"
    let sig: string | undefined;
    let timestamp: string | undefined;

    if (signature.includes(',')) {
      // Combined format: "v0=<sig>,t=<timestamp>"
      const parts = signature.split(',');
      for (const part of parts) {
        const [key, value] = part.split('=');
        if (key === 'v0') {
          sig = value;
        } else if (key === 't') {
          timestamp = value;
        }
      }
    } else if (signature.startsWith('v0=')) {
      sig = signature.slice(3);
      // Timestamp must be in options or we can't validate
      timestamp = String(Math.floor(Date.now() / 1000));
    } else {
      sig = signature;
      timestamp = String(Math.floor(Date.now() / 1000));
    }

    if (!sig || !timestamp) {
      return false;
    }

    // Validate timestamp
    if (!isTimestampValid(timestamp, tolerance)) {
      return false;
    }

    // Compute expected signature
    const payloadString = typeof payload === 'string' ? payload : payload.toString('utf8');
    const baseString = `v0:${timestamp}:${payloadString}`;
    const expectedSig = computeHmacHex('sha256', secret, baseString);

    return secureCompare(`v0=${expectedSig}`, `v0=${sig.toLowerCase()}`);
  },
};
