import { createHash, createHmac } from 'crypto';
import { secureCompare } from '../utils/crypto.js';
import type { ProviderVerifier, VippsOptions } from '../types.js';

/**
 * Vipps MobilePay webhook verification
 *
 * Vipps uses the Azure API Management signature scheme. The request carries:
 * - Authorization: HMAC-SHA256 SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature=<base64>
 * - x-ms-date: RFC1123 timestamp, e.g. "Thu, 30 Mar 2023 08:38:32 GMT"
 * - x-ms-content-sha256: base64 SHA-256 of the raw body
 *
 * The signed string is, with \n and not \r\n:
 *
 *   METHOD\nPATH_AND_QUERY\nDATE;HOST;CONTENT_HASH
 *
 * signed with HMAC-SHA256 using the webhook secret as-is (it is not
 * base64-decoded first) and base64-encoded.
 *
 * Verification is two steps, not one. The signature covers a *hash* of the body
 * rather than the body itself, so checking the signature alone would accept a
 * swapped payload carrying a still-valid signature. The content hash is checked
 * against the received bytes first.
 *
 * Requires the `url` option: host and path-and-query are taken from the URL you
 * registered with Vipps rather than from the inbound Host header, so a proxy
 * rewriting Host cannot break verification.
 *
 * For this library, pass the signature as: "<signature>|t=<date>|c=<content-hash>"
 * (pipe-delimited, because the RFC1123 date itself contains a comma). Passing
 * the headers object to verify() does this for you.
 *
 * @see https://developer.vippsmobilepay.com/docs/APIs/webhooks-api/request-authentication/
 */
export const vipps: ProviderVerifier = {
  verify(payload, signature, secret, options) {
    if (!payload || !signature || !secret) {
      return false;
    }

    const opts = options as VippsOptions | undefined;
    const url = opts?.url;
    if (!url) {
      return false;
    }

    // "<signature>|t=<date>|c=<content-hash>"
    const parts = signature.split('|');
    let sig = parts[0];
    let date: string | undefined;
    let contentHash: string | undefined;

    for (const part of parts.slice(1)) {
      if (part.startsWith('t=')) {
        date = part.slice(2);
      } else if (part.startsWith('c=')) {
        contentHash = part.slice(2);
      }
    }

    if (!sig || !date || !contentHash) {
      return false;
    }

    // Tolerate the full Authorization header value being passed as the signature
    const signatureParam = /Signature=([^&\s]+)/.exec(sig);
    if (signatureParam?.[1]) {
      sig = signatureParam[1];
    }

    // Step 1: the claimed content hash must match the bytes we actually received
    const computedHash = createHash('sha256').update(payload).digest('base64');
    if (!secureCompare(computedHash, contentHash)) {
      return false;
    }

    // Reject stale deliveries. x-ms-date is RFC1123, not a Unix timestamp.
    const tolerance = opts?.tolerance ?? 300;
    const sentAt = Date.parse(date);
    if (Number.isNaN(sentAt)) {
      return false;
    }
    if (Math.abs(Date.now() - sentAt) > tolerance * 1000) {
      return false;
    }

    let host: string;
    let pathAndQuery: string;
    try {
      const parsed = new URL(url);
      host = parsed.host;
      pathAndQuery = parsed.pathname + parsed.search;
    } catch {
      return false;
    }

    // Step 2: METHOD\nPATH_AND_QUERY\nDATE;HOST;CONTENT_HASH
    const method = opts?.method ?? 'POST';
    const signedString = `${method}\n${pathAndQuery}\n${date};${host};${contentHash}`;
    const computed = createHmac('sha256', secret).update(signedString).digest('base64');

    return secureCompare(computed, sig);
  },
};
