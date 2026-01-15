import {
  computeHmac,
  computeHmacHex,
  computeHmacBase64,
  secureCompare,
  secureCompareBuffer,
  verifyEd25519,
  verifyRsa,
  isTimestampValid,
} from './utils/crypto.js';

export type HmacAlgorithm = 'sha1' | 'sha256' | 'sha512';
export type SignatureEncoding = 'hex' | 'base64';

export interface HmacOptions {
  /** The HMAC algorithm to use */
  algorithm?: HmacAlgorithm;
  /** The encoding of the signature (hex or base64) */
  encoding?: SignatureEncoding;
  /** Prefix to strip from signature (e.g., 'sha256=') */
  prefix?: string;
}

export interface TimestampHmacOptions extends HmacOptions {
  /** Maximum age of the webhook in seconds (default: 300) */
  tolerance?: number;
  /** Format of the signed payload. Use {timestamp} and {payload} placeholders */
  format?: string;
}

/**
 * Generic HMAC verification
 *
 * @param payload - The raw request body
 * @param signature - The signature to verify against
 * @param secret - The HMAC secret
 * @param options - Verification options
 * @returns true if the signature is valid
 *
 * @example
 * ```typescript
 * import { hmac } from 'webhook-verify';
 *
 * // Verify a SHA256 HMAC with hex encoding (most common)
 * hmac.verify(payload, signature, secret);
 *
 * // Verify with base64 encoding
 * hmac.verify(payload, signature, secret, { encoding: 'base64' });
 *
 * // Verify SHA1 with 'sha1=' prefix
 * hmac.verify(payload, signature, secret, {
 *   algorithm: 'sha1',
 *   prefix: 'sha1='
 * });
 * ```
 */
function verifyHmac(
  payload: string | Buffer,
  signature: string,
  secret: string | Buffer,
  options: HmacOptions = {}
): boolean {
  if (!payload || !signature || !secret) {
    return false;
  }

  const { algorithm = 'sha256', encoding = 'hex', prefix } = options;

  // Strip prefix if present
  let sig = signature;
  if (prefix && sig.startsWith(prefix)) {
    sig = sig.slice(prefix.length);
  }

  // Compute expected signature
  const computed =
    encoding === 'base64'
      ? computeHmacBase64(algorithm, secret, payload)
      : computeHmacHex(algorithm, secret, payload);

  return secureCompare(computed, encoding === 'hex' ? sig.toLowerCase() : sig);
}

/**
 * Generate an HMAC signature
 *
 * @param payload - The data to sign
 * @param secret - The HMAC secret
 * @param options - Signing options
 * @returns The signature string
 */
function signHmac(
  payload: string | Buffer,
  secret: string | Buffer,
  options: HmacOptions = {}
): string {
  const { algorithm = 'sha256', encoding = 'hex', prefix = '' } = options;

  const sig =
    encoding === 'base64'
      ? computeHmacBase64(algorithm, secret, payload)
      : computeHmacHex(algorithm, secret, payload);

  return prefix + sig;
}

/**
 * Generic HMAC verification with timestamp validation
 *
 * @param payload - The raw request body
 * @param signature - The signature to verify against
 * @param secret - The HMAC secret
 * @param timestamp - The timestamp (Unix seconds)
 * @param options - Verification options
 * @returns true if the signature is valid and timestamp is fresh
 *
 * @example
 * ```typescript
 * import { hmac } from 'webhook-verify';
 *
 * // Stripe-style: signature over "timestamp.payload"
 * hmac.verifyWithTimestamp(payload, signature, secret, timestamp, {
 *   format: '{timestamp}.{payload}'
 * });
 *
 * // Slack-style: signature over "v0:timestamp:payload"
 * hmac.verifyWithTimestamp(payload, signature, secret, timestamp, {
 *   format: 'v0:{timestamp}:{payload}'
 * });
 * ```
 */
function verifyHmacWithTimestamp(
  payload: string | Buffer,
  signature: string,
  secret: string | Buffer,
  timestamp: number | string,
  options: TimestampHmacOptions = {}
): boolean {
  if (!payload || !signature || !secret || !timestamp) {
    return false;
  }

  const { tolerance = 300, format = '{timestamp}.{payload}', ...hmacOptions } = options;

  // Validate timestamp freshness
  if (!isTimestampValid(timestamp, tolerance)) {
    return false;
  }

  // Build the signed payload using the format string
  const payloadString = typeof payload === 'string' ? payload : payload.toString('utf8');
  const signedPayload = format
    .replace('{timestamp}', String(timestamp))
    .replace('{payload}', payloadString);

  return verifyHmac(signedPayload, signature, secret, hmacOptions);
}

/**
 * HMAC verification utilities
 */
export const hmac = {
  verify: verifyHmac,
  verifyWithTimestamp: verifyHmacWithTimestamp,
  sign: signHmac,
};

/**
 * Verify an Ed25519 signature
 *
 * @param payload - The message that was signed
 * @param signature - The hex-encoded signature
 * @param publicKey - The hex-encoded public key
 * @returns true if the signature is valid
 *
 * @example
 * ```typescript
 * import { ed25519 } from 'webhook-verify';
 *
 * // Discord-style verification
 * const message = timestamp + body;
 * ed25519.verify(message, signature, publicKey);
 * ```
 */
function verifyEd25519Signature(
  payload: string | Buffer,
  signature: string,
  publicKey: string
): boolean {
  if (!payload || !signature || !publicKey) {
    return false;
  }
  return verifyEd25519(publicKey, signature, payload);
}

/**
 * Ed25519 signature verification
 */
export const ed25519 = {
  verify: verifyEd25519Signature,
};

export interface RsaOptions {
  /** The RSA algorithm to use */
  algorithm?: 'RSA-SHA256' | 'RSA-SHA1';
  /** The encoding of the signature */
  encoding?: 'base64' | 'hex';
}

/**
 * Verify an RSA signature
 *
 * @param payload - The message that was signed
 * @param signature - The signature (base64 or hex encoded)
 * @param publicKey - The PEM-encoded public key
 * @param options - Verification options
 * @returns true if the signature is valid
 *
 * @example
 * ```typescript
 * import { rsa } from 'webhook-verify';
 *
 * rsa.verify(payload, signature, publicKey);
 * rsa.verify(payload, signature, publicKey, { algorithm: 'RSA-SHA1' });
 * ```
 */
function verifyRsaSignature(
  payload: string | Buffer,
  signature: string,
  publicKey: string,
  options: RsaOptions = {}
): boolean {
  if (!payload || !signature || !publicKey) {
    return false;
  }

  const { algorithm = 'RSA-SHA256' } = options;
  return verifyRsa(publicKey, signature, payload, algorithm);
}

/**
 * RSA signature verification
 */
export const rsa = {
  verify: verifyRsaSignature,
};

/**
 * Timing-safe string comparison
 *
 * @param a - First string
 * @param b - Second string
 * @returns true if strings are equal
 */
export function timingSafeEqual(a: string, b: string): boolean {
  return secureCompare(a, b);
}

/**
 * Validate that a timestamp is within the allowed tolerance
 *
 * @param timestamp - Unix timestamp in seconds
 * @param tolerance - Maximum age in seconds (default: 300)
 * @returns true if timestamp is fresh
 */
export function validateTimestamp(
  timestamp: number | string,
  tolerance: number = 300
): boolean {
  return isTimestampValid(timestamp, tolerance);
}
