import { createHmac, timingSafeEqual, createVerify, createPublicKey } from 'crypto';

/**
 * Compute HMAC signature of a payload
 */
export function computeHmac(
  algorithm: 'sha1' | 'sha256' | 'sha512',
  secret: string | Buffer,
  payload: string | Buffer
): Buffer {
  return createHmac(algorithm, secret).update(payload).digest();
}

/**
 * Compute HMAC signature and return as hex string
 */
export function computeHmacHex(
  algorithm: 'sha1' | 'sha256' | 'sha512',
  secret: string | Buffer,
  payload: string | Buffer
): string {
  return computeHmac(algorithm, secret, payload).toString('hex');
}

/**
 * Compute HMAC signature and return as base64 string
 */
export function computeHmacBase64(
  algorithm: 'sha1' | 'sha256' | 'sha512',
  secret: string | Buffer,
  payload: string | Buffer
): string {
  return computeHmac(algorithm, secret, payload).toString('base64');
}

/**
 * Timing-safe string comparison to prevent timing attacks
 */
export function secureCompare(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }

  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);

  if (bufA.length !== bufB.length) {
    // Still do a comparison to prevent timing attacks based on length
    timingSafeEqual(bufA, bufA);
    return false;
  }

  return timingSafeEqual(bufA, bufB);
}

/**
 * Timing-safe buffer comparison
 */
export function secureCompareBuffer(a: Buffer, b: Buffer): boolean {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    return false;
  }

  if (a.length !== b.length) {
    timingSafeEqual(a, a);
    return false;
  }

  return timingSafeEqual(a, b);
}

/**
 * Verify Ed25519 signature (used by Discord)
 */
export function verifyEd25519(
  publicKey: string,
  signature: string,
  message: string | Buffer
): boolean {
  try {
    const key = createPublicKey({
      key: Buffer.from(publicKey, 'hex'),
      format: 'der',
      type: 'spki',
    });

    const verify = createVerify('Ed25519');
    verify.update(message);
    return verify.verify(key, Buffer.from(signature, 'hex'));
  } catch {
    // Try raw key format for Ed25519
    try {
      // Ed25519 public key in raw format needs to be wrapped in SPKI
      const rawKey = Buffer.from(publicKey, 'hex');
      if (rawKey.length !== 32) {
        return false;
      }

      // SPKI wrapper for Ed25519 (OID 1.3.101.112)
      const spkiPrefix = Buffer.from([
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
      ]);
      const spkiKey = Buffer.concat([spkiPrefix, rawKey]);

      const key = createPublicKey({
        key: spkiKey,
        format: 'der',
        type: 'spki',
      });

      const verify = createVerify('Ed25519');
      verify.update(message);
      return verify.verify(key, Buffer.from(signature, 'hex'));
    } catch {
      return false;
    }
  }
}

/**
 * Verify RSA signature (used by Paddle)
 */
export function verifyRsa(
  publicKey: string,
  signature: string,
  message: string | Buffer,
  algorithm: 'RSA-SHA256' | 'RSA-SHA1' = 'RSA-SHA256'
): boolean {
  try {
    const verify = createVerify(algorithm);
    verify.update(message);
    return verify.verify(publicKey, signature, 'base64');
  } catch {
    return false;
  }
}

/**
 * Parse a timestamp from various formats and validate it's within tolerance
 */
export function isTimestampValid(
  timestamp: number | string,
  toleranceSeconds: number = 300
): boolean {
  const ts = typeof timestamp === 'string' ? parseInt(timestamp, 10) : timestamp;

  if (isNaN(ts) || ts <= 0) {
    return false;
  }

  const now = Math.floor(Date.now() / 1000);
  const diff = Math.abs(now - ts);

  return diff <= toleranceSeconds;
}
