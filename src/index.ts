import { providers } from './providers/index.js';
import { getSignature, getHeaderNames } from './headers.js';
import type { Headers } from './headers.js';
import type { Provider, VerifyOptions } from './types.js';

/**
 * Verify a webhook signature from a supported provider
 *
 * @param provider - The webhook provider name
 * @param payload - The raw request body (string or Buffer)
 * @param signatureOrHeaders - The signature string OR request headers object
 * @param secret - The webhook secret, API key, or public key
 * @param options - Provider-specific options (e.g., timestamp tolerance)
 * @returns true if the signature is valid, false otherwise
 * @throws Error if headers object is passed but required signature headers are missing
 *
 * @example
 * ```typescript
 * import { verify } from 'webhook-verify';
 *
 * // Pass headers directly (recommended)
 * const isValid = verify('stripe', req.rawBody, req.headers, webhookSecret);
 *
 * // Or pass signature string manually
 * const isValid = verify('stripe', body, signatureString, webhookSecret);
 *
 * // With custom timestamp tolerance
 * const isValid = verify('stripe', body, req.headers, secret, { tolerance: 600 });
 * ```
 */
export function verify(
  provider: Provider,
  payload: string | Buffer,
  signatureOrHeaders: string | Headers,
  secret: string,
  options?: VerifyOptions
): boolean {
  const verifier = providers[provider];

  if (!verifier) {
    throw new Error(`Unknown webhook provider: ${provider}`);
  }

  let signature: string;

  if (typeof signatureOrHeaders === 'string') {
    // Direct signature string
    signature = signatureOrHeaders;
  } else {
    // Headers object - extract signature
    const sigData = getSignature(provider, signatureOrHeaders);
    if (!sigData) {
      const headerNames = getHeaderNames(provider);
      const required = Object.values(headerNames).join(', ');
      throw new Error(`Missing required webhook signature header(s) for ${provider}: ${required}`);
    }
    signature = sigData.signature;
  }

  return verifier.verify(payload, signature, secret, options);
}

/**
 * Get a list of all supported providers
 */
export function getSupportedProviders(): Provider[] {
  return Object.keys(providers) as Provider[];
}

/**
 * Check if a provider is supported
 */
export function isProviderSupported(provider: string): provider is Provider {
  return provider in providers;
}

// Re-export types
export type { Provider, VerifyOptions, TimestampOptions, TwilioOptions } from './types.js';

// Re-export individual providers for direct access
export * from './providers/index.js';

// Re-export generic algorithm handlers
export {
  hmac,
  ed25519,
  rsa,
  timingSafeEqual,
  validateTimestamp,
} from './algorithms.js';

export type { HmacAlgorithm, SignatureEncoding, HmacOptions, TimestampHmacOptions, RsaOptions } from './algorithms.js';

// Re-export header extraction helpers
export { getSignature, getHeaderNames } from './headers.js';

export type { SignatureData, Headers } from './headers.js';
