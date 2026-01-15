import { providers } from './providers/index.js';
import type { Provider, VerifyOptions } from './types.js';

/**
 * Verify a webhook signature from a supported provider
 *
 * @param provider - The webhook provider name
 * @param payload - The raw request body (string or Buffer)
 * @param signature - The signature from the webhook header
 * @param secret - The webhook secret, API key, or public key
 * @param options - Provider-specific options (e.g., timestamp tolerance)
 * @returns true if the signature is valid, false otherwise
 *
 * @example
 * ```typescript
 * import { verify } from 'webhook-verify';
 *
 * // Verify a Stripe webhook
 * const isValid = verify('stripe', body, signature, webhookSecret);
 *
 * // Verify with custom timestamp tolerance
 * const isValid = verify('stripe', body, signature, secret, { tolerance: 600 });
 * ```
 */
export function verify(
  provider: Provider,
  payload: string | Buffer,
  signature: string,
  secret: string,
  options?: VerifyOptions
): boolean {
  const verifier = providers[provider];

  if (!verifier) {
    throw new Error(`Unknown webhook provider: ${provider}`);
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
