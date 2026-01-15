/**
 * Supported webhook providers
 */
export type Provider =
  | 'stripe'
  | 'github'
  | 'shopify'
  | 'slack'
  | 'twilio'
  | 'discord'
  | 'linear'
  | 'vercel'
  | 'svix'
  | 'clerk'
  | 'sendgrid'
  | 'paddle'
  | 'intercom'
  | 'mailchimp'
  | 'gitlab'
  | 'typeform'
  | 'crystallize';

/**
 * Base options available to all providers
 */
export interface BaseOptions {
  /**
   * Additional secrets to try if the primary secret fails.
   * Useful for secret rotation - allows accepting both old and new secrets
   * during a transition period.
   */
  additionalSecrets?: string[];
}

/**
 * Options for providers that support timestamp tolerance
 */
export interface TimestampOptions extends BaseOptions {
  /**
   * Maximum age of the webhook in seconds (default: 300 = 5 minutes)
   */
  tolerance?: number;
}

/**
 * Twilio-specific options requiring the request URL
 */
export interface TwilioOptions extends BaseOptions {
  /**
   * The full URL of the webhook endpoint (required for Twilio validation)
   */
  url: string;
}

/**
 * Crystallize-specific options requiring URL and method
 */
export interface CrystallizeOptions extends BaseOptions {
  /**
   * The full URL of the webhook endpoint (required for Crystallize validation)
   */
  url: string;
  /**
   * The HTTP method (default: 'POST')
   */
  method?: string;
}

/**
 * Provider-specific verification options
 */
export type VerifyOptions = BaseOptions | TimestampOptions | TwilioOptions | CrystallizeOptions;

/**
 * Internal interface for provider verification functions
 */
export interface ProviderVerifier {
  /**
   * Verify a webhook payload
   * @param payload - The raw request body (string or Buffer)
   * @param signature - The signature from the webhook header
   * @param secret - The webhook secret or public key
   * @param options - Provider-specific options
   * @returns true if the signature is valid, false otherwise
   */
  verify(
    payload: string | Buffer,
    signature: string,
    secret: string,
    options?: VerifyOptions
  ): boolean;
}

/**
 * Registry of all provider verifiers
 */
export type ProviderRegistry = Record<Provider, ProviderVerifier>;
