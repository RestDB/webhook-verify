import type { Provider } from './types.js';

/**
 * Extracted signature data from request headers
 */
export interface SignatureData {
  /** The signature string (formatted for verify()) */
  signature: string;
  /** Raw signature value from header */
  rawSignature?: string;
  /** Timestamp (if applicable) */
  timestamp?: string;
  /** Message ID (for Svix-based providers) */
  messageId?: string;
  /** Event type (if available in headers) */
  eventType?: string;
}

/**
 * Headers object type (case-insensitive access)
 */
export type Headers = Record<string, string | string[] | undefined>;

/**
 * Get header value (handles case-insensitivity and arrays)
 */
function getHeader(headers: Headers, name: string): string | undefined {
  const nameLower = name.toLowerCase();

  // Search through all headers case-insensitively
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === nameLower) {
      // Handle array values
      if (Array.isArray(value)) {
        return value[0];
      }
      return value;
    }
  }

  return undefined;
}

/**
 * Header configurations for each provider
 */
const providerHeaders: Record<Provider, (headers: Headers) => SignatureData | null> = {
  stripe: (headers) => {
    const signature = getHeader(headers, 'stripe-signature');
    if (!signature) return null;
    return { signature, rawSignature: signature };
  },

  github: (headers) => {
    const signature = getHeader(headers, 'x-hub-signature-256');
    const event = getHeader(headers, 'x-github-event');
    if (!signature) return null;
    return { signature, rawSignature: signature, eventType: event };
  },

  shopify: (headers) => {
    const signature = getHeader(headers, 'x-shopify-hmac-sha256');
    const topic = getHeader(headers, 'x-shopify-topic');
    if (!signature) return null;
    return { signature, rawSignature: signature, eventType: topic };
  },

  slack: (headers) => {
    const signature = getHeader(headers, 'x-slack-signature');
    const timestamp = getHeader(headers, 'x-slack-request-timestamp');
    if (!signature || !timestamp) return null;
    // Format for verify(): "v0=<sig>,t=<timestamp>"
    return {
      signature: `${signature},t=${timestamp}`,
      rawSignature: signature,
      timestamp,
    };
  },

  twilio: (headers) => {
    const signature = getHeader(headers, 'x-twilio-signature');
    if (!signature) return null;
    return { signature, rawSignature: signature };
  },

  discord: (headers) => {
    const signature = getHeader(headers, 'x-signature-ed25519');
    const timestamp = getHeader(headers, 'x-signature-timestamp');
    if (!signature || !timestamp) return null;
    // Format for verify(): "<sig>,t=<timestamp>"
    return {
      signature: `${signature},t=${timestamp}`,
      rawSignature: signature,
      timestamp,
    };
  },

  linear: (headers) => {
    const signature = getHeader(headers, 'linear-signature');
    if (!signature) return null;
    return { signature, rawSignature: signature };
  },

  vercel: (headers) => {
    const signature = getHeader(headers, 'x-vercel-signature');
    if (!signature) return null;
    return { signature, rawSignature: signature };
  },

  svix: (headers) => {
    const signature = getHeader(headers, 'svix-signature');
    const timestamp = getHeader(headers, 'svix-timestamp');
    const messageId = getHeader(headers, 'svix-id');
    if (!signature || !timestamp || !messageId) return null;
    // Format for verify(): "<sig>,t=<timestamp>,id=<messageId>"
    return {
      signature: `${signature},t=${timestamp},id=${messageId}`,
      rawSignature: signature,
      timestamp,
      messageId,
    };
  },

  clerk: (headers) => {
    // Clerk uses Svix headers
    return providerHeaders.svix(headers);
  },

  sendgrid: (headers) => {
    const signature = getHeader(headers, 'x-twilio-email-event-webhook-signature');
    const timestamp = getHeader(headers, 'x-twilio-email-event-webhook-timestamp');
    if (!signature) return null;
    // Format for verify(): "<sig>,t=<timestamp>" if timestamp exists
    const sig = timestamp ? `${signature},t=${timestamp}` : signature;
    return {
      signature: sig,
      rawSignature: signature,
      timestamp,
    };
  },

  paddle: (headers) => {
    const signature = getHeader(headers, 'paddle-signature');
    if (!signature) return null;
    return { signature, rawSignature: signature };
  },

  intercom: (headers) => {
    const signature = getHeader(headers, 'x-hub-signature');
    if (!signature) return null;
    return { signature, rawSignature: signature };
  },

  mailchimp: (headers) => {
    const signature = getHeader(headers, 'x-mailchimp-signature');
    if (!signature) return null;
    return { signature, rawSignature: signature };
  },

  gitlab: (headers) => {
    const token = getHeader(headers, 'x-gitlab-token');
    const event = getHeader(headers, 'x-gitlab-event');
    if (!token) return null;
    return { signature: token, rawSignature: token, eventType: event };
  },

  typeform: (headers) => {
    const signature = getHeader(headers, 'typeform-signature');
    if (!signature) return null;
    return { signature, rawSignature: signature };
  },

  crystallize: (headers) => {
    const signature = getHeader(headers, 'x-crystallize-signature');
    if (!signature) return null;
    return { signature, rawSignature: signature };
  },
};

/**
 * Extract signature data from request headers for a specific provider
 *
 * @param provider - The webhook provider name
 * @param headers - Request headers object
 * @returns Signature data object, or null if required headers are missing
 *
 * @example
 * ```typescript
 * import { verify, getSignature } from 'webhook-verify';
 *
 * // Express
 * app.post('/webhook/stripe', express.raw({ type: 'application/json' }), (req, res) => {
 *   const sig = getSignature('stripe', req.headers);
 *   if (!sig) {
 *     return res.status(400).send('Missing signature');
 *   }
 *   const isValid = verify('stripe', req.body, sig.signature, secret);
 * });
 *
 * // Codehooks.io
 * app.post('/webhook/slack', async (req, res) => {
 *   const sig = getSignature('slack', req.headers);
 *   if (!sig) {
 *     return res.status(400).json({ error: 'Missing signature' });
 *   }
 *   // sig.signature is pre-formatted with timestamp for verify()
 *   const isValid = verify('slack', req.rawBody, sig.signature, secret);
 * });
 * ```
 */
export function getSignature(provider: Provider, headers: Headers): SignatureData | null {
  const extractor = providerHeaders[provider];

  if (!extractor) {
    throw new Error(`Unknown webhook provider: ${provider}`);
  }

  return extractor(headers);
}

/**
 * Get the expected header name(s) for a provider
 *
 * @param provider - The webhook provider name
 * @returns Object with header names for this provider
 *
 * @example
 * ```typescript
 * const headers = getHeaderNames('stripe');
 * // { signature: 'stripe-signature' }
 *
 * const headers = getHeaderNames('slack');
 * // { signature: 'x-slack-signature', timestamp: 'x-slack-request-timestamp' }
 * ```
 */
export function getHeaderNames(provider: Provider): Record<string, string> {
  const headerMap: Record<Provider, Record<string, string>> = {
    stripe: { signature: 'stripe-signature' },
    github: { signature: 'x-hub-signature-256', event: 'x-github-event' },
    shopify: { signature: 'x-shopify-hmac-sha256', topic: 'x-shopify-topic' },
    slack: { signature: 'x-slack-signature', timestamp: 'x-slack-request-timestamp' },
    twilio: { signature: 'x-twilio-signature' },
    discord: { signature: 'x-signature-ed25519', timestamp: 'x-signature-timestamp' },
    linear: { signature: 'linear-signature' },
    vercel: { signature: 'x-vercel-signature' },
    svix: { signature: 'svix-signature', timestamp: 'svix-timestamp', id: 'svix-id' },
    clerk: { signature: 'svix-signature', timestamp: 'svix-timestamp', id: 'svix-id' },
    sendgrid: { signature: 'x-twilio-email-event-webhook-signature', timestamp: 'x-twilio-email-event-webhook-timestamp' },
    paddle: { signature: 'paddle-signature' },
    intercom: { signature: 'x-hub-signature' },
    mailchimp: { signature: 'x-mailchimp-signature' },
    gitlab: { token: 'x-gitlab-token', event: 'x-gitlab-event' },
    typeform: { signature: 'typeform-signature' },
    crystallize: { signature: 'x-crystallize-signature' },
  };

  return headerMap[provider];
}
