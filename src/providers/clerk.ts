import { svix } from './svix.js';
import type { ProviderVerifier } from '../types.js';

/**
 * Clerk webhook verification
 *
 * Clerk uses Svix for webhook delivery, so the verification is identical.
 * Headers: svix-id, svix-timestamp, svix-signature
 *
 * @see https://clerk.com/docs/integrations/webhooks/sync-data
 */
export const clerk: ProviderVerifier = {
  verify(payload, signature, secret, options?) {
    // Clerk uses Svix under the hood
    return svix.verify(payload, signature, secret, options);
  },
};
