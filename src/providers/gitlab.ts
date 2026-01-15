import { secureCompare } from '../utils/crypto.js';
import type { ProviderVerifier } from '../types.js';

/**
 * GitLab webhook verification
 *
 * GitLab uses a simple secret token comparison via X-Gitlab-Token header.
 * The signature parameter should contain the token from the header.
 *
 * @see https://docs.gitlab.com/ee/user/project/integrations/webhooks.html#validate-payloads-by-using-a-secret-token
 */
export const gitlab: ProviderVerifier = {
  verify(_payload, signature, secret) {
    if (!signature || !secret) {
      return false;
    }

    // GitLab simply compares the token from the header with the secret
    return secureCompare(signature, secret);
  },
};
