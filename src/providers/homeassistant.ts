import { secureCompare } from '../utils/crypto.js';
import type { ProviderVerifier } from '../types.js';

/**
 * Home Assistant webhook verification
 *
 * Home Assistant uses a simple secret token comparison via X-HA-Secret header.
 * The signature parameter should contain the token from the header.
 *
 * Home Assistant Configuration Example:
 * ```yaml
 * rest_command:
 *   send_event:
 *     url: "https://your-webhook-url.com/ha/event"
 *     method: POST
 *     headers:
 *       X-HA-Secret: "your-shared-secret"
 *     content_type: "application/json"
 *     payload: '{"entity_id": "{{ entity_id }}", "state": "{{ state }}"}'
 * ```
 *
 * @see https://www.home-assistant.io/integrations/rest_command/
 */
export const homeassistant: ProviderVerifier = {
  verify(_payload, signature, secret) {
    if (!signature || !secret) {
      return false;
    }

    // Home Assistant simply compares the token from the header with the secret
    return secureCompare(signature, secret);
  },
};
