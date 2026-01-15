# webhook-verify

[![npm version](https://img.shields.io/npm/v/webhook-verify.svg)](https://www.npmjs.com/package/webhook-verify)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Works with Codehooks.io](https://img.shields.io/badge/works%20with-codehooks.io-blue)](https://codehooks.io)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](https://www.npmjs.com/package/webhook-verify)

**One API for all your webhooks.** Verify signatures from Stripe, GitHub, Shopify, Slack, and 17 other providers with a single, consistent interface.

```typescript
// Same pattern for every provider
verify('stripe', payload, headers, secret);
verify('github', payload, headers, secret);
verify('shopify', payload, headers, secret);
```

**Why use this?**

- **Multi-provider apps** - Building a SaaS that receives webhooks from Stripe, GitHub, and Slack? Use one library instead of three.
- **Zero dependencies** - Just Node.js crypto. No dependency tree to audit.
- **Unified API** - Stop reading different docs for each provider's signature scheme. HMAC, Ed25519, RSA - it's all just `verify()`.
- **Key rotation built-in** - Rotate secrets without downtime using `additionalSecrets`.

Built and maintained by [Codehooks.io](https://codehooks.io) - the serverless backend platform for webhook integrations.

## Installation

```bash
npm install webhook-verify
```

## Quick Start

```typescript
import { verify } from 'webhook-verify';

// Pass headers directly - signature is extracted automatically
const isValid = verify('stripe', req.rawBody, req.headers, webhookSecret);

if (!isValid) {
  return res.status(401).send('Invalid signature');
}
```

> **Important:** You must use the **raw request body** (exact bytes) for verification. Parsed JSON won't work because signatures are computed over the original bytes. See [Raw Body Handling](#raw-body-handling) for setup instructions.

## Supported Providers

| Provider  | Header                                   | Method                  |
| --------- | ---------------------------------------- | ----------------------- |
| Stripe    | `Stripe-Signature`                       | HMAC-SHA256 + timestamp |
| GitHub    | `X-Hub-Signature-256`                    | HMAC-SHA256             |
| Shopify   | `X-Shopify-Hmac-Sha256`                  | HMAC-SHA256 (base64)    |
| Slack     | `X-Slack-Signature`                      | HMAC-SHA256 + timestamp |
| Twilio    | `X-Twilio-Signature`                     | HMAC-SHA1               |
| Discord   | `X-Signature-Ed25519`                    | Ed25519                 |
| Linear    | `Linear-Signature`                       | HMAC-SHA256             |
| Vercel    | `x-vercel-signature`                     | HMAC-SHA1               |
| Svix      | `svix-signature`                         | HMAC-SHA256 + timestamp |
| Clerk     | `svix-signature`                         | HMAC-SHA256 (Svix)      |
| SendGrid  | `X-Twilio-Email-Event-Webhook-Signature` | ECDSA                   |
| Paddle    | `Paddle-Signature`                       | RSA-SHA256              |
| Intercom  | `X-Hub-Signature`                        | HMAC-SHA1               |
| Mailchimp | `X-Mailchimp-Signature`                  | HMAC-SHA256 (base64)    |
| GitLab    | `X-Gitlab-Token`                         | Token comparison        |
| Typeform  | `Typeform-Signature`                     | HMAC-SHA256 (base64)    |
| Crystallize | `X-Crystallize-Signature`              | JWT + HMAC-SHA256       |
| Zendesk   | `X-Zendesk-Webhook-Signature`            | HMAC-SHA256 + timestamp |
| Square    | `x-square-hmacsha256-signature`          | HMAC-SHA256             |
| HubSpot   | `X-HubSpot-Signature-V3`                 | HMAC-SHA256 + timestamp |
| Segment   | `X-Signature`                            | HMAC-SHA1               |

## API

### `verify(provider, payload, signatureOrHeaders, secret, options?)`

Verify a webhook signature.

```typescript
function verify(
  provider: Provider,
  payload: string | Buffer,
  signatureOrHeaders: string | Headers,
  secret: string,
  options?: VerifyOptions
): boolean;
```

**Parameters:**

- `provider` - The webhook provider name
- `payload` - The raw request body (string or Buffer)
- `signatureOrHeaders` - Either the request headers object OR a signature string
- `secret` - The webhook secret, API key, or public key
- `options` - Provider-specific options

**Returns:** `true` if the signature is valid, `false` otherwise

**Throws:** `Error` if headers object is passed but required signature headers are missing

```typescript
import { verify } from 'webhook-verify';

// Recommended: Pass headers directly
const isValid = verify('stripe', req.rawBody, req.headers, secret);

// Also works: Pass signature string manually
const isValid = verify('stripe', req.rawBody, signatureString, secret);
```

### `getSupportedProviders()`

Returns an array of all supported provider names.

### `isProviderSupported(provider)`

Check if a provider is supported.

## Raw Body Handling

Webhook signatures are computed over the **exact bytes** sent by the provider. You must use the raw, unparsed request body - not `JSON.parse(body)` or similar.

### Codehooks.io

Codehooks.io provides `req.rawBody` automatically:

```typescript
import { app } from 'codehooks-js';
import { verify } from 'webhook-verify';

app.post('/webhook', async (req, res) => {
  // ✅ Use req.rawBody (the raw bytes)
  const isValid = verify('github', req.rawBody, req.headers, secret);

  // ❌ Don't use req.body (parsed JSON)
  // const isValid = verify('github', JSON.stringify(req.body), req.headers, secret);
});

export default app.init();
```

### Express.js / Node.js

Use `express.raw()` middleware to capture the raw body:

```typescript
import express from 'express';
import { verify } from 'webhook-verify';

const app = express();

// Apply raw body parser to webhook routes
app.post(
  '/webhook/stripe',
  express.raw({ type: 'application/json' }),
  (req, res) => {
    // req.body is a Buffer containing the raw bytes
    const isValid = verify('stripe', req.body, req.headers, secret);
  }
);

// For other routes, you can still use JSON parsing
app.use(express.json());
```

### Why Raw Body Matters

```typescript
// Original webhook payload from provider
'{"id":123,"name":"test"}';

// After JSON.parse() + JSON.stringify()
'{"id":123,"name":"test"}'; // Might look the same...

// But sometimes:
'{"name":"test","id":123}'; // Key order changed!
'{ "id": 123, "name": "test" }'; // Whitespace changed!

// The signature won't match because the bytes are different
```

## Provider Examples

### Stripe

```typescript
import { verify } from 'webhook-verify';

app.post(
  '/webhook/stripe',
  express.raw({ type: 'application/json' }),
  (req, res) => {
    const isValid = verify(
      'stripe',
      req.body,
      req.headers,
      process.env.STRIPE_WEBHOOK_SECRET
    );

    if (!isValid) {
      return res.status(401).send('Invalid signature');
    }

    const event = JSON.parse(req.body);
    // Process webhook...
  }
);
```

### GitHub

```typescript
import { verify } from 'webhook-verify';

app.post(
  '/webhook/github',
  express.raw({ type: 'application/json' }),
  (req, res) => {
    const isValid = verify(
      'github',
      req.body,
      req.headers,
      process.env.GITHUB_WEBHOOK_SECRET
    );

    if (!isValid) {
      return res.status(401).send('Invalid signature');
    }

    const event = req.headers['x-github-event']; // e.g., "push", "pull_request"
    // Process webhook...
  }
);
```

### Shopify

```typescript
import { verify } from 'webhook-verify';

app.post(
  '/webhook/shopify',
  express.raw({ type: 'application/json' }),
  (req, res) => {
    const isValid = verify(
      'shopify',
      req.body,
      req.headers,
      process.env.SHOPIFY_WEBHOOK_SECRET
    );

    if (!isValid) {
      return res.status(401).send('Invalid signature');
    }

    const topic = req.headers['x-shopify-topic']; // e.g., "orders/create"
    // Process webhook...
  }
);
```

### Slack

```typescript
import { verify } from 'webhook-verify';

app.post(
  '/webhook/slack',
  express.raw({ type: 'application/x-www-form-urlencoded' }),
  (req, res) => {
    // Slack requires both signature and timestamp - handled automatically
    const isValid = verify(
      'slack',
      req.body,
      req.headers,
      process.env.SLACK_SIGNING_SECRET
    );

    if (!isValid) {
      return res.status(401).send('Invalid signature');
    }

    // Process webhook...
  }
);
```

### Twilio

```typescript
import { verify } from 'webhook-verify';

app.post(
  '/webhook/twilio',
  express.urlencoded({ extended: false }),
  (req, res) => {
    // Twilio requires the full URL for verification
    const url = `https://${req.headers.host}${req.originalUrl}`;
    const isValid = verify(
      'twilio',
      req.body,
      req.headers,
      process.env.TWILIO_AUTH_TOKEN,
      { url }
    );

    if (!isValid) {
      return res.status(401).send('Invalid signature');
    }

    // Process webhook...
  }
);
```

### Discord

```typescript
import { verify } from 'webhook-verify';

app.post(
  '/webhook/discord',
  express.raw({ type: 'application/json' }),
  (req, res) => {
    // Discord uses Ed25519 - signature and timestamp handled automatically
    const isValid = verify(
      'discord',
      req.body,
      req.headers,
      process.env.DISCORD_PUBLIC_KEY
    );

    if (!isValid) {
      return res.status(401).send('Invalid signature');
    }

    // Process interaction...
  }
);
```

### Svix / Clerk

```typescript
import { verify } from 'webhook-verify';

app.post(
  '/webhook/clerk',
  express.raw({ type: 'application/json' }),
  (req, res) => {
    // Svix requires signature, timestamp, and message ID - handled automatically
    const isValid = verify(
      'clerk',
      req.body,
      req.headers,
      process.env.CLERK_WEBHOOK_SECRET
    );

    if (!isValid) {
      return res.status(401).send('Invalid signature');
    }

    const messageId = req.headers['svix-id'];
    // Process webhook...
  }
);
```

### GitLab

```typescript
import { verify } from 'webhook-verify';

app.post('/webhook/gitlab', express.json(), (req, res) => {
  // GitLab uses token comparison (not signature)
  const isValid = verify(
    'gitlab',
    '',
    req.headers,
    process.env.GITLAB_WEBHOOK_SECRET
  );

  if (!isValid) {
    return res.status(401).send('Invalid token');
  }

  const event = req.headers['x-gitlab-event']; // e.g., "Push Hook"
  // Process webhook...
});
```

### Crystallize

```typescript
import { verify } from 'webhook-verify';

app.post(
  '/webhook/crystallize',
  express.raw({ type: 'application/json' }),
  (req, res) => {
    // Crystallize requires the full URL for verification
    const url = `https://${req.headers.host}${req.originalUrl}`;
    const isValid = verify(
      'crystallize',
      req.body,
      req.headers,
      process.env.CRYSTALLIZE_SIGNATURE_SECRET,
      { url }
    );

    if (!isValid) {
      return res.status(401).send('Invalid signature');
    }

    // Process webhook...
  }
);
```

## Codehooks.io Example

```typescript
import { app } from 'codehooks-js';
import { verify } from 'webhook-verify';

app.post('/webhook/stripe', async (req, res) => {
  // Pass headers directly - uses req.rawBody for verification
  const isValid = verify(
    'stripe',
    req.rawBody,
    req.headers,
    process.env.STRIPE_WEBHOOK_SECRET
  );

  if (!isValid) {
    return res.status(401).json({ error: 'Invalid signature' });
  }

  const event = JSON.parse(req.rawBody);
  // Process event...

  res.json({ received: true });
});

export default app.init();
```

## Options

### Key Rotation (additionalSecrets)

When rotating webhook secrets, you need to accept both old and new secrets during a transition period. Use `additionalSecrets` to verify against multiple secrets:

```typescript
// During secret rotation, accept both new and old secrets
verify('github', payload, headers, newSecret, {
  additionalSecrets: [oldSecret],
});

// Support multiple old secrets if needed
verify('stripe', payload, headers, currentSecret, {
  additionalSecrets: [previousSecret, olderSecret],
});
```

The primary secret is tried first. If verification fails, each additional secret is tried in order until one succeeds or all fail. This works with all providers.

### Timestamp Tolerance

For providers that include timestamps (Stripe, Slack, Svix), you can customize the tolerance window:

```typescript
// Allow signatures up to 10 minutes old (default is 5 minutes)
verify('stripe', payload, signature, secret, { tolerance: 600 });
```

### Twilio URL

Twilio requires the full webhook URL for verification:

```typescript
verify('twilio', payload, signature, secret, {
  url: 'https://example.com/webhook',
});
```

### Crystallize URL

Crystallize requires the full webhook URL for verification:

```typescript
verify('crystallize', payload, signature, secret, {
  url: 'https://example.com/webhook',
});
```

### Square URL

Square requires the full webhook URL for verification:

```typescript
verify('square', payload, signature, secret, {
  url: 'https://example.com/webhook',
});
```

### HubSpot URL

HubSpot (v3) requires the full webhook URL and optionally the HTTP method:

```typescript
verify('hubspot', payload, signature, secret, {
  url: 'https://example.com/webhook',
  method: 'POST', // optional, defaults to 'POST'
});
```

## Generic Algorithm Handlers

For providers not explicitly supported, or for custom verification logic, use the generic handlers:

### HMAC Verification

```typescript
import { hmac } from 'webhook-verify';

// Basic HMAC-SHA256 verification (hex encoded)
hmac.verify(payload, signature, secret);

// With options
hmac.verify(payload, signature, secret, {
  algorithm: 'sha256', // 'sha1' | 'sha256' | 'sha512'
  encoding: 'hex', // 'hex' | 'base64'
  prefix: 'sha256=', // Strip prefix from signature
});

// Generate a signature
const sig = hmac.sign(payload, secret, { encoding: 'base64' });
```

### HMAC with Timestamp

```typescript
import { hmac } from 'webhook-verify';

// Stripe-style: signature over "timestamp.payload"
hmac.verifyWithTimestamp(payload, signature, secret, timestamp, {
  format: '{timestamp}.{payload}',
});

// Slack-style: signature over "v0:timestamp:payload"
hmac.verifyWithTimestamp(payload, signature, secret, timestamp, {
  format: 'v0:{timestamp}:{payload}',
  tolerance: 300, // Max age in seconds
});
```

### Ed25519 Verification

```typescript
import { ed25519 } from 'webhook-verify';

// Verify Ed25519 signature (e.g., Discord)
const message = timestamp + payload;
ed25519.verify(message, signature, publicKey);
```

### RSA Verification

```typescript
import { rsa } from 'webhook-verify';

// Verify RSA-SHA256 signature
rsa.verify(payload, signature, publicKey);

// With SHA1
rsa.verify(payload, signature, publicKey, { algorithm: 'RSA-SHA1' });
```

### Utility Functions

```typescript
import { timingSafeEqual, validateTimestamp } from 'webhook-verify';

// Timing-safe string comparison
timingSafeEqual(a, b);

// Validate timestamp freshness
validateTimestamp(timestamp, toleranceSeconds);
```

### Custom Provider Example (Express)

```typescript
import { hmac } from 'webhook-verify';

// Use express.raw() to get the raw body as a Buffer
app.post(
  '/webhook/custom',
  express.raw({ type: 'application/json' }),
  (req, res) => {
    const signature = req.headers['x-signature'];
    const timestamp = req.headers['x-timestamp'];

    // req.body is a Buffer when using express.raw()
    const isValid = hmac.verifyWithTimestamp(
      req.body,
      signature,
      process.env.WEBHOOK_SECRET,
      timestamp,
      {
        format: '{timestamp}:{payload}',
        algorithm: 'sha256',
        encoding: 'hex',
        tolerance: 300,
      }
    );

    if (!isValid) {
      return res.status(401).send('Invalid signature');
    }

    // Parse verified payload
    const data = JSON.parse(req.body.toString());
    // Process webhook...
  }
);
```

### Custom Provider Example (Codehooks.io)

```typescript
import { app } from 'codehooks-js';
import { hmac } from 'webhook-verify';

app.post('/webhook/custom', async (req, res) => {
  const signature = req.headers['x-signature'];
  const timestamp = req.headers['x-timestamp'];

  // Use req.rawBody for verification
  const isValid = hmac.verifyWithTimestamp(
    req.rawBody,
    signature,
    process.env.WEBHOOK_SECRET,
    timestamp,
    {
      format: '{timestamp}:{payload}',
      algorithm: 'sha256',
      encoding: 'hex',
      tolerance: 300,
    }
  );

  if (!isValid) {
    return res.status(401).json({ error: 'Invalid signature' });
  }

  const data = JSON.parse(req.rawBody);
  // Process webhook...
});

export default app.init();
```

## Unsupported Providers

Some providers use verification patterns that don't fit this library's synchronous model:

| Provider | Reason                                                | Alternative                                                                              |
| -------- | ----------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| PayPal   | Requires async certificate fetch and chain validation | Use [@paypal/paypal-server-sdk](https://www.npmjs.com/package/@paypal/paypal-server-sdk) |
| AWS SNS  | Requires async certificate fetch                      | Use [aws-sdk](https://www.npmjs.com/package/aws-sdk)                                     |

For these providers, we recommend using their official SDKs.

## Security Notes

- Always use the **raw request body** for verification (not parsed JSON)
- Use **timing-safe comparison** (this library handles this automatically)
- Keep webhook secrets secure and rotate them periodically
- Validate **timestamp freshness** to prevent replay attacks

## Requirements

- Node.js >= 18.0.0 (required for native Ed25519 support)

## Related Articles

Learn more about webhook handling and verification:

- [How to Handle Webhooks with Codehooks.io](https://codehooks.io/docs/webhooks)
- [Securing Your Webhook Endpoints](https://codehooks.io/blog/securing-webhooks)
- [Building a Stripe Integration](https://codehooks.io/blog/stripe-webhooks)

## About Codehooks.io

[Codehooks.io](https://codehooks.io) is a serverless backend platform purpose-built for webhook integrations and event-driven automations. Deploy complete webhook handlers in minutes with built-in infrastructure—no need to assemble separate services.

**Complete Webhook Infrastructure:**

- **Built-in database** - NoSQL document store for webhook events
- **Key-value store** - Redis-like caching and state management
- **Job queues** - Durable queues for async processing with automatic retries
- **Background workers** - Cron jobs and scheduled tasks
- **Signature verification** - Native `req.rawBody` support for HMAC validation

**Developer Experience:**

- Instant deployment via CLI (`coho deploy`)
- JavaScript/TypeScript with the `codehooks-js` library
- Web-based Studio for code and data management
- Flat-rate pricing with unlimited compute—no surprise bills

[Get started for free](https://codehooks.io) | [Documentation](https://codehooks.io/docs) | [Examples](https://github.com/RestDB/webhook-verify/tree/main/examples)

## Contributing

We welcome contributions, especially new provider implementations. Here's how to add support for a new webhook provider:

### Adding a New Provider

1. **Create the provider file** at `src/providers/{provider}.ts`:

```typescript
import { createHmac } from 'crypto';
import { secureCompare } from '../utils/crypto.js';
import type { ProviderVerifier } from '../types.js';

export const myprovider: ProviderVerifier = {
  verify(payload, signature, secret, options) {
    // Implement verification logic
    // Return true if valid, false otherwise
  },
};
```

2. **Register the provider** in `src/providers/index.ts`

3. **Add the provider type** to the `Provider` union in `src/types.ts`

4. **Add header extraction** in `src/headers.ts` (both `providerHeaders` and `getHeaderNames`)

5. **Add tests** in `test/verify.test.ts`

6. **Document it** in README.md (Supported Providers table + example if needed)

### Provider Checklist

- [ ] Uses timing-safe comparison for signatures
- [ ] Handles both string and Buffer payloads
- [ ] Returns `false` for invalid inputs (don't throw)
- [ ] Includes timestamp validation if the provider uses it
- [ ] Has test coverage with valid and invalid signatures

### Running Tests

```bash
npm install
npm test
npm run build
```

### Providers We'd Like to Add

- Braintree
- Customer.io
- Postmark
- Adyen
- Coinbase
- DocuSign
- ...and many more!

Check the [issues](https://github.com/RestDB/webhook-verify/issues) for provider requests or open one for a provider you'd like to see supported.

## License

MIT

---

Made with care by [Codehooks.io](https://codehooks.io)
