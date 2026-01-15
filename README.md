# webhook-verify

[![npm version](https://img.shields.io/npm/v/webhook-verify.svg)](https://www.npmjs.com/package/webhook-verify)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Works with Codehooks.io](https://img.shields.io/badge/works%20with-codehooks.io-blue)](https://codehooks.io)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](https://www.npmjs.com/package/webhook-verify)

Verify webhooks from popular services with zero dependencies. A unified API for webhook signature verification.

Built and maintained by [Codehooks.io](https://codehooks.io) - the serverless backend platform.

## Installation

```bash
npm install webhook-verify
```

## Quick Start

```typescript
import { verify } from 'webhook-verify';

// In your webhook handler
const isValid = verify('stripe', rawBody, signature, webhookSecret);

if (!isValid) {
  return res.status(401).send('Invalid signature');
}
```

> **Important:** You must use the **raw request body** (exact bytes) for verification. Parsed JSON won't work because signatures are computed over the original bytes. See [Raw Body Handling](#raw-body-handling) for setup instructions.

## Supported Providers

| Provider | Header | Method |
|----------|--------|--------|
| Stripe | `Stripe-Signature` | HMAC-SHA256 + timestamp |
| GitHub | `X-Hub-Signature-256` | HMAC-SHA256 |
| Shopify | `X-Shopify-Hmac-Sha256` | HMAC-SHA256 (base64) |
| Slack | `X-Slack-Signature` | HMAC-SHA256 + timestamp |
| Twilio | `X-Twilio-Signature` | HMAC-SHA1 |
| Discord | `X-Signature-Ed25519` | Ed25519 |
| Linear | `Linear-Signature` | HMAC-SHA256 |
| Vercel | `x-vercel-signature` | HMAC-SHA1 |
| Svix | `svix-signature` | HMAC-SHA256 + timestamp |
| Clerk | `svix-signature` | HMAC-SHA256 (Svix) |
| SendGrid | `X-Twilio-Email-Event-Webhook-Signature` | ECDSA |
| Paddle | `Paddle-Signature` | RSA-SHA256 |
| Intercom | `X-Hub-Signature` | HMAC-SHA1 |
| Mailchimp | `X-Mailchimp-Signature` | HMAC-SHA256 (base64) |
| GitLab | `X-Gitlab-Token` | Token comparison |
| Typeform | `Typeform-Signature` | HMAC-SHA256 (base64) |

## API

### `verify(provider, payload, signature, secret, options?)`

Verify a webhook signature.

```typescript
function verify(
  provider: Provider,
  payload: string | Buffer,
  signature: string,
  secret: string,
  options?: VerifyOptions
): boolean;
```

**Parameters:**
- `provider` - The webhook provider name
- `payload` - The raw request body (string or Buffer)
- `signature` - The signature from the webhook header
- `secret` - The webhook secret, API key, or public key
- `options` - Provider-specific options

**Returns:** `true` if the signature is valid, `false` otherwise

### `getSupportedProviders()`

Returns an array of all supported provider names.

### `isProviderSupported(provider)`

Check if a provider is supported.

### `getSignature(provider, headers)`

Extract signature data from request headers. Returns a `SignatureData` object or `null` if required headers are missing.

```typescript
import { verify, getSignature } from 'webhook-verify';

// Automatically extracts and formats the signature
const sig = getSignature('stripe', req.headers);

if (!sig) {
  return res.status(400).send('Missing signature headers');
}

// sig.signature is ready to use with verify()
const isValid = verify('stripe', req.rawBody, sig.signature, secret);
```

The helper handles:
- Case-insensitive header lookup
- Combining multiple headers (e.g., Slack's signature + timestamp)
- Extracting event types when available

**SignatureData object:**
```typescript
{
  signature: string;      // Formatted for verify()
  rawSignature?: string;  // Original header value
  timestamp?: string;     // For providers with timestamps
  messageId?: string;     // For Svix-based providers
  eventType?: string;     // Event type (GitHub, Shopify, etc.)
}
```

### `getHeaderNames(provider)`

Get the expected header names for a provider (useful for documentation or debugging).

```typescript
import { getHeaderNames } from 'webhook-verify';

getHeaderNames('slack');
// { signature: 'x-slack-signature', timestamp: 'x-slack-request-timestamp' }
```

## Raw Body Handling

Webhook signatures are computed over the **exact bytes** sent by the provider. You must use the raw, unparsed request body - not `JSON.parse(body)` or similar.

### Codehooks.io

Codehooks.io provides `req.rawBody` automatically:

```typescript
import { app } from 'codehooks-js';
import { verify } from 'webhook-verify';

app.post('/webhook', async (req, res) => {
  const signature = req.headers['x-signature'];

  // ✅ Use req.rawBody (the raw bytes)
  const isValid = verify('github', req.rawBody, signature, secret);

  // ❌ Don't use req.body (parsed JSON)
  // const isValid = verify('github', JSON.stringify(req.body), signature, secret);
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
app.post('/webhook/stripe',
  express.raw({ type: 'application/json' }),
  (req, res) => {
    // req.body is a Buffer containing the raw bytes
    const isValid = verify('stripe', req.body, req.headers['stripe-signature'], secret);
  }
);

// For other routes, you can still use JSON parsing
app.use(express.json());
```

### Why Raw Body Matters

```typescript
// Original webhook payload from provider
'{"id":123,"name":"test"}'

// After JSON.parse() + JSON.stringify()
'{"id":123,"name":"test"}'  // Might look the same...

// But sometimes:
'{"name":"test","id":123}'  // Key order changed!
'{ "id": 123, "name": "test" }'  // Whitespace changed!

// The signature won't match because the bytes are different
```

## Provider Examples

### Stripe

```typescript
import { verify, getSignature } from 'webhook-verify';

app.post('/webhook/stripe', express.raw({ type: 'application/json' }), (req, res) => {
  // Extracts: stripe-signature header
  const sig = getSignature('stripe', req.headers);
  if (!sig) return res.status(400).send('Missing signature');

  const isValid = verify('stripe', req.body, sig.signature, process.env.STRIPE_WEBHOOK_SECRET);

  if (!isValid) {
    return res.status(400).send('Invalid signature');
  }

  // Process webhook...
  res.sendStatus(200);
});
```

### GitHub

```typescript
import { verify, getSignature } from 'webhook-verify';

app.post('/webhook/github', express.raw({ type: 'application/json' }), (req, res) => {
  // Extracts: x-hub-signature-256, x-github-event headers
  const sig = getSignature('github', req.headers);
  if (!sig) return res.status(400).send('Missing signature');

  const isValid = verify('github', req.body, sig.signature, process.env.GITHUB_WEBHOOK_SECRET);

  if (!isValid) {
    return res.status(401).send('Invalid signature');
  }

  console.log(`Event type: ${sig.eventType}`); // e.g., "push", "pull_request"
  // Process webhook...
});
```

### Shopify

```typescript
import { verify, getSignature } from 'webhook-verify';

app.post('/webhook/shopify', express.raw({ type: 'application/json' }), (req, res) => {
  // Extracts: x-shopify-hmac-sha256, x-shopify-topic headers
  const sig = getSignature('shopify', req.headers);
  if (!sig) return res.status(400).send('Missing signature');

  const isValid = verify('shopify', req.body, sig.signature, process.env.SHOPIFY_WEBHOOK_SECRET);

  if (!isValid) {
    return res.status(401).send('Invalid signature');
  }

  console.log(`Topic: ${sig.eventType}`); // e.g., "orders/create"
  // Process webhook...
});
```

### Slack

```typescript
import { verify, getSignature } from 'webhook-verify';

app.post('/webhook/slack', express.raw({ type: 'application/x-www-form-urlencoded' }), (req, res) => {
  // Extracts: x-slack-signature, x-slack-request-timestamp headers
  // Combines them automatically into the format verify() expects
  const sig = getSignature('slack', req.headers);
  if (!sig) return res.status(400).send('Missing signature');

  const isValid = verify('slack', req.body, sig.signature, process.env.SLACK_SIGNING_SECRET);

  if (!isValid) {
    return res.status(401).send('Invalid signature');
  }

  // Process webhook...
});
```

### Twilio

```typescript
import { verify, getSignature } from 'webhook-verify';

app.post('/webhook/twilio', express.urlencoded({ extended: false }), (req, res) => {
  // Extracts: x-twilio-signature header
  const sig = getSignature('twilio', req.headers);
  if (!sig) return res.status(400).send('Missing signature');

  // Twilio requires the full URL for verification
  const url = `https://${req.headers.host}${req.originalUrl}`;
  const isValid = verify('twilio', req.body, sig.signature, process.env.TWILIO_AUTH_TOKEN, { url });

  if (!isValid) {
    return res.status(401).send('Invalid signature');
  }

  // Process webhook...
});
```

### Discord

```typescript
import { verify, getSignature } from 'webhook-verify';

app.post('/webhook/discord', express.raw({ type: 'application/json' }), (req, res) => {
  // Extracts: x-signature-ed25519, x-signature-timestamp headers
  // Combines them automatically for Ed25519 verification
  const sig = getSignature('discord', req.headers);
  if (!sig) return res.status(400).send('Missing signature');

  const isValid = verify('discord', req.body, sig.signature, process.env.DISCORD_PUBLIC_KEY);

  if (!isValid) {
    return res.status(401).send('Invalid signature');
  }

  // Process interaction...
});
```

### Svix / Clerk

```typescript
import { verify, getSignature } from 'webhook-verify';

app.post('/webhook/clerk', express.raw({ type: 'application/json' }), (req, res) => {
  // Extracts: svix-signature, svix-timestamp, svix-id headers
  // Combines them automatically into the format verify() expects
  const sig = getSignature('clerk', req.headers);
  if (!sig) return res.status(400).send('Missing signature');

  const isValid = verify('clerk', req.body, sig.signature, process.env.CLERK_WEBHOOK_SECRET);

  if (!isValid) {
    return res.status(401).send('Invalid signature');
  }

  console.log(`Message ID: ${sig.messageId}`);
  // Process webhook...
});
```

### GitLab

```typescript
import { verify, getSignature } from 'webhook-verify';

app.post('/webhook/gitlab', express.json(), (req, res) => {
  // Extracts: x-gitlab-token, x-gitlab-event headers
  const sig = getSignature('gitlab', req.headers);
  if (!sig) return res.status(400).send('Missing token');

  const isValid = verify('gitlab', '', sig.signature, process.env.GITLAB_WEBHOOK_SECRET);

  if (!isValid) {
    return res.status(401).send('Invalid token');
  }

  console.log(`Event: ${sig.eventType}`); // e.g., "Push Hook"
  // Process webhook...
});
```

## Codehooks.io Example

```typescript
import { app } from 'codehooks-js';
import { verify, getSignature } from 'webhook-verify';

app.post('/webhook/stripe', async (req, res) => {
  // Extracts: stripe-signature header
  const sig = getSignature('stripe', req.headers);
  if (!sig) {
    return res.status(400).json({ error: 'Missing signature' });
  }

  // Always use req.rawBody for signature verification
  const isValid = verify('stripe', req.rawBody, sig.signature, process.env.STRIPE_WEBHOOK_SECRET);

  if (!isValid) {
    return res.status(400).json({ error: 'Invalid signature' });
  }

  // Parse the verified payload
  const event = JSON.parse(req.rawBody);
  // Process event...

  res.json({ received: true });
});

export default app.init();
```

## Options

### Timestamp Tolerance

For providers that include timestamps (Stripe, Slack, Svix), you can customize the tolerance window:

```typescript
// Allow signatures up to 10 minutes old (default is 5 minutes)
verify('stripe', payload, signature, secret, { tolerance: 600 });
```

### Twilio URL

Twilio requires the full webhook URL for verification:

```typescript
verify('twilio', payload, signature, secret, { url: 'https://example.com/webhook' });
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
  algorithm: 'sha256',  // 'sha1' | 'sha256' | 'sha512'
  encoding: 'hex',      // 'hex' | 'base64'
  prefix: 'sha256=',    // Strip prefix from signature
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
  tolerance: 300,  // Max age in seconds
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
app.post('/webhook/custom', express.raw({ type: 'application/json' }), (req, res) => {
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
});
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

| Provider | Reason | Alternative |
|----------|--------|-------------|
| PayPal | Requires async certificate fetch and chain validation | Use [@paypal/paypal-server-sdk](https://www.npmjs.com/package/@paypal/paypal-server-sdk) |
| AWS SNS | Requires async certificate fetch | Use [aws-sdk](https://www.npmjs.com/package/aws-sdk) |

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

## License

MIT

---

Made with care by [Codehooks.io](https://codehooks.io)
