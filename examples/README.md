# Codehooks.io Webhook Examples

Ready-to-deploy webhook handlers for [Codehooks.io](https://codehooks.io).

## Prerequisites

1. Install the Codehooks CLI:
   ```bash
   npm install -g codehooks
   ```

2. Create a Codehooks.io account at [codehooks.io](https://codehooks.io)

3. Login to the CLI:
   ```bash
   coho login
   ```

## Examples

### Stripe Webhooks

Handle Stripe payment events like successful payments, subscriptions, and failed invoices.

```bash
cd codehooks-stripe
npm init -y
npm install codehooks-js webhook-verify
coho create stripe-webhooks
coho set-env STRIPE_WEBHOOK_SECRET whsec_your_secret_here
coho deploy
```

### GitHub Webhooks

Process GitHub events like pushes, pull requests, issues, and stars.

```bash
cd codehooks-github
npm init -y
npm install codehooks-js webhook-verify
coho create github-webhooks
coho set-env GITHUB_WEBHOOK_SECRET your_secret_here
coho deploy
```

### Shopify Webhooks

Handle Shopify store events like orders, products, and customer updates.

```bash
cd codehooks-shopify
npm init -y
npm install codehooks-js webhook-verify
coho create shopify-webhooks
coho set-env SHOPIFY_WEBHOOK_SECRET your_secret_here
coho deploy
```

### Multi-Provider

Handle webhooks from multiple providers (Stripe, GitHub, Slack) in a single deployment.

```bash
cd codehooks-multi-provider
npm init -y
npm install codehooks-js webhook-verify
coho create multi-webhooks
coho set-env STRIPE_WEBHOOK_SECRET whsec_xxx
coho set-env GITHUB_WEBHOOK_SECRET xxx
coho set-env SLACK_SIGNING_SECRET xxx
coho deploy
```

## Getting Your Webhook URL

After deploying, get your webhook URL:

```bash
coho info
```

Your webhook endpoints will be:
- `https://your-project-xxxx.api.codehooks.io/dev/webhooks/stripe`
- `https://your-project-xxxx.api.codehooks.io/dev/webhooks/github`
- etc.

## Testing Webhooks

Use the [Codehooks.io dashboard](https://codehooks.io) to view logs and debug webhook deliveries.

## Learn More

- [Codehooks.io Documentation](https://codehooks.io/docs)
- [webhook-verify Documentation](https://github.com/nicedoc/webhook-verify)
- [Webhook Security Best Practices](https://codehooks.io/blog/securing-webhooks)
