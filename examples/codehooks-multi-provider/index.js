/**
 * Multi-Provider Webhook Handler for Codehooks.io
 *
 * Handle webhooks from multiple providers in a single deployment.
 *
 * Deploy with: coho deploy
 *
 * Set your secrets:
 *   coho set-env STRIPE_WEBHOOK_SECRET whsec_xxxxx
 *   coho set-env GITHUB_WEBHOOK_SECRET your_github_secret
 *   coho set-env SLACK_SIGNING_SECRET your_slack_secret
 */

import { app, Datastore } from 'codehooks-js';
import { verify, getSignature } from 'webhook-verify';

// Stripe webhooks
app.post('/webhooks/stripe', async (req, res) => {
  // Pass headers directly - throws if signature header is missing
  const isValid = verify('stripe', req.rawBody, req.headers, process.env.STRIPE_WEBHOOK_SECRET);

  if (!isValid) {
    return res.status(401).json({ error: 'Invalid signature' });
  }

  const event = JSON.parse(req.rawBody);
  await logWebhook('stripe', event.type, event);

  res.json({ received: true });
});

// GitHub webhooks
app.post('/webhooks/github', async (req, res) => {
  // Pass headers directly - throws if signature header is missing
  const isValid = verify('github', req.rawBody, req.headers, process.env.GITHUB_WEBHOOK_SECRET);

  if (!isValid) {
    return res.status(401).json({ error: 'Invalid signature' });
  }

  // Use getSignature() if you need the event type
  const sig = getSignature('github', req.headers);
  const payload = JSON.parse(req.rawBody);
  await logWebhook('github', sig.eventType, payload);

  res.json({ received: true });
});

// Slack webhooks
app.post('/webhooks/slack', async (req, res) => {
  // Pass headers directly - signature and timestamp handled automatically
  const isValid = verify('slack', req.rawBody, req.headers, process.env.SLACK_SIGNING_SECRET);

  if (!isValid) {
    return res.status(401).json({ error: 'Invalid signature' });
  }

  const payload = JSON.parse(req.rawBody);

  // Handle Slack URL verification challenge
  if (payload.type === 'url_verification') {
    return res.json({ challenge: payload.challenge });
  }

  await logWebhook('slack', payload.event?.type || 'unknown', payload);

  res.json({ received: true });
});

// Helper to log webhooks to database
async function logWebhook(provider, eventType, payload) {
  const conn = await Datastore.open();
  await conn.insertOne('webhooks', {
    provider,
    eventType,
    payload,
    receivedAt: new Date().toISOString(),
  });
  console.log(`[${provider}] ${eventType}`);
}

// API to view recent webhooks
app.get('/webhooks/recent', async (req, res) => {
  const conn = await Datastore.open();
  const webhooks = await conn.getMany('webhooks', {
    sort: { _id: -1 },
    limit: 20,
  }).toArray();
  res.json(webhooks);
});

export default app.init();
