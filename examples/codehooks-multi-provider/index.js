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
  // Extracts: stripe-signature header
  const sig = getSignature('stripe', req.headers);
  if (!sig) {
    return res.status(400).json({ error: 'Missing signature' });
  }

  if (!verify('stripe', req.rawBody, sig.signature, process.env.STRIPE_WEBHOOK_SECRET)) {
    return res.status(400).json({ error: 'Invalid signature' });
  }

  const event = JSON.parse(req.rawBody);
  await logWebhook('stripe', event.type, event);

  res.json({ received: true });
});

// GitHub webhooks
app.post('/webhooks/github', async (req, res) => {
  // Extracts: x-hub-signature-256, x-github-event headers
  const sig = getSignature('github', req.headers);
  if (!sig) {
    return res.status(400).json({ error: 'Missing signature' });
  }

  if (!verify('github', req.rawBody, sig.signature, process.env.GITHUB_WEBHOOK_SECRET)) {
    return res.status(401).json({ error: 'Invalid signature' });
  }

  const payload = JSON.parse(req.rawBody);
  await logWebhook('github', sig.eventType, payload);

  res.json({ received: true });
});

// Slack webhooks
app.post('/webhooks/slack', async (req, res) => {
  // Extracts: x-slack-signature, x-slack-request-timestamp headers
  // Combines them automatically into the format verify() expects
  const sig = getSignature('slack', req.headers);
  if (!sig) {
    return res.status(400).json({ error: 'Missing signature' });
  }

  if (!verify('slack', req.rawBody, sig.signature, process.env.SLACK_SIGNING_SECRET)) {
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
