/**
 * GitHub Webhook Handler for Codehooks.io
 *
 * Deploy with: coho deploy
 *
 * Set your webhook secret:
 *   coho set-env GITHUB_WEBHOOK_SECRET your_secret_here
 */

import { app, Datastore } from 'codehooks-js';
import { verify } from 'webhook-verify';

// GitHub webhook endpoint
app.post('/webhooks/github', async (req, res) => {
  const isValid = verify('github', req.rawBody, req.headers, process.env.GITHUB_WEBHOOK_SECRET);

  if (!isValid) {
    return res.status(401).json({ error: 'Invalid signature' });
  }

  // Access event info directly from headers
  const event = req.headers['x-github-event'];
  const deliveryId = req.headers['x-github-delivery'];

  const payload = JSON.parse(req.rawBody);
  console.log(`Received GitHub event: ${event} (${deliveryId})`);

  // Store the event
  const conn = await Datastore.open();
  await conn.insertOne('github_events', {
    deliveryId,
    event,
    action: payload.action,
    repository: payload.repository?.full_name,
    sender: payload.sender?.login,
    receivedAt: new Date().toISOString(),
  });

  // Handle specific events
  switch (event) {
    case 'push':
      console.log(`Push to ${payload.ref} by ${payload.pusher?.name}`);
      break;

    case 'pull_request':
      console.log(`PR ${payload.action}: #${payload.number} - ${payload.pull_request?.title}`);
      break;

    case 'issues':
      console.log(`Issue ${payload.action}: #${payload.issue?.number} - ${payload.issue?.title}`);
      break;

    default:
      console.log(`Unhandled event: ${event}`);
  }

  res.json({ received: true });
});

export default app.init();
