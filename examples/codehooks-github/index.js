/**
 * GitHub Webhook Handler for Codehooks.io
 *
 * Deploy with: coho deploy
 *
 * Set your webhook secret:
 *   coho set-env GITHUB_WEBHOOK_SECRET your_secret_here
 */

import { app, Datastore } from 'codehooks-js';
import { verify, getSignature } from 'webhook-verify';

// GitHub webhook endpoint
app.post('/webhooks/github', async (req, res) => {
  // Pass headers directly - signature extracted automatically
  // Throws if x-hub-signature-256 header is missing
  const isValid = verify('github', req.rawBody, req.headers, process.env.GITHUB_WEBHOOK_SECRET);

  if (!isValid) {
    console.error('Invalid GitHub signature');
    return res.status(401).json({ error: 'Invalid signature' });
  }

  // Use getSignature() to access event type and other metadata
  const sig = getSignature('github', req.headers);
  const deliveryId = req.headers['x-github-delivery'];

  // Parse the verified payload
  const payload = JSON.parse(req.rawBody);
  console.log(`Received GitHub event: ${sig.eventType} (${deliveryId})`);

  // Store the event
  const conn = await Datastore.open();
  await conn.insertOne('github_events', {
    deliveryId,
    event: sig.eventType,
    action: payload.action,
    repository: payload.repository?.full_name,
    sender: payload.sender?.login,
    receivedAt: new Date().toISOString(),
  });

  // Handle specific events
  switch (sig.eventType) {
    case 'push':
      console.log(`Push to ${payload.ref} by ${payload.pusher?.name}`);
      console.log(`Commits: ${payload.commits?.length || 0}`);
      break;

    case 'pull_request':
      console.log(`PR ${payload.action}: #${payload.number} - ${payload.pull_request?.title}`);
      break;

    case 'issues':
      console.log(`Issue ${payload.action}: #${payload.issue?.number} - ${payload.issue?.title}`);
      break;

    case 'star':
      console.log(`Repository ${payload.action === 'created' ? 'starred' : 'unstarred'} by ${payload.sender?.login}`);
      break;

    default:
      console.log(`Unhandled event: ${sig.eventType}`);
  }

  res.json({ received: true, event: sig.eventType, deliveryId });
});

export default app.init();
