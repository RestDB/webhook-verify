/**
 * Shopify Webhook Handler for Codehooks.io
 *
 * Deploy with: coho deploy
 *
 * Set your webhook secret:
 *   coho set-env SHOPIFY_WEBHOOK_SECRET your_secret_here
 */

import { app, Datastore } from 'codehooks-js';
import { verify, getSignature } from 'webhook-verify';

// Shopify webhook endpoint
app.post('/webhooks/shopify', async (req, res) => {
  // Extracts: x-shopify-hmac-sha256, x-shopify-topic headers
  const sig = getSignature('shopify', req.headers);
  if (!sig) {
    console.error('Missing Shopify signature header');
    return res.status(400).json({ error: 'Missing signature' });
  }

  const shopDomain = req.headers['x-shopify-shop-domain'];
  const secret = process.env.SHOPIFY_WEBHOOK_SECRET;

  // Verify the webhook signature
  if (!verify('shopify', req.rawBody, sig.signature, secret)) {
    console.error('Invalid Shopify signature');
    return res.status(401).json({ error: 'Invalid signature' });
  }

  // Parse the verified payload
  const payload = JSON.parse(req.rawBody);
  console.log(`Received Shopify webhook: ${sig.eventType} from ${shopDomain}`);

  // Store the event
  const conn = await Datastore.open();
  await conn.insertOne('shopify_events', {
    topic: sig.eventType,
    shopDomain,
    payload,
    receivedAt: new Date().toISOString(),
  });

  // Handle specific topics
  switch (sig.eventType) {
    case 'orders/create':
      console.log(`New order: ${payload.name} - $${payload.total_price}`);
      // Process new order
      break;

    case 'orders/paid':
      console.log(`Order paid: ${payload.name}`);
      // Handle payment confirmation
      break;

    case 'products/update':
      console.log(`Product updated: ${payload.title}`);
      // Sync product changes
      break;

    case 'customers/create':
      console.log(`New customer: ${payload.email}`);
      // Welcome new customer
      break;

    case 'app/uninstalled':
      console.log(`App uninstalled from ${shopDomain}`);
      // Cleanup shop data
      break;

    default:
      console.log(`Unhandled topic: ${sig.eventType}`);
  }

  res.json({ received: true });
});

export default app.init();
