/**
 * Shopify Webhook Handler for Codehooks.io
 *
 * Deploy with: coho deploy
 *
 * Set your webhook secret:
 *   coho set-env SHOPIFY_WEBHOOK_SECRET your_secret_here
 */

import { app, Datastore } from 'codehooks-js';
import { verify } from 'webhook-verify';

// Shopify webhook endpoint
app.post('/webhooks/shopify', async (req, res) => {
  const isValid = verify('shopify', req.rawBody, req.headers, process.env.SHOPIFY_WEBHOOK_SECRET);

  if (!isValid) {
    return res.status(401).json({ error: 'Invalid signature' });
  }

  // Access event info directly from headers
  const topic = req.headers['x-shopify-topic'];
  const shopDomain = req.headers['x-shopify-shop-domain'];

  const payload = JSON.parse(req.rawBody);
  console.log(`Received Shopify webhook: ${topic} from ${shopDomain}`);

  // Store the event
  const conn = await Datastore.open();
  await conn.insertOne('shopify_events', {
    topic,
    shopDomain,
    payload,
    receivedAt: new Date().toISOString(),
  });

  // Handle specific topics
  switch (topic) {
    case 'orders/create':
      console.log(`New order: ${payload.name} - $${payload.total_price}`);
      break;

    case 'orders/paid':
      console.log(`Order paid: ${payload.name}`);
      break;

    case 'products/update':
      console.log(`Product updated: ${payload.title}`);
      break;

    case 'customers/create':
      console.log(`New customer: ${payload.email}`);
      break;

    default:
      console.log(`Unhandled topic: ${topic}`);
  }

  res.json({ received: true });
});

export default app.init();
