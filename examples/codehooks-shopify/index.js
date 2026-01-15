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
  // Pass headers directly - signature extracted automatically
  // Throws if x-shopify-hmac-sha256 header is missing
  const isValid = verify('shopify', req.rawBody, req.headers, process.env.SHOPIFY_WEBHOOK_SECRET);

  if (!isValid) {
    console.error('Invalid Shopify signature');
    return res.status(401).json({ error: 'Invalid signature' });
  }

  // Use getSignature() to access topic (event type)
  const sig = getSignature('shopify', req.headers);
  const shopDomain = req.headers['x-shopify-shop-domain'];

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
