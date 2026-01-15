/**
 * Stripe Webhook Handler for Codehooks.io
 *
 * Deploy with: coho deploy
 *
 * Set your webhook secret:
 *   coho set-env STRIPE_WEBHOOK_SECRET whsec_xxxxx
 */

import { app, Datastore } from 'codehooks-js';
import { verify } from 'webhook-verify';

// Stripe webhook endpoint
app.post('/webhooks/stripe', async (req, res) => {
  const signature = req.headers['stripe-signature'];
  const secret = process.env.STRIPE_WEBHOOK_SECRET;

  // Verify the webhook signature using raw body
  if (!verify('stripe', req.rawBody, signature, secret)) {
    console.error('Invalid Stripe signature');
    return res.status(400).json({ error: 'Invalid signature' });
  }

  // Parse the verified payload
  const event = JSON.parse(req.rawBody);
  console.log(`Received Stripe event: ${event.type}`);

  // Store the event in the database
  const conn = await Datastore.open();
  await conn.insertOne('stripe_events', {
    eventId: event.id,
    type: event.type,
    data: event.data,
    receivedAt: new Date().toISOString(),
  });

  // Handle specific event types
  switch (event.type) {
    case 'payment_intent.succeeded':
      console.log('Payment succeeded:', event.data.object.id);
      // Handle successful payment
      break;

    case 'customer.subscription.created':
      console.log('New subscription:', event.data.object.id);
      // Handle new subscription
      break;

    case 'invoice.payment_failed':
      console.log('Payment failed:', event.data.object.id);
      // Handle failed payment
      break;

    default:
      console.log(`Unhandled event type: ${event.type}`);
  }

  res.json({ received: true });
});

// Export the app
export default app.init();
