// Stripe → Keygen Webhook
// Creates/suspends licenses automatically based on Stripe events
// Deploy: node stripe-keygen.js (or add to existing Express app)

import Stripe from 'stripe';
import express from 'express';

const app = express();

// Config - set these environment variables
const STRIPE_SECRET = process.env.STRIPE_SECRET_KEY;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
const KEYGEN_ACCOUNT = process.env.KEYGEN_ACCOUNT || 'musashimiyamoto1';
const KEYGEN_ADMIN_TOKEN = process.env.KEYGEN_ADMIN_TOKEN;

// Policy mapping: Stripe Price ID → Keygen Policy ID
const POLICY_MAP = {
  // Update these after creating Stripe products
  'price_pro_monthly': 'eb7ed7a4-3bf1-49b6-a745-249018ddbc24',  // Pro policy
  'price_team_monthly': 'YOUR_TEAM_POLICY_ID',                   // Team policy
};

const stripe = new Stripe(STRIPE_SECRET);

// Keygen API helper
async function keygenRequest(method, path, body = null) {
  const res = await fetch(`https://api.keygen.sh/v1/accounts/${KEYGEN_ACCOUNT}${path}`, {
    method,
    headers: {
      'Authorization': `Bearer ${KEYGEN_ADMIN_TOKEN}`,
      'Content-Type': 'application/vnd.api+json',
      'Accept': 'application/vnd.api+json',
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  return res.json();
}

// Create license for a customer
async function createLicense(email, policyId, stripeCustomerId, stripeSubscriptionId) {
  const result = await keygenRequest('POST', '/licenses', {
    data: {
      type: 'licenses',
      attributes: {
        name: `License for ${email}`,
        metadata: {
          stripeCustomerId,
          stripeSubscriptionId,
          email,
        }
      },
      relationships: {
        policy: {
          data: { type: 'policies', id: policyId }
        }
      }
    }
  });
  
  if (result.data?.attributes?.key) {
    console.log(`✓ License created: ${result.data.attributes.key} for ${email}`);
    return result.data;
  } else {
    console.error('License creation failed:', result.errors);
    return null;
  }
}

// Suspend license by Stripe subscription ID
async function suspendLicense(stripeSubscriptionId) {
  // Find license by metadata
  const licenses = await keygenRequest('GET', 
    `/licenses?metadata[stripeSubscriptionId]=${stripeSubscriptionId}`);
  
  if (licenses.data?.[0]) {
    const licenseId = licenses.data[0].id;
    await keygenRequest('POST', `/licenses/${licenseId}/actions/suspend`);
    console.log(`✓ License suspended: ${licenseId}`);
    return true;
  }
  console.log(`No license found for subscription ${stripeSubscriptionId}`);
  return false;
}

// Reinstate license by Stripe subscription ID
async function reinstateLicense(stripeSubscriptionId) {
  const licenses = await keygenRequest('GET',
    `/licenses?metadata[stripeSubscriptionId]=${stripeSubscriptionId}`);
  
  if (licenses.data?.[0]) {
    const licenseId = licenses.data[0].id;
    await keygenRequest('POST', `/licenses/${licenseId}/actions/reinstate`);
    console.log(`✓ License reinstated: ${licenseId}`);
    return true;
  }
  return false;
}

// Raw body for Stripe signature verification
app.post('/webhooks/stripe', 
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;

    try {
      event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
    } catch (err) {
      console.error('Webhook signature verification failed:', err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    console.log(`Received: ${event.type}`);

    try {
      switch (event.type) {
        case 'checkout.session.completed': {
          const session = event.data.object;
          if (session.mode === 'subscription' && session.subscription) {
            // Get subscription details
            const subscription = await stripe.subscriptions.retrieve(session.subscription);
            const priceId = subscription.items.data[0]?.price?.id;
            const policyId = POLICY_MAP[priceId];
            
            if (policyId) {
              await createLicense(
                session.customer_email,
                policyId,
                session.customer,
                session.subscription
              );
            } else {
              console.log(`No policy mapped for price ${priceId}`);
            }
          }
          break;
        }

        case 'customer.subscription.deleted':
        case 'customer.subscription.paused': {
          const subscription = event.data.object;
          await suspendLicense(subscription.id);
          break;
        }

        case 'customer.subscription.resumed': {
          const subscription = event.data.object;
          await reinstateLicense(subscription.id);
          break;
        }

        case 'invoice.payment_failed': {
          const invoice = event.data.object;
          if (invoice.subscription) {
            console.log(`Payment failed for subscription ${invoice.subscription}`);
            // Optional: suspend after grace period
          }
          break;
        }
      }
    } catch (err) {
      console.error('Webhook handler error:', err);
    }

    res.json({ received: true });
  }
);

// Health check
app.get('/health', (req, res) => res.json({ status: 'ok' }));

const PORT = process.env.PORT || 3847;
app.listen(PORT, () => {
  console.log(`Stripe-Keygen webhook listening on port ${PORT}`);
});
