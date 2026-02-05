# Stripe → Keygen Webhook Setup

This webhook automatically creates Keygen licenses when customers pay via Stripe.

## Prerequisites

- Stripe account with products created
- Keygen account (already set up)
- Server to host the webhook (or use Cloudflare Tunnel)

## Step 1: Create Stripe Products

1. Go to [Stripe Dashboard](https://dashboard.stripe.com/products)
2. Create products:
   - **Agent Guard Pro** — $49/month recurring
   - **Agent Guard Team** — $199/month recurring
3. Note the **Price IDs** (e.g., `price_1Abc...`)

## Step 2: Create Stripe Webhook

1. Go to [Stripe Webhooks](https://dashboard.stripe.com/webhooks)
2. Click **Add endpoint**
3. URL: `https://your-domain.com/webhooks/stripe`
4. Events to send:
   - `checkout.session.completed`
   - `customer.subscription.deleted`
   - `customer.subscription.paused`
   - `customer.subscription.resumed`
   - `invoice.payment_failed`
5. Copy the **Webhook Signing Secret** (`whsec_...`)

## Step 3: Get Keygen Admin Token

1. Go to [Keygen Dashboard](https://app.keygen.sh) → Settings → API Tokens
2. Create a new **Admin token**
3. Copy the token

## Step 4: Configure Environment

```bash
export STRIPE_SECRET_KEY="sk_live_..."
export STRIPE_WEBHOOK_SECRET="whsec_..."
export KEYGEN_ACCOUNT="musashimiyamoto1"
export KEYGEN_ADMIN_TOKEN="admin-..."
```

## Step 5: Update Policy Mapping

Edit `stripe-keygen.js` and update the `POLICY_MAP`:

```javascript
const POLICY_MAP = {
  'price_YOUR_PRO_PRICE_ID': 'eb7ed7a4-3bf1-49b6-a745-249018ddbc24',  // Pro
  'price_YOUR_TEAM_PRICE_ID': 'YOUR_TEAM_POLICY_ID',                   // Team
};
```

## Step 6: Deploy

### Option A: Standalone server
```bash
cd webhooks
npm install
npm start
```

### Option B: Add to existing dashboard
Add the route to `review-dashboard/server.js`:
```javascript
import './stripe-keygen.js';
```

### Option C: Cloudflare Tunnel (recommended)
```bash
# Start webhook server
npm start

# In another terminal, expose via tunnel
cloudflared tunnel --url http://localhost:3847
```

## Step 7: Create Stripe Checkout Links

1. Go to Stripe Dashboard → Products → Your Product
2. Click **Create payment link**
3. Configure and copy the link
4. Update `agentguard-site/pro.html` with the links

## Testing

1. Use Stripe test mode first
2. Make a test purchase
3. Check Keygen dashboard for new license
4. Verify license works: `npx agent-guard license activate TEST-KEY`

## Flow

```
Customer → agentguard.co/pro → Stripe Checkout → Payment
                                      ↓
                              Stripe Webhook
                                      ↓
                              stripe-keygen.js
                                      ↓
                              Keygen API (create license)
                                      ↓
                              License key emailed to customer
```

## Troubleshooting

- **No license created**: Check webhook logs, verify policy mapping
- **Signature error**: Verify `STRIPE_WEBHOOK_SECRET` is correct
- **Keygen error**: Check admin token permissions
