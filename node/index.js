import express from 'express';
import crypto from 'crypto';
import * as dotenv from 'dotenv';

dotenv.config();

const app = express();

const CLIENT_ID = process.env.SHOPIFY_CLIENT_ID;
const CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;
const SCOPES = process.env.SCOPES || 'read_products,write_orders';

// In-memory nonce store (use a database in production)
const nonces = new Set();

// [START oauth.build-authorization-url]
app.get('/install', (req, res) => {
  const { shop } = req.query;
  const nonce = crypto.randomBytes(16).toString('hex');
  nonces.add(nonce);

  const authUrl = `https://${shop}/admin/oauth/authorize?` +
    new URLSearchParams({
      client_id: CLIENT_ID,
      scope: SCOPES,
      redirect_uri: REDIRECT_URI,
      state: nonce,
    });

  res.redirect(authUrl);
});
// [END oauth.build-authorization-url]

app.get('/callback', async (req, res) => {
  const { code, hmac, shop, state } = req.query;

  // [START oauth.validate-state]
  if (!nonces.has(state)) return res.status(403).send('Invalid state parameter');
  nonces.delete(state);
  // [END oauth.validate-state]

  // [START oauth.verify-hmac]
  const params = Object.fromEntries(
    Object.entries(req.query).filter(([key]) => key !== 'hmac')
  );
  const message = new URLSearchParams(Object.entries(params).sort()).toString();
  const digest = crypto.createHmac('sha256', CLIENT_SECRET).update(message).digest('hex');
  if (!crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(hmac))) {
    return res.status(403).send('Invalid HMAC');
  }
  // [END oauth.verify-hmac]

  // [START oauth.validate-shop]
  if (!/^[a-zA-Z0-9][a-zA-Z0-9\-]*\.myshopify\.com$/.test(shop)) {
    return res.status(400).send('Invalid shop domain');
  }
  // [END oauth.validate-shop]

  // [START oauth.exchange-code]
  const tokenResponse = await fetch(`https://${shop}/admin/oauth/access_token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: new URLSearchParams({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      code,
      expiring: '1',
    }),
  });

  const { access_token, scope } = await tokenResponse.json();
  // [END oauth.exchange-code]

  // [START oauth.confirm-scopes]
  const missing = SCOPES.split(',').filter(s => !scope.split(',').includes(s));
  if (missing.length > 0) return res.status(403).send(`Missing scopes: ${missing.join(', ')}`);
  // [END oauth.confirm-scopes]

  // Store access_token securely — omitted for brevity
  res.json({ message: 'App installed', shop, scope });
});

// [START oauth.make-request]
app.get('/products', async (req, res) => {
  const { shop, access_token } = req.query;

  const response = await fetch(`https://${shop}/admin/api/2026-04/graphql.json`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Shopify-Access-Token': access_token,
    },
    body: JSON.stringify({ query: '{ products(first: 5) { edges { node { id handle } } } }' }),
  });

  res.json(await response.json());
});
// [END oauth.make-request]

app.listen(3000, () => console.log('Server running on http://localhost:3000'));
