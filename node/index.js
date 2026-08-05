import express from 'express';
import crypto from 'crypto';
import cookieParser from 'cookie-parser';
import * as dotenv from 'dotenv';

dotenv.config();

// Falls back to a random secret for local dev. Set COOKIE_SECRET in production
// so signed cookies stay valid across restarts and deployments.
const COOKIE_SECRET = process.env.COOKIE_SECRET || crypto.randomBytes(64).toString('hex');

const app = express();
app.use(cookieParser(COOKIE_SECRET));

const CLIENT_ID = process.env.SHOPIFY_CLIENT_ID;
const CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;
const SCOPES = process.env.SCOPES || 'read_products,write_orders';

// In-memory token store (use a database in production)
const tokenStore = {};

// Send cookies only over HTTPS in production; over plain HTTP on localhost in dev.
const cookieOptions = {
  signed: true,
  httpOnly: true,
  sameSite: 'lax',
  secure: process.env.NODE_ENV === 'production',
};

function isValidShopDomain(shop) {
  return /^[a-zA-Z0-9][a-zA-Z0-9\-]*\.myshopify\.com$/.test(shop);
}

// [START oauth.build-authorization-url]
app.get('/install', (req, res) => {
  const { shop } = req.query;

  if (!isValidShopDomain(shop)) {
    return res.status(400).send('Invalid shop domain');
  }

  const nonce = crypto.randomBytes(16).toString('hex');
  // Store the nonce in a signed cookie so you can verify it against the callback
  res.cookie('oauth_state', nonce, cookieOptions);

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
  if (!state || state !== req.signedCookies.oauth_state) {
    return res.status(403).send('Invalid state parameter');
  }
  res.clearCookie('oauth_state');
  // [END oauth.validate-state]

  // [START oauth.verify-hmac]
  const params = Object.fromEntries(
    Object.entries(req.query).filter(([key]) => key !== 'hmac')
  );
  const message = Object.entries(params).sort().map(([k, v]) => `${k}=${v}`).join('&');
  const digest = crypto.createHmac('sha256', CLIENT_SECRET).update(message).digest('hex');
  const digestBuf = Buffer.from(digest);
  const hmacBuf = Buffer.from(String(hmac));
  if (digestBuf.length !== hmacBuf.length || !crypto.timingSafeEqual(digestBuf, hmacBuf)) {
    return res.status(403).send('Invalid HMAC');
  }
  // [END oauth.verify-hmac]

  // [START oauth.validate-shop]
  if (!isValidShopDomain(shop)) {
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

  if (!tokenResponse.ok) {
    return res.status(403).send('Token exchange failed');
  }

  const { access_token, refresh_token, scope } = await tokenResponse.json();
  // [END oauth.exchange-code]

  // [START oauth.confirm-scopes]
  const granted = scope.split(',');
  // A write_* grant includes its matching read_* scope, so Shopify may return
  // only the write scope. Treat a requested read_* as satisfied by its write_*.
  const missing = SCOPES.split(',').filter(s =>
    !granted.includes(s) &&
    !(s.startsWith('read_') && granted.includes(`write_${s.slice(5)}`))
  );
  if (missing.length > 0) return res.status(403).send(`Missing scopes: ${missing.join(', ')}`);
  // [END oauth.confirm-scopes]

  // Store tokens server-side, keyed by shop (use a database in production)
  tokenStore[shop] = { access_token, refresh_token };

  // Set a signed session cookie so subsequent requests can identify the shop
  res.cookie('shop', shop, cookieOptions);
  res.json({ message: 'App installed', shop, scope });
});

// [START oauth.make-request]
app.get('/products', async (req, res) => {
  const shop = req.signedCookies.shop;
  if (!shop) return res.status(401).send('Not authenticated');

  const stored = tokenStore[shop];
  if (!stored) return res.status(401).send('Not authenticated');

  const response = await fetch(`https://${shop}/admin/api/2026-04/graphql.json`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Shopify-Access-Token': stored.access_token,
    },
    body: JSON.stringify({ query: '{ products(first: 5) { edges { node { id handle } } } }' }),
  });

  res.json(await response.json());
});
// [END oauth.make-request]

app.listen(3000, () => console.log('Server running on http://localhost:3000'));
