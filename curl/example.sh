#!/usr/bin/env bash

SHOP="your-store.myshopify.com"
CLIENT_ID="your-client-id"
CLIENT_SECRET="your-client-secret"
REDIRECT_URI="https://your-app.example.com/callback"
SCOPES="read_products,write_orders"

# Step 1: Open this URL in a browser to start the OAuth flow.
# Replace {nonce} with a randomly generated value you store to verify in the callback.
# https://${SHOP}/admin/oauth/authorize?client_id=${CLIENT_ID}&scope=${SCOPES}&redirect_uri=${REDIRECT_URI}&state={nonce}

# [START oauth.exchange-code]
# Step 3: Exchange the authorization code for an access token.
# Replace {authorization_code} with the code from the callback query parameter.
curl -X POST \
  https://${SHOP}/admin/oauth/access_token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Accept: application/json' \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}" \
  -d 'code={authorization_code}' \
  -d 'expiring=1'
# [END oauth.exchange-code]

# [START oauth.make-request]
# Step 4: Make an authenticated GraphQL Admin API request.
# Replace {access_token} with the token from the exchange response.
curl -X POST \
  https://${SHOP}/admin/api/2026-04/graphql.json \
  -H 'Content-Type: application/json' \
  -H "X-Shopify-Access-Token: {access_token}" \
  -d '{"query": "{ products(first: 5) { edges { node { id handle } } } }"}'
# [END oauth.make-request]
