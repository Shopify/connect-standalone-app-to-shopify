# Connect a standalone app to Shopify

Tutorial for authenticating standalone apps using the OAuth authorization code grant flow.

**Tutorial:** [Connect a standalone app to Shopify](https://shopify.dev/docs/apps/build/authentication-authorization/connect-standalone)

## Languages

- `node/` — Node.js example
- `ruby/` — Ruby example
- `curl/` — cURL/Bash example

## Setup

1. Copy `.env.example` to `.env` and add your credentials
2. Run `npm install` in the `node/` directory to install dependencies
3. Start the Node.js server with `node node/index.js`, or run `ruby ruby/app.rb` for the Ruby example
4. Open the app in your dev store

## Environment variables

| Variable | Description |
|---|---|
| `SHOPIFY_CLIENT_ID` | Your app's client ID from the Dev Dashboard. |
| `SHOPIFY_CLIENT_SECRET` | Your app's client secret from the Dev Dashboard. |
| `REDIRECT_URI` | The callback URL configured in the Dev Dashboard. |
| `SCOPES` | Comma-separated list of access scopes (for example, `read_products,write_orders`). |

## Note

This repository is for documentation purposes. Issues and pull requests are not accepted.

