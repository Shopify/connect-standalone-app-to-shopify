# ruby/app.rb
require 'sinatra'
require 'rack/session/cookie'
require 'dotenv/load'
require 'net/http'
require 'json'
require 'openssl'
require 'securerandom'
require 'uri'

CLIENT_ID = ENV['SHOPIFY_CLIENT_ID']
CLIENT_SECRET = ENV['SHOPIFY_CLIENT_SECRET']
REDIRECT_URI = ENV['REDIRECT_URI']
SCOPES = ENV.fetch('SCOPES', 'read_products,write_orders')

# Send the session cookie only over HTTPS in production; over plain HTTP on
# localhost in dev. httponly + same_site protect it the rest of the time.
use Rack::Session::Cookie,
    key: 'rack.session',
    secret: ENV.fetch('SESSION_SECRET') { SecureRandom.hex(64) },
    secure: ENV['RACK_ENV'] == 'production',
    httponly: true,
    same_site: :lax

# In-memory token store (use a database in production)
token_store = {}
# A valid expiring-token response includes expires_in (seconds until the token
# expires). Return nil when it's absent or non-positive: treat the token as
# non-expiring and never refresh it, rather than computing an immediate expiry
# that would send a token with no refresh_token through a doomed refresh.
def expires_at_from(expires_in)
  seconds = expires_in.to_i
  seconds.positive? ? Time.now.to_i + seconds : nil
end

def valid_shop_domain?(shop)
  shop.to_s.match?(/\A[a-zA-Z0-9][a-zA-Z0-9\-]*\.myshopify\.com\z/)
end

# [START oauth.build-authorization-url]
get '/install' do
  shop = params[:shop]
  halt 400, 'Invalid shop domain' unless valid_shop_domain?(shop)

  nonce = SecureRandom.hex(16)
  # Store the nonce in the signed session so you can verify it against the callback
  session[:oauth_state] = nonce

  auth_url = "https://#{shop}/admin/oauth/authorize?" + URI.encode_www_form(
    client_id: CLIENT_ID,
    scope: SCOPES,
    redirect_uri: REDIRECT_URI,
    state: nonce
  )

  redirect auth_url
end
# [END oauth.build-authorization-url]

get '/callback' do
  code  = params[:code]
  hmac  = params[:hmac]
  shop  = params[:shop]
  state = params[:state]

  # [START oauth.validate-state]
  halt 403, 'Invalid state parameter' unless state && state == session.delete(:oauth_state)
  # [END oauth.validate-state]

  # [START oauth.verify-hmac]
  query_params = params.reject { |key, _| key == 'hmac' }
  message = query_params.sort.map { |k, v| "#{k}=#{v}" }.join('&')
  digest = OpenSSL::HMAC.hexdigest('SHA256', CLIENT_SECRET, message)
  halt 403, 'Invalid HMAC' unless hmac && Rack::Utils.secure_compare(digest, hmac)
  # [END oauth.verify-hmac]

  # [START oauth.validate-shop]
  halt 400, 'Invalid shop domain' unless valid_shop_domain?(shop)
  # [END oauth.validate-shop]

  # [START oauth.exchange-code]
  uri = URI("https://#{shop}/admin/oauth/access_token")
  http_response = Net::HTTP.post_form(uri, {
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    code: code,
    expiring: '1'
  })

  halt 403, 'Token exchange failed' unless http_response.is_a?(Net::HTTPSuccess)

  data = JSON.parse(http_response.body)
  access_token = data['access_token']
  refresh_token = data['refresh_token']
  expires_in = data['expires_in']
  scope = data['scope']
  # [END oauth.exchange-code]

  # [START oauth.confirm-scopes]
  granted = scope.split(',')
  # A write_* grant includes its matching read_* scope, so Shopify may return
  # only the write scope. Treat a requested read_* as satisfied by its write_*.
  missing = SCOPES.split(',').reject do |s|
    granted.include?(s) || (s.start_with?('read_') && granted.include?("write_#{s.delete_prefix('read_')}"))
  end
  halt 403, "Missing scopes: #{missing.join(', ')}" unless missing.empty?
  # [END oauth.confirm-scopes]

  # Store tokens server-side, keyed by shop (use a database in production).
  # Track when the access token expires so requests can refresh it in time.
  token_store[shop] = {
    access_token: access_token,
    refresh_token: refresh_token,
   expires_at: expires_at_from(expires_in)
  }

  # Store the shop in the signed server-side session
  session[:shop] = shop

  content_type :json
  JSON.generate({ message: 'App installed', shop: shop, scope: scope })
end

# Exchange the stored refresh token for a new access token. The return value
# tells the caller how to react, and matches the refresh error handling used
# across grant types:
#   :refreshed   - got a new access token
#   :reauthorize - a 401 means the refresh token is terminal (expired, revoked,
#                  replayed after the one-hour retry window, or the app was
#                  uninstalled); send the merchant back through OAuth
#   :retry       - a transient failure (network, timeout, 5xx, 429); safe to
#                  retry later with the same refresh token
def refresh_access_token(shop, token_store)
  stored = token_store[shop]
  return :reauthorize unless stored && stored[:refresh_token]

  uri = URI("https://#{shop}/admin/oauth/access_token")
  response = Net::HTTP.post_form(uri, {
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    grant_type: 'refresh_token',
    refresh_token: stored[:refresh_token]
  })

  # A 401 is terminal: drop the dead token so the merchant reinstalls.
  if response.is_a?(Net::HTTPUnauthorized)
    token_store.delete(shop)
    return :reauthorize
  end
  return :retry unless response.is_a?(Net::HTTPSuccess)

  data = JSON.parse(response.body)
  token_store[shop] = {
    access_token: data['access_token'],
    refresh_token: data['refresh_token'],
    expires_at: expires_at_from(data['expires_in'])
  }
  :refreshed
end

# [START oauth.make-request]
get '/products' do
  shop = session[:shop]
  halt 401, 'Not authenticated' unless shop
  stored = token_store[shop]
  halt 401, 'Not authenticated' unless stored

  # Expiring access tokens are short-lived. Refresh ~60 seconds before the token
  # actually expires so a request never goes out with a token that lapses
  # mid-flight.
  if stored[:expires_at] && Time.now.to_i >= stored[:expires_at] - 60
    case refresh_access_token(shop, token_store)
    when :reauthorize then halt 401, 'Reauthorization required'
    when :retry then halt 503, 'Token refresh failed, try again'
    end
    stored = token_store[shop]
  end

  uri = URI("https://#{shop}/admin/api/2026-04/graphql.json")
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true

  req = Net::HTTP::Post.new(uri)
  req['Content-Type'] = 'application/json'
  req['X-Shopify-Access-Token'] = stored[:access_token]
  req.body = JSON.generate({ query: '{ products(first: 5) { edges { node { id handle } } } }' })

  content_type :json
  http.request(req).body
end
# [END oauth.make-request]
