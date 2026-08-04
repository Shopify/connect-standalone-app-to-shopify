# ruby/app.rb
require 'sinatra'
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

enable :sessions
set :session_secret, ENV.fetch('SESSION_SECRET') { SecureRandom.hex(64) }

# In-memory token store (use a database in production)
token_store = {}

def valid_shop_domain?(shop)
  shop.match?(/\A[a-zA-Z0-9][a-zA-Z0-9\-]*\.myshopify\.com\z/)
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

  # Store tokens server-side, keyed by shop (use a database in production)
  token_store[shop] = { access_token: access_token, refresh_token: refresh_token }

  # Store the shop in the signed server-side session
  session[:shop] = shop

  content_type :json
  JSON.generate({ message: 'App installed', shop: shop, scope: scope })
end

# [START oauth.make-request]
get '/products' do
  shop = session[:shop]
  halt 401, 'Not authenticated' unless shop
  stored = token_store[shop]
  halt 401, 'Not authenticated' unless stored

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
