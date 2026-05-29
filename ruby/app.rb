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

# In-memory nonce store (use a database in production)
nonces = {}

# [START oauth.build-authorization-url]
get '/install' do
  shop = params[:shop]
  nonce = SecureRandom.hex(16)
  nonces[nonce] = true

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
  halt 403, 'Invalid state parameter' unless nonces.delete(state)
  # [END oauth.validate-state]

  # [START oauth.verify-hmac]
  query_params = params.reject { |key, _| key == 'hmac' }
  message = query_params.sort.map { |k, v| "#{k}=#{v}" }.join('&')
  digest = OpenSSL::HMAC.hexdigest('SHA256', CLIENT_SECRET, message)
  halt 403, 'Invalid HMAC' unless Rack::Utils.secure_compare(digest, hmac)
  # [END oauth.verify-hmac]

  # [START oauth.validate-shop]
  halt 400, 'Invalid shop domain' unless shop.match?(/\A[a-zA-Z0-9][a-zA-Z0-9\-]*\.myshopify\.com\z/)
  # [END oauth.validate-shop]

  # [START oauth.exchange-code]
  uri = URI("https://#{shop}/admin/oauth/access_token")
  response = Net::HTTP.post_form(uri, {
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    code: code,
    expiring: '1'
  })

  data = JSON.parse(response.body)
  access_token = data['access_token']
  scope = data['scope']
  # [END oauth.exchange-code]

  # [START oauth.confirm-scopes]
  missing = SCOPES.split(',') - scope.split(',')
  halt 403, "Missing scopes: #{missing.join(', ')}" unless missing.empty?
  # [END oauth.confirm-scopes]

  # Store access_token securely — omitted for brevity
  json({ message: 'App installed', shop: shop, scope: scope })
end

# [START oauth.make-request]
get '/products' do
  shop         = params[:shop]
  access_token = params[:access_token]

  uri = URI("https://#{shop}/admin/api/2025-01/graphql.json")
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true

  req = Net::HTTP::Post.new(uri)
  req['Content-Type'] = 'application/json'
  req['X-Shopify-Access-Token'] = access_token
  req.body = JSON.generate({ query: '{ products(first: 5) { edges { node { id handle } } } }' })

  json JSON.parse(http.request(req).body)
end
# [END oauth.make-request]
