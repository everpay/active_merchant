require 'minitest/autorun'
require 'net/http'
require 'tmpdir'
require_relative 'server'

class SandboxAdapterTest < Minitest::Test
  SECRET = 'bearer-fixture-only-' * 2
  SIGNING_KEY = 'signing-fixture-only-' * 2
  AUTH = "Bearer #{SECRET}"
  NETWORK_REFERENCE = 'sandbox-network-reference'
  CARD_TOKEN = 'sandbox-card-token'
  CARD = {
    'number' => '4111111111111111', 'exp_month' => '03', 'exp_year' => '28', 'cvc' => '123', 'holder_name' => 'Sandbox Card'
  }.freeze
  CREDENTIALS = { 'username' => 'test-user', 'password' => 'test-password', 'merchant_account' => 'TestMerchant' }.freeze

  class FixtureGateway < EverpaySandbox::AdyenGateway
    def initialize(credentials, transport)
      super(**credentials, test: true)
      @transport = transport
    end

    def ssl_post(url, data, headers)
      JSON.generate(@transport.call(URI(url), JSON.parse(data), headers['Idempotency-Key']))
    end
  end

  def setup
    @directory = Dir.mktmpdir('everpay-gateway-test-')
    @path = File.join(@directory, 'requests.sqlite3')
    @calls = []
    @transport = method(:respond_to_adyen)
    open_adapter
  end

  def teardown
    @ledger&.close
    FileUtils.remove_entry(@directory)
  end

  def test_platform_staging_enrollment_and_token_renewal_contract
    status, stored = post('store', enrollment, key: 'renewal-enroll:transaction')
    assert_equal 200, status
    assert_equal true, stored[:success]
    assert_equal NETWORK_REFERENCE, stored[:network_transaction_id]
    assert_equal true, stored[:test]
    assert_equal 'Ecommerce', @calls[0][1]['shopperInteraction']
    refute_empty @calls[0][1]['reference']

    status, purchase = post('purchase', renewal(stored), key: 'renewal:attempt')
    assert_equal 202, status
    assert_equal 'pending', purchase[:status]
    assert_equal 'OUTCOME_UNKNOWN', purchase[:response_code]
    assert_equal %w[authorise authorise capture], @calls.map(&:first)
    enrollment_request = @calls[0][1]
    renewal_request = @calls[1][1]
    assert_equal 'Subscription', renewal_request['recurringProcessingModel']
    assert_equal 'ContAuth', renewal_request['shopperInteraction']
    assert_equal enrollment_request['shopperReference'], renewal_request['shopperReference']
    assert_equal CARD_TOKEN, renewal_request['selectedRecurringDetailReference']
    assert_equal NETWORK_REFERENCE, renewal_request.dig('additionalData', 'networkTxReference')
    refute renewal_request.key?('card')
    assert_equal({ 'currency' => 'EUR', 'value' => 1_234 }, renewal_request['amount'])
    assert_equal({ 'currency' => 'EUR', 'value' => 1_234 }, @calls[2][1]['modificationAmount'])
    refute_equal @calls[1][2], @calls[2][2]
  end

  def test_enrollment_carries_supplied_order_and_stable_shopper_reference
    payload = enrollment.merge('metadata' => { 'order_id' => 'order-123', 'subscription_id' => 'sub-123' })
    assert_equal 200, post('store', payload, key: 'renewal-enroll:one').first
    assert_equal 200, post('store', payload, key: 'renewal-enroll:two').first
    assert_equal 'order-123', @calls[0][1]['reference']
    assert_equal @calls[0][1]['shopperReference'], @calls[1][1]['shopperReference']
    refute_equal 'sub-123', @calls[0][1]['shopperReference']
  end

  def test_retry_is_replayed_after_reopening_storage
    _, stored = post('store', enrollment, key: 'renewal-enroll:one')
    payload = renewal(stored)
    result = post('purchase', payload, key: 'renewal:one')
    @ledger.close
    open_adapter

    assert_equal [200, stored], post('store', enrollment, key: 'renewal-enroll:one')
    assert_equal result, post('purchase', payload.to_a.reverse.to_h, key: 'renewal:one')
    assert_equal 409, post('purchase', payload.merge('amount' => 200), key: 'renewal:one').first
    assert_equal %w[authorise authorise capture], @calls.map(&:first)

    stored_bytes = File.binread(@path)
    [CARD['number'], '"cvc"', CREDENTIALS['password'], CREDENTIALS['username']].each do |value|
      refute_includes stored_bytes, value
    end
  end

  def test_simultaneous_requests_and_lost_reply_make_one_processor_attempt
    _, stored = post('store', enrollment, key: 'renewal-enroll:one')
    entered = Queue.new
    release = Queue.new
    @transport = lambda do |uri, body, _key|
      @calls << [uri.path.split('/').last, body]
      entered << true
      release.pop
      raise ActiveMerchant::ConnectionError.new('mock timed out')
    end
    request = renewal(stored)
    first = Thread.new { post('purchase', request, key: 'renewal:once') }
    entered.pop

    assert_equal 202, post('purchase', request, key: 'renewal:once').first
    release << true
    assert_equal 202, first.value.first
    @ledger.close
    open_adapter
    assert_equal 202, post('purchase', request, key: 'renewal:once').first
    assert_equal %w[authorise authorise], @calls.map(&:first)
  ensure
    first&.kill if first&.alive?
  end

  def test_interrupted_reservation_remains_pending_after_restart
    assert_raises(Interrupt) do
      @ledger.run('test-key', 'test-fingerprint', :pending) { raise Interrupt }
    end
    @ledger.close
    open_adapter

    assert_equal :pending, @ledger.run('test-key', 'test-fingerprint', :pending) { flunk 'reservation should survive' }
  end

  def test_enrollment_rejects_missing_token_or_network_reference
    @transport = ->(_uri, _body, _key) { accepted_authorization(nil) }
    status, body = post('store', enrollment, key: 'renewal-enroll:no-reference')
    assert_equal 422, status
    assert_equal 'CARD_ENROLLMENT_INCOMPLETE', body[:response_code]
    refute body.key?(:authorization)

    @transport = lambda do |_uri, _body, _key|
      result = accepted_authorization(NETWORK_REFERENCE)
      result['additionalData'].delete('recurring.recurringDetailReference')
      result
    end
    status, body = post('store', enrollment, key: 'renewal-enroll:no-token')
    assert_equal 422, status
    assert_equal 'CARD_ENROLLMENT_INCOMPLETE', body[:response_code]
    refute body.key?(:network_transaction_id)
  end

  def test_rejects_live_requests_bad_credentials_and_unbound_tokens
    assert_equal 401, post('store', enrollment, key: 'x', auth: 'Bearer wrong').first
    assert_equal 422, post('store', enrollment.merge('environment' => 'live', 'test' => false), key: 'x').first
    assert_equal 422, post('store', enrollment.merge('gateway' => 'stripe'), key: 'x').first
    assert_equal 422, post('store', enrollment.merge('credentials' => {}), key: 'x').first
    assert_equal 422, post('store', enrollment, key: nil).first
    assert_empty @calls

    _, stored = post('store', enrollment, key: 'renewal-enroll:one')
    request = renewal(stored)
    assert_equal 422, post('purchase', request.merge('card' => CARD), key: 'renewal:one').first
    assert_equal 422, post('purchase', request.merge('token' => 'bad-token'), key: 'renewal:one').first
    assert_equal 422, post('purchase', request.merge('credentials' => CREDENTIALS.merge('merchant_account' => 'Other')), key: 'renewal:one').first
    request['stored_credential']['network_transaction_id'] = 'other-network-reference'
    assert_equal 422, post('purchase', request, key: 'renewal:one').first
    assert_equal %w[authorise], @calls.map(&:first)
  end

  def test_raw_staging_checkout_can_use_order_id_for_retries
    raw_purchase = base('purchase').merge('card' => CARD, 'amount' => 100, 'currency' => 'USD', 'metadata' => { 'order_id' => 'checkout-123' })
    result = post('purchase', raw_purchase, key: nil)
    assert_equal 202, result.first
    assert_equal result, post('purchase', raw_purchase, key: nil)
    assert_equal %w[authorise capture], @calls.map(&:first)
    assert_equal 'checkout-123', @calls.first[1]['reference']
    assert_equal 422, post('purchase', raw_purchase.merge('metadata' => {}), key: nil).first
  end

  def test_pending_authorization_is_not_captured
    _, stored = post('store', enrollment, key: 'renewal-enroll:one')
    @transport = lambda do |uri, body, key|
      @calls << [uri.path.split('/').last, body, key]
      { 'resultCode' => 'Received', 'pspReference' => 'pending-test-ref' }
    end
    assert_equal 202, post('purchase', renewal(stored), key: 'renewal:one').first
    assert_equal %w[authorise authorise], @calls.map(&:first)
  end

  def test_lost_capture_reply_keeps_authorization_reference
    _, stored = post('store', enrollment, key: 'renewal-enroll:one')
    @transport = lambda do |uri, body, key|
      reply = respond_to_adyen(uri, body, key)
      raise ActiveMerchant::ConnectionError.new('mock timeout') if uri.path.end_with?('/capture')

      reply
    end
    payload = renewal(stored)
    status, reply = post('purchase', payload, key: 'renewal:once')
    assert_equal 202, status
    assert_includes reply[:authorization], 'test-authorization'
    assert_equal [status, reply], post('purchase', payload, key: 'renewal:once')
    assert_equal %w[authorise authorise capture], @calls.map(&:first)
  end

  def test_zero_decimal_currency_is_forwarded_without_rescaling
    _, stored = post('store', enrollment, key: 'renewal-enroll:one')
    assert_equal 202, post('purchase', renewal(stored).merge('currency' => 'JPY', 'amount' => 505), key: 'renewal:one').first
    assert_equal 505, @calls[1][1].dig('amount', 'value')
    assert_equal 505, @calls[2][1].dig('modificationAmount', 'value')
  end

  def test_http_endpoint_accepts_bearer_and_idempotency_headers
    server = EverpaySandbox.server(@adapter, address: '127.0.0.1', port: 0)
    worker = Thread.new { server.start }
    port = server.listeners.first.addr[1]
    client = Net::HTTP.new('127.0.0.1', port, nil)
    assert_equal '200', client.get('/healthz').code

    path = '/api/v1/gateway/store'
    headers = { 'Authorization' => AUTH, 'Idempotency-Key' => 'renewal-enroll:http', 'Content-Type' => 'application/json' }
    first = client.post(path, JSON.generate(enrollment), headers)
    assert_equal '200', first.code
    assert_equal NETWORK_REFERENCE, JSON.parse(first.body)['network_transaction_id']
    assert_equal first.body, client.post(path, JSON.generate(enrollment), headers).body
    assert_equal '413', client.post(path, 'x' * 20_000, headers).code
    assert_equal %w[authorise], @calls.map(&:first)
  ensure
    server&.shutdown
    worker&.join
  end

  private

  def open_adapter
    @ledger = EverpaySandbox::Idempotency.new(@path)
    @adapter = EverpaySandbox::Adapter.new(secret: SECRET, signing_key: SIGNING_KEY, idempotency: @ledger,
                                           gateway_factory: ->(credentials) { FixtureGateway.new(credentials, @transport) })
  end

  def post(action, body, key:, auth: AUTH)
    @adapter.call(method: 'POST', path: "/api/v1/gateway/#{action}", authorization: auth, idempotency_key: key) { JSON.generate(body) }
  end

  def base(action)
    { 'action' => action, 'gateway' => 'adyen', 'environment' => 'test', 'test' => true, 'credentials' => CREDENTIALS }
  end

  def enrollment
    base('store').merge('card' => CARD, 'stored_credential' => {
      'initiator' => 'cardholder', 'reason_type' => 'recurring', 'initial_transaction' => true
    })
  end

  def renewal(stored)
    base('purchase').merge('token' => stored.fetch(:authorization), 'amount' => 1_234, 'currency' => 'EUR',
                           'metadata' => { 'order_id' => 'renewal-one', 'subscription_id' => 'sub-123' },
                           'stored_credential' => {
                             'initiator' => 'merchant', 'reason_type' => 'recurring', 'initial_transaction' => false,
                             'network_transaction_id' => stored.fetch(:network_transaction_id)
                           })
  end

  def respond_to_adyen(uri, body, key)
    assert_equal 'pal-test.adyen.com', uri.host
    action = uri.path.split('/').last
    @calls << [action, body, key]
    return { 'response' => '[capture-received]', 'pspReference' => 'test-capture' } if action == 'capture'

    accepted_authorization(NETWORK_REFERENCE)
  end

  def accepted_authorization(network_reference)
    { 'resultCode' => 'Authorised', 'pspReference' => 'test-authorization',
      'additionalData' => { 'recurring.recurringDetailReference' => CARD_TOKEN, 'networkTxReference' => network_reference }.compact }
  end
end
