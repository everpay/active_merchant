require 'active_merchant'
require 'base64'
require 'json'
require 'openssl'
require_relative 'idempotency'

module EverpaySandbox
  class AdyenGateway < ActiveMerchant::Billing::AdyenGateway
    private

    # Recurring authorization and vaulting need the same shopper reference on the wire.
    def add_stored_credentials(post, payment, options)
      super
      add_shopper_reference(post, options)
    end

    # Platform OS already supplies minor units for the requested currency.
    def localized_amount(amount, _currency)
      amount
    end
  end

  class Adapter
    ROUTES = { '/api/v1/gateway/store' => 'store', '/api/v1/gateway/purchase' => 'purchase' }.freeze
    TEST_FIELDS = { environment: 'test', test: true }.freeze
    CREDENTIAL_FIELDS = %w[username password merchant_account].freeze
    DEFINITIVE_DECLINES = %w[Refused Cancelled].freeze
    MAX_BODY_BYTES = 16_384

    class InvalidRequest < StandardError; end

    def initialize(secret:, signing_key:, idempotency:, gateway_factory: ->(credentials) { AdyenGateway.new(**credentials, test: true) })
      raise ArgumentError, 'A sandbox bearer secret is required' if secret.bytesize < 32 || secret.match?(/\s/)
      raise ArgumentError, 'A separate sandbox signing key is required' if signing_key.bytesize < 32 || signing_key == secret

      @secret = secret
      @signing_key = signing_key
      @idempotency = idempotency
      @gateway_factory = gateway_factory
    end

    def call(method:, path:, authorization:, idempotency_key:)
      return reply(200, status: 'ok') if method == 'GET' && path == '/healthz'

      action = ROUTES[path]
      return failure(404, 'ROUTE_NOT_FOUND') unless action
      return failure(405, 'METHOD_NOT_ALLOWED') unless method == 'POST'
      return failure(401, 'UNAUTHORIZED') unless secure_equal("Bearer #{@secret}", authorization.to_s)

      raw = yield
      return failure(413, 'REQUEST_TOO_LARGE') if raw.bytesize > MAX_BODY_BYTES

      request = object(JSON.parse(raw))
      return failure(422, 'TEST_MODE_REQUIRED') unless request['environment'] == 'test' && request['test'] == true
      return failure(422, 'UNSUPPORTED_GATEWAY') unless request['gateway'] == 'adyen'
      return failure(422, 'INVALID_ACTION') if request.key?('action') && request['action'] != action

      metadata = object(request.fetch('metadata', {}))
      credentials = processor_credentials(request['credentials'])
      key = operation_key(action, idempotency_key, request, metadata)
      scope = [credentials.fetch(:merchant_account), action, key]
      request_key = sign('request', JSON.generate(scope))
      fingerprint = sign('payload', JSON.generate(canonical(request)))
      payment = prepare(action, request, metadata, credentials, request_key)

      @idempotency.run(request_key, fingerprint, pending) do
        submit(action, credentials, payment)
      rescue StandardError
        pending
      end
    rescue JSON::ParserError, InvalidRequest
      failure(422, 'INVALID_REQUEST')
    rescue SQLite3::Exception
      pending
    end

    private

    def operation_key(action, key, request, metadata)
      return text(key, 200) unless key.nil? || key.empty?

      # Older checkout callers may supply only an order ID.
      return "order:#{text(metadata['order_id'], 160)}" if action == 'purchase' && request.key?('card') && !request.key?('token')

      raise InvalidRequest
    end

    def processor_credentials(input)
      values = object(input)
      CREDENTIAL_FIELDS.to_h { |field| [field.to_sym, text(values[field], 256)] }
    end

    def prepare(action, request, metadata, credentials, request_key)
      options = { idempotency_key: request_key[0, 48], order_id: optional_text(metadata['order_id'], 80) || request_key }
      if action == 'store'
        raise InvalidRequest if request.key?('token')

        shopper_seed = optional_text(metadata['subscription_id'], 160) || request_key
        options[:shopper_reference] = sign('shopper', shopper_seed)
        options[:currency] = currency(request.fetch('currency', 'USD'))
        options[:stored_credential] = stored_credential(request, initial: true)
        return { instrument: card(request['card']), options: }
      end

      amount = request['amount']
      raise InvalidRequest unless amount.is_a?(Integer) && amount.positive? && amount <= 999_999_999

      options[:currency] = currency(request['currency'])
      if request.key?('token')
        raise InvalidRequest if request.key?('card')

        options[:stored_credential] = stored_credential(request, initial: false)
        instrument, options[:shopper_reference] = open_token(
          request['token'], credentials.fetch(:merchant_account), options[:stored_credential].fetch(:network_transaction_id)
        )
      else
        raise InvalidRequest if request.key?('stored_credential')

        instrument = card(request['card'])
      end
      { amount:, instrument:, options: }
    end

    def submit(action, credentials, payment)
      gateway = @gateway_factory.call(credentials)
      options = payment.fetch(:options)
      instrument = payment.fetch(:instrument)
      if action == 'store'
        result = gateway.store(instrument, options)
        return pending unless result.test?
        return processor_failure(result) unless result.params['resultCode'] == 'Authorised'

        authorization = result.authorization
        network_id = result.network_transaction_id
        return failure(422, 'CARD_ENROLLMENT_INCOMPLETE') unless result.success? && present?(authorization, 256) && present?(network_id, 256)

        token = issue_token(authorization, options.fetch(:shopper_reference), credentials.fetch(:merchant_account), network_id)
        reply(200, success: true, authorization: token, network_transaction_id: network_id)
      else
        amount = payment.fetch(:amount)
        result = gateway.authorize(amount, instrument, options)
        return pending unless result.test?
        return processor_failure(result) unless authorized?(result)
        return pending unless present?(result.authorization, 256)

        # Capture is asynchronous. The authorization reference is needed even if capture is rejected.
        begin
          gateway.capture(amount, result.authorization, currency: options.fetch(:currency),
                          idempotency_key: "#{options.fetch(:idempotency_key)}-capture")
        rescue StandardError
          # The authorization already exists and the capture may have reached the processor.
        end
        pending(result.authorization)
      end
    end

    def authorized?(result)
      result.success? && result.params['resultCode'] == 'Authorised'
    end

    def processor_failure(result)
      return reply(200, success: false, response_code: 'DECLINED', message: 'The sandbox processor declined the request') if DEFINITIVE_DECLINES.include?(result.params['resultCode'])

      pending(result.authorization)
    end

    def stored_credential(request, initial:)
      stored = object(request['stored_credential'])
      initiator = initial ? 'cardholder' : 'merchant'
      raise InvalidRequest unless stored.values_at('initiator', 'reason_type', 'initial_transaction') == [initiator, 'recurring', initial]

      flags = { initiator:, reason_type: 'recurring', initial_transaction: initial }
      flags[:network_transaction_id] = text(stored['network_transaction_id'], 256) unless initial
      flags
    end

    def card(input)
      data = object(input)
      number = data['number']
      cvc = data['cvc']
      month = data['exp_month'].to_s
      year = data['exp_year'].to_s
      raise InvalidRequest unless number.is_a?(String) && number.match?(/\A[0-9]{12,19}\z/) &&
                                  cvc.is_a?(String) && cvc.match?(/\A[0-9]{3,4}\z/) &&
                                  month.match?(/\A(?:0?[1-9]|1[0-2])\z/) && year.match?(/\A(?:[0-9]{2}|20[0-9]{2})\z/)

      first, last = optional_text(data['holder_name'], 120)&.split(/\s+/, 2)
      ActiveMerchant::Billing::CreditCard.new(
        number:, month: month.to_i, year: year.length == 2 ? 2000 + year.to_i : year.to_i,
        verification_value: cvc, first_name: first, last_name: last
      )
    end

    def issue_token(authorization, shopper, merchant, network_id)
      payload = Base64.urlsafe_encode64(JSON.generate([authorization, shopper, merchant, network_id]), padding: false)
      "#{payload}.#{sign('token', payload)}"
    end

    def open_token(input, merchant, network_id)
      payload, signature = text(input, 2048).split('.', 2)
      raise InvalidRequest unless signature && secure_equal(sign('token', payload), signature)

      authorization, shopper, token_merchant, token_network_id = JSON.parse(Base64.urlsafe_decode64(payload))
      raise InvalidRequest unless token_merchant == merchant && token_network_id == network_id

      [authorization, shopper]
    rescue ArgumentError
      raise InvalidRequest
    end

    def currency(value)
      raise InvalidRequest unless value.is_a?(String) && value.match?(/\A[A-Z]{3}\z/)

      value
    end

    def object(value)
      raise InvalidRequest unless value.is_a?(Hash)

      value
    end

    def present?(value, limit)
      value.is_a?(String) && !value.strip.empty? && value.bytesize <= limit && !value.match?(/[[:cntrl:]]/)
    end

    def text(value, limit)
      raise InvalidRequest unless present?(value, limit)

      value
    end

    def optional_text(value, limit)
      return if value.nil? || value == ''

      text(value, limit)
    end

    def canonical(value)
      case value
      when Hash then value.sort.to_h.transform_values { |item| canonical(item) }
      when Array then value.map { |item| canonical(item) }
      else value
      end
    end

    def sign(purpose, value)
      OpenSSL::HMAC.hexdigest('SHA256', @signing_key, "#{purpose}\0#{value}")
    end

    def secure_equal(expected, actual)
      OpenSSL.secure_compare(expected, actual)
    end

    def pending(reference = nil)
      reply(202, status: 'pending', authorization: reference, response_code: 'OUTCOME_UNKNOWN')
    end

    def failure(status, code)
      reply(status, success: false, response_code: code)
    end

    def reply(status, **body)
      [status, TEST_FIELDS.merge(body.compact)]
    end
  end
end
