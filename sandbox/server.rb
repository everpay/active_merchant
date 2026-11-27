require 'webrick'
require_relative 'adapter'

module EverpaySandbox
  def self.server(adapter, address:, port:)
    server = WEBrick::HTTPServer.new(
      BindAddress: address, Port: port, RequestTimeout: 15, MaxClients: 16,
      AccessLog: [], Logger: WEBrick::Log.new($stderr, WEBrick::Log::FATAL)
    )
    server.mount_proc('/') do |request, response|
      status, body = adapter.call(
        method: request.request_method, path: request.path, authorization: request['authorization'],
        idempotency_key: request['idempotency-key']
      ) do
        raw = +''
        request.body do |chunk|
          raw << chunk
          break if raw.bytesize > Adapter::MAX_BODY_BYTES
        end
        raw
      end
      response.status = status
      response['Content-Type'] = 'application/json'
      response['Cache-Control'] = 'no-store'
      response['Connection'] = 'close'
      response.body = JSON.generate(body)
      response.keep_alive = false
    end
    server
  end
end

if $PROGRAM_NAME == __FILE__
  store = EverpaySandbox::Idempotency.new(ENV.fetch('ACTIVE_MERCHANT_SANDBOX_DB'))
  adapter = EverpaySandbox::Adapter.new(secret: ENV.fetch('ACTIVE_MERCHANT_SANDBOX_SECRET'),
                                        signing_key: ENV.fetch('ACTIVE_MERCHANT_SANDBOX_SIGNING_KEY'), idempotency: store)
  server = EverpaySandbox.server(adapter, address: ENV.fetch('BIND_ADDRESS', '127.0.0.1'), port: Integer(ENV.fetch('PORT', '8080')))
  %w[INT TERM].each { |signal| trap(signal) { server.shutdown } }
  server.start
  store.close
end
