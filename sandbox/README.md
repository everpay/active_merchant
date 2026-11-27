# Active Merchant sandbox adapter

This service accepts Platform OS test-mode card enrollment and renewal requests. It uses the Ruby fork's Adyen Classic test gateway. The test suite replaces the processor transport with fixtures and exercises the request and response formats without a processor account.

From the repository root, set `BUNDLE_GEMFILE` to `sandbox/Gemfile`, run `bundle install`, and run `ruby -rbundler/setup sandbox/adapter_test.rb`. The HTTP test listens on loopback.

To start the local service, run `ruby -rbundler/setup sandbox/server.rb` with the same bundle and these environment variables.

- `ACTIVE_MERCHANT_SANDBOX_SECRET` authenticates requests. Its value must match Platform OS staging's `ACTIVE_MERCHANT_SECRET` when connected.
- `ACTIVE_MERCHANT_SANDBOX_SIGNING_KEY` is a separate persistent secret for enrollment tokens and idempotency. Both secrets require at least 32 bytes.
- `ACTIVE_MERCHANT_SANDBOX_DB` points to a SQLite file outside the checkout in a private, persistent directory. Keep the database and signing key together across restarts.
- `BIND_ADDRESS` and `PORT` default to `127.0.0.1` and `8080`.

`POST /api/v1/gateway/store` requires an idempotency key and returns a signed card token plus the network transaction reference when both are present. A staging request without order or shopper metadata uses its idempotency key to derive stable references.

`POST /api/v1/gateway/purchase` requires the enrollment token, matching network transaction reference, and an idempotency key for a renewal. An initial card purchase can use a unique order ID when the header is absent. The service records a reservation before making the processor request. It replays known responses and leaves interrupted attempts pending for reconciliation.

Adyen Classic acknowledges capture before it confirms the result. A capture attempt stays pending in this adapter. Confirm the approved test account's supported API and add a way to process a final capture result before using this flow for staging acceptance. Adyen directs new integrations to its Checkout API.
