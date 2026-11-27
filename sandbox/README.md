# Active Merchant sandbox adapter

This service accepts Platform OS test-mode card enrollment and renewal requests. It uses the Ruby fork's Adyen Classic test gateway. The test suite replaces the processor transport with fixtures and exercises the request and response formats without a processor account.

From the repository root, set `BUNDLE_GEMFILE` to `sandbox/Gemfile`, run `bundle install`, and run `ruby -rbundler/setup sandbox/adapter_test.rb`. The HTTP test listens on loopback.

To start the local service, run `ruby -rbundler/setup sandbox/server.rb` with the same bundle and these environment variables.

- `ACTIVE_MERCHANT_SANDBOX_SECRET` authenticates requests. Its value must match Platform OS staging's `ACTIVE_MERCHANT_SANDBOX_SECRET` when connected.
- `ACTIVE_MERCHANT_SANDBOX_SIGNING_KEY` is a separate persistent secret for enrollment tokens and idempotency. Both secrets require at least 32 bytes.
- `ACTIVE_MERCHANT_SANDBOX_WEBHOOK_KEY` is the 64-character hex HMAC key for the Adyen test Standard webhook.
- `ACTIVE_MERCHANT_SANDBOX_DB` points to a SQLite file outside the checkout in a private, persistent directory. Keep the database and signing key together across restarts.
- `BIND_ADDRESS` and `PORT` default to `127.0.0.1` and `8080`.

`POST /api/v1/gateway/store` requires an idempotency key and returns a signed card token plus the network transaction reference when both are present. A staging request without order or shopper metadata uses its idempotency key to derive stable references.

`POST /api/v1/gateway/purchase` requires the enrollment token, matching network transaction reference, and an idempotency key for a renewal. Platform OS sends a distinct key per checkout attempt and keeps the order ID as the processor reference. The service records a reservation before calling Adyen and converts Platform OS amounts to Adyen minor units for authorization and capture. IDR and CVE amounts must be representable as whole units.

For hosted enrollment, Platform OS includes the validated shopper consent context with the purchase. The adapter tokenizes during authorization. It stores the token candidate in its private SQLite file and releases it through the authenticated `POST /api/v1/gateway/capture-status` after a signed, full-amount `CAPTURE` notification to `POST /webhooks/adyen`. An acknowledgment from the capture API leaves the payment pending. A capture failure places it in reconciliation review.

Before staging acceptance, verify the approved test account supports Adyen Classic manual capture, delivers signed `CAPTURE` and `CAPTURE_FAILED` events, and returns both tokenization references. Set Platform OS staging's `ACTIVE_MERCHANT_SANDBOX_URL` to the adapter's HTTPS origin and verify its pending-payment watcher runs. Adyen directs new integrations to its Checkout API.
