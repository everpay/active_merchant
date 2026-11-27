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

The status endpoint also returns definitive issuer declines from its persistent ledger, keyed by the capture ID and accompanied by the exact amount, currency, and normalized decline code. This lets Platform OS release a reserved attempt when the original response is lost. An unconfirmed authorization remains pending.

Before staging acceptance, verify the approved test account supports Adyen Classic manual capture, delivers signed `CAPTURE` and `CAPTURE_FAILED` events, and returns both tokenization references. Set Platform OS staging's `ACTIVE_MERCHANT_SANDBOX_URL` to the adapter's HTTPS origin and verify its pending-payment watcher runs. Adyen directs new integrations to its Checkout API.

## Verify capture before staging

The local HTTP tests send signed fixture events through `/webhooks/adyen` and read the result from `/api/v1/gateway/capture-status`. They cover delayed delivery, a matching full capture, failure, and request and webhook replay. The fixtures use the suite's HMAC key and synthetic references.

Once test access is confirmed, use a dedicated test merchant, provider-issued test card, and the HMAC key for that merchant's Test Standard webhook.

1. Run the adapter locally. Enroll the test card and verify that both the reusable token and the original network transaction reference are present. Submit one manual renewal with a new capture ID and a stable idempotency key. Verify that status is pending after the capture API acknowledges the request.
2. Obtain the unmodified signed test event from an approved test webhook receiver. Verify that its merchant account, original authorization reference, amount, and currency match the renewal. Deliver it to the local adapter and confirm `captured` through the status endpoint. Cross-check the capture in the processor's Test Customer Area.
3. Replay the same renewal payload and event. Verify that the status stays captured and that the Test Customer Area shows just one capture for that renewal.
4. Use a separate renewal attempt to verify failure handling. Obtain the matching Adyen-signed `CAPTURE_FAILED` event from the same test webhook receiver and deliver it unchanged to the local adapter. Verify that the status moves to `capture_review` after the first delivery and stays there when you replay the event and renewal request. Verify in the Test Customer Area that replay created no additional authorization or capture.

Keep test credentials, tokens, and signed payloads out of source control. Record the capture ID, authorization and capture references, and observed statuses. [Adyen capture events](https://docs.adyen.com/online-payments/capture/) · [Standard webhook signatures](https://docs.adyen.com/development-resources/webhooks/secure-webhooks/verify-hmac-signatures/)
