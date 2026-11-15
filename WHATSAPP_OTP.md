# WhatsApp Cloud API setup

WhatsApp delivery uses Meta's official Cloud API for two independent features:

1. customer OTP authentication messages; and
2. automatic admin order notifications after a checkout transaction commits.

The endpoint paths, JSON request fields, bcrypt-hashed `phone_otps` records, and checkout response are unchanged. Order notifications use a durable MySQL outbox, so a Meta error cannot roll back a successful order.

- `whatsapp.js` is the reusable Meta Cloud API client.
- `whatsapp-webhook.js` verifies Meta's callback challenge and authenticates incoming webhooks.
- `otp.js` handles OTP generation, expiry, cooldown, verification, and throttling.
- `order-notifications.js` formats and processes durable order-notification events.
- `server.js` queues order events in the checkout transaction and starts the worker.
- `.env.example` lists configuration without credentials.
- `migrations/20261112_create_whatsapp_notification_outbox.sql` creates the outbox table.

## 1. Protect credentials first

The repository's existing `.env` is tracked by Git. A new `.gitignore` prevents new local environment files from being added, but ignore rules do not untrack files already committed. Before adding production Meta credentials, preserve your local file and remove it from the index with `git rm --cached -- .env`, then review the staged change. Do not delete your only local credential copy accidentally.

Removing a file from tracking does not remove its previous contents from Git history. If real credentials were previously published, rotate them. A Google client secret-like value was found in the old `.env.example` and has been replaced with a blank placeholder; rotate that credential in Google Cloud if it was genuine. Do not paste tokens into chat, frontend code, example files, or logs.

The migration leaves `.env` untouched. Merge only the WhatsApp/OTP entries from `.env.example` into your existing local environment; do not replace database, JWT, Razorpay, or port settings. The active server no longer uses `APIHOME_API_KEY`. Backup server files have not been migrated.

## 2. Set up Meta

1. Create or use a Meta developer app with the WhatsApp product and a WhatsApp Business account.
2. Register a WhatsApp sending number, then obtain its **Phone Number ID**. This is an API resource ID, not the sender's phone number or the WhatsApp Business Account ID.
3. Configure a production system-user access token authorized for that number with `whatsapp_business_messaging`; grant `whatsapp_business_management` where required to manage business assets/templates. Dashboard test tokens expire. Give the token only the permissions and assets the server needs.
4. Create and obtain approval for an **AUTHENTICATION** template with a **COPY_CODE** OTP button. Use its exact template name and approved language code. This implementation is for the copy-code flow, not one-tap/zero-tap authentication or a marketing/free-text template.
5. Set the template's displayed expiration to agree with `OTP_EXPIRY_MINUTES`; server-side expiry is enforced by this application.
6. Create a separate approved **UTILITY** template for the admin order alert. Add exactly nine body variables in this order:
   1. order ID;
   2. order date/time;
   3. customer/recipient name;
   4. customer phone;
   5. account email;
   6. all item lines (`product x quantity @ price`, separated by semicolons);
   7. final amount;
   8. payment method/status; and
   9. complete delivery address.
7. If customer confirmations are enabled, create another Utility template with five body variables: order ID, item summary, final amount, payment method/status, and delivery address. Obtain the customer's WhatsApp consent and pass `shipping_address.whatsapp_consent: true`; otherwise no customer event is queued.
8. Use a WhatsApp-enabled admin recipient. In Meta's test setup, add and verify the admin number in the allowed test-recipient list. Confirm account restrictions, template categorization, and pricing before production use.

Update your frontend's wording to say "Send OTP on WhatsApp" and obtain the required consent before submitting the request. This repository does not contain the frontend; its request fields do not need to change.

Official starting points:

- [WhatsApp Cloud API](https://developers.facebook.com/docs/whatsapp/cloud-api/)
- [Authentication templates](https://developers.facebook.com/docs/whatsapp/business-management-api/authentication-templates/)

## 3. Configure the server

| Variable | Required / default | Meaning |
| --- | --- | --- |
| `WHATSAPP_ACCESS_TOKEN` | Required | Server-side Bearer token. |
| `WHATSAPP_PHONE_NUMBER_ID` | Required | Registered sending number's numeric API ID. |
| `WHATSAPP_API_VERSION` | Required | Explicit supported Graph API version, such as `v23.0`; confirm support for your Meta app. The server does not guess a version. |
| `WHATSAPP_TEMPLATE_NAME` | Required | Exact approved authentication-template name. |
| `WHATSAPP_TEMPLATE_LANGUAGE` | `en_UK` | Exact approved template language. |
| `WHATSAPP_REQUEST_TIMEOUT_MS` | `10000` | Meta HTTP request timeout; positive integer up to `60000`. |
| `WHATSAPP_VERIFY_TOKEN` | Required for webhook verification | Random shared value entered in Meta's Verify token field. |
| `WHATSAPP_APP_SECRET` | Required for incoming webhooks | Meta App settings > Basic > App secret; validates `X-Hub-Signature-256`. This is different from the access token and verify token. |
| `WHATSAPP_DEFAULT_COUNTRY_CODE` | Empty | Optional numeric country calling code, such as `91`, for bare ten-digit local numbers. Do not include `+`. |
| `OTP_EXPIRY_MINUTES` | `5` | OTP lifetime; positive integer up to `1440`. |
| `OTP_RESEND_COOLDOWN` | `60` | Seconds between sends to the same normalized phone. |
| `OTP_RATE_LIMIT_WINDOW_MINUTES` | `15` | Fixed throttling window; positive integer up to `1440`. |
| `OTP_SEND_MAX_REQUESTS` | `5` | Send requests per IP in that window, including failed requests. |
| `OTP_VERIFY_MAX_ATTEMPTS` | `5` | Failed verification requests per normalized phone in that window, across IPs. |
| `OTP_VERIFY_IP_MAX_ATTEMPTS` | `20` | Failed verification requests per IP in that window, across phones. |
| `OTP_VERIFICATION_REQUIRED` | `true` | Set to `false` to temporarily let checkout accept any valid phone without OTP verification. OTP endpoints stay available; set back to `true` to restore enforcement. |
| `WHATSAPP_ADMIN_PHONE` | Required for order alerts | One admin recipient in international format. |
| `WHATSAPP_ADMIN_ORDER_TEMPLATE_NAME` | Required for order alerts | Approved nine-variable Utility template. |
| `WHATSAPP_ADMIN_ORDER_TEMPLATE_LANGUAGE` | `en_US` | Exact approved admin-template language. |
| `WHATSAPP_CUSTOMER_CONFIRMATION_ENABLED` | `false` | Enables consent-gated customer confirmation events. |
| `WHATSAPP_CUSTOMER_ORDER_TEMPLATE_NAME` | Required when enabled | Approved five-variable customer Utility template. |
| `WHATSAPP_CUSTOMER_ORDER_TEMPLATE_LANGUAGE` | `en_US` | Exact approved customer-template language. |
| `WHATSAPP_ORDER_CURRENCY` | `INR` | Prefix used when formatting order prices. |
| `WHATSAPP_ORDER_TIMEZONE` | `Asia/Kolkata` in example | IANA timezone used for the order date. |
| `WHATSAPP_NOTIFICATION_POLL_INTERVAL_MS` | `15000` | Pending-event polling interval. |
| `WHATSAPP_NOTIFICATION_CLAIM_TIMEOUT_MINUTES` | `10` | Processing claims older than this become `unknown`, never auto-retried. |
| `WHATSAPP_NOTIFICATION_BATCH_SIZE` | `10` | Maximum events processed per worker pass. |

Invalid numeric tuning values fall back to the listed defaults. Missing or malformed OTP template configuration causes send requests to return `503` without changing OTP records. Missing order-notification configuration leaves checkout operational but does not queue an admin event; the server logs only a generic configuration error. These checks validate configuration shape only; Meta validates token permissions, version support, template approval, and number registration when a message is submitted. Restart the server after changing environment settings.

### Phone format

Prefer an international phone number with `+`, country calling code, and national number. For example, `+1 202-555-0123` is normalized to `12025550123` for both the database and Meta. Digits-only international input such as `12025550123` is also supported. Spaces, parentheses, and hyphens are accepted; letters, extensions, invalid lengths, and leading-zero international numbers are rejected. `00` prefixes are not supported; use `+` instead.

A bare **ten-digit** number is deliberately treated as local: it is accepted only when `WHATSAPP_DEFAULT_COUNTRY_CODE` is configured. For example, with `91`, `9876543210` becomes `919876543210`. If the *entire international number* is ten digits, prefix it with `+` to distinguish it from local input. Local numbers of other lengths must be supplied in explicit international format. The helper checks syntax, not whether a particular number is registered on WhatsApp.

The same helper runs in send, verify, and checkout, so `phone` and `shipping_address.phone` may use equivalent formatting. Shipping-address data itself is not rewritten. Existing OTP rows that used a different phone format are not converted; request a fresh code after deployment. Allow old codes to expire before switching formats in a live deployment.

## 4. API behavior

### Request a code

```http
POST /api/send-otp
Content-Type: application/json
```

```json
{ "phone": "+12025550123" }
```

The example number is illustrative, not a delivery target. Use an authorized recipient you control for a live test.

On Meta acceptance:

```json
{ "message": "OTP submitted to WhatsApp" }
```

The backend generates a cryptographically random six-digit code, saves only its bcrypt hash, and submits an approved template. Meta receives the same code in the template body and copy-code button URL parameter. The API token goes in the Authorization header, not the URL. Neither the response nor logs expose the OTP or token.

A synchronous Meta message ID confirms **acceptance**, not delivery. The webhook endpoint authenticates and acknowledges incoming events and logs message/status counts. It does not save message content, update outbox delivery statuses, or send automatic replies. Use Meta's delivery diagnostics for individual delivery results. There is no automatic SMS fallback or automatic resend.

### Verify the code

```http
POST /api/verify-otp
Content-Type: application/json
```

```json
{ "phone": "+12025550123", "otp": "123456" }
```

Send both values as strings. The code above is an example, not a bypass; verification requires the actual delivered code.

On success:

```json
{ "success": true, "message": "Phone verified" }
```

Verification does not extend the original expiry time. Checkout still requires a verified, unexpired record matching `shipping_address.phone` and consumes the verification using the existing checkout flow. While `OTP_VERIFICATION_REQUIRED=false`, checkout skips this requirement and accepts any valid phone number without verification.

### Failure handling

- `400`: malformed phone/code, wrong code, missing record, expired code, or code already verified/replaced.
- `429`: resend cooldown or request limit. `Retry-After` indicates the wait; limiter responses also include `RateLimit` headers.
- `503`: missing or malformed WhatsApp configuration.
- `502`: Meta rejection, request timeout/network failure, or acceptance response without a message ID. The just-created OTP is deleted **by ID**, so cleanup cannot delete a newer request's code. If the database cleanup itself fails, only a generic cleanup error is logged; the row may remain until expiry/replacement.
- `500`: OTP processing/database error. Detailed database errors and raw HTTP errors are not returned to clients.

A timed-out request may already have reached Meta. Its code is invalidated if cleanup succeeds, even if a delayed message arrives; request a fresh code and use the newest message. Rate limits still apply when submission fails. Sanitized server diagnostics include numeric Meta status/error codes and a timeout flag, never full Axios request/response objects. For error `132001`, they also include the requested template name, language, and a fixed troubleshooting hint; recipient numbers, tokens, and template parameters are excluded.

### Meta error 132001: template not found

Meta cannot find the requested template for the requested language in the sending number's WhatsApp Business Account. The sample names in `.env.example` do not create templates in Meta.

1. Open WhatsApp Manager for the account that owns `WHATSAPP_PHONE_NUMBER_ID` and check that the admin Utility template is **APPROVED**.
2. Copy its exact name and language code into `WHATSAPP_ADMIN_ORDER_TEMPLATE_NAME` and `WHATSAPP_ADMIN_ORDER_TEMPLATE_LANGUAGE`. `en` and `en_US` are different codes; use the approved code. The admin template must have the nine body parameters listed above.
3. Restart the backend. OTP and customer confirmations have their own template settings; changing the admin settings does not change them.
4. Existing outbox rows keep the template name and language captured at checkout. Changing `.env` only affects new rows. Review old `failed` rows with `last_error_code='132001'` and correct their stored template configuration before any deliberate manual resend. Do not reset `sent`, `unknown`, or `processing` rows as part of this fix.

### Worker database failures

Worker logs include sanitized database error codes and numeric error numbers. `ER_NO_SUCH_TABLE` means the outbox migration has not been applied to the configured database. `ER_BAD_FIELD_ERROR` indicates an incompatible schema. Apply the migration below using your database deployment process, then restart the backend.

## 5. Order notification lifecycle

Apply the migration before deploying the new server code:

```sh
mysql -u YOUR_DB_USER -p YOUR_DB_NAME < migrations/20261112_create_whatsapp_notification_outbox.sql
```

Use your normal managed-database migration mechanism instead when applicable. Back up the database and verify that `orders.id` matches the migration's `order_id`: `VARCHAR(36)`, character set `utf8mb4`, collation `utf8mb4_0900_ai_ci`. This matches the database configured in this workspace. Adjust the foreign-key column to the exact parent type/collation for other deployments before applying it. `CREATE TABLE IF NOT EXISTS` does not repair an existing incompatible outbox table.

Checkout behavior is automatic:

1. For online orders, the server first validates the current Razorpay HMAC signature. This preserves existing behavior; it does not add a Razorpay capture/status/amount API lookup.
2. The order, its item snapshots, stock changes, and notification outbox row are committed together.
3. COD orders are queued with `payment_status=pending`; online orders use the existing `paid` status.
4. The existing checkout response is sent, then an in-process worker submits the approved Utility template. It also polls after startup to recover pending rows.
5. OTP cleanup and Meta failures are isolated from the committed order.

Outbox statuses:

- `pending`: safely queued and eligible for processing.
- `processing`: atomically claimed by one worker.
- `sent`: Meta returned a message ID. This means API acceptance, not confirmed delivery.
- `failed`: Meta explicitly rejected the request; it is not retried automatically.
- `unknown`: the request timed out/lost its response or the process left a stale claim. It is not retried automatically because Meta may already have accepted it.

The unique dedupe key uses the Razorpay payment ID for online orders and the order UUID for COD, plus notification kind and recipient. This prevents duplicate notifications for the same payment/order event. It does not by itself prevent duplicate COD orders created by repeated checkout submissions. No Shiprocket integration is present.

Review `failed` and `unknown` rows manually. Before any manual resend, check Meta logs/message status and update or clone the event deliberately; automatic resend is disabled to prioritize duplicate prevention. A crash after Meta accepts but before MySQL stores the message ID cannot be made absolutely exactly-once across two independent systems.

Customer confirmation is disabled by default. To enable it, approve the five-variable Utility template, set the customer variables, and ensure checkout provides explicit `shipping_address.whatsapp_consent: true`. Admin notifications do not depend on that flag.

## 6. Deployment considerations

- Keep the existing `phone_otps` schema with `id`, `phone`, `otp`, `expires_at`, `is_verified`, and `created_at`. It must accept country-code-inclusive phone strings of up to 15 digits and bcrypt hashes. This repository does not include the database DDL; verify column widths/defaults against your deployment without sharing secrets.
- Request limits use `express-rate-limit`'s default **process-local memory store**. They reset on restart and are not shared across instances. For multiple workers/servers, configure a shared limiter store before relying on these limits. These are time-window limits, not a durable failed-attempt counter stored with each OTP.
- The existing database resend check and delete/insert flow are not atomic across simultaneous send requests. Serialize per-phone sends or add database-level coordination before relying on strict concurrency guarantees at scale. An earlier code may be replaced by a subsequent accepted request.
- Concurrent verification requests count temporarily toward rate limits until successful responses finish. Request a resend only after the cooldown and rate-limit window allow it; a resend does not reset failed-verification rate limits.
- Behind a reverse proxy, configure Express's `trust proxy` for your actual trusted topology so the limiter sees the correct client IP. Do not set unrestricted proxy trust or trust arbitrary forwarded headers to bypass throttling. This change leaves proxy settings unchanged.
- Keep `.env` out of source control and ensure global HTTP logging/APM does not capture Authorization headers or OTP payloads.

## 7. Verification

Automated checks do not contact Meta or MySQL and do not import/start the production server:

```sh
npm test
node --check whatsapp.js
node --check otp.js
node --check order-notifications.js
node --check server.js
```

Tests use Node's built-in runner with fake database and HTTP dependencies. They exercise phone normalization, OTP behavior, the shared Meta client, order formatting, outbox deduplication/claims, provider failures, and request throttling without contacting Meta or MySQL.

For an explicitly authorized live test **after** configuring Meta and the real database:

1. Apply the migration to a disposable/staging database and confirm the server starts without outbox-table errors.
2. Start the backend using your existing environment, e.g. `node server.js`.
3. Ask `/api/send-otp` for a code for an authorized WhatsApp recipient you control. Confirm both HTTP acceptance and the approved authentication template.
4. Place one sandbox online order and one test COD order. Confirm the checkout response is unchanged, each admin message contains all nine fields, and exactly one outbox row reaches `sent` for each order.
5. Confirm online notifications occur only after valid signature verification. A later admin order status such as delivered/completed is not the trigger.
6. Test an invalid template in staging and confirm the order still succeeds while its outbox row becomes `failed`.
7. If customer confirmation is enabled, test once without consent (no customer row) and once with explicit consent (one customer row).
8. Review Meta delivery diagnostics separately because a returned message ID confirms acceptance, not delivery.

No live OTP or order-notification delivery test has been performed as part of this implementation.
