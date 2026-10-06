# DropZone SMM API v2

Production-oriented, dependency-free Node.js gateway for the Social Rank SMM API.

## Architecture

Customer/DropZone app -> DropZone API -> Social Rank API

The Social Rank credential stays server-side. Browser code must never contain `SOCIAL_RANK_API_KEY`.

## What is built in

- Live Social Rank service catalogue retrieval with short caching.
- Search/category/type filtering for the catalogue.
- Single-service lookup.
- Real supplier order creation.
- Immediate real supplier-status lookup after an order is created.
- Single and batch real supplier status endpoints (up to 100 orders per call).
- Normalized order status plus the provider's raw status/data.
- Supplier balance endpoint.
- Refill and cancel endpoints.
- Timeout handling.
- Safe retries for read-only upstream calls.
- No automatic retry of order creation after an ambiguous network failure, avoiding accidental duplicate paid orders.
- Basic idempotency-key protection for the current API instance and forwarding of an order reference to the supplier.
- Input validation against the live provider catalogue.
- Provider min/max validation.
- Drip-feed option validation.
- Request IDs and structured JSON errors.
- CORS controls.
- Basic rate limiting.
- Vercel-compatible handler.

## Real order status

DropZone never invents completion states. Status is read from Social Rank through:

`GET /api/order/{supplierOrderId}`

and, for multiple orders:

`GET /api/orders?ids=123,456`

The response includes both:

- `normalizedStatus` for a clean DropZone UI.
- `providerStatus` and `raw`/`providerResponse` for exact supplier truth.

A DropZone frontend/backend can poll these endpoints while an order is active. A later database/cron layer can also use the same endpoints for background synchronization.

Important serverless note: Vercel functions are stateless/ephemeral, so this API does not pretend to maintain an in-process forever-running order watcher. Persistent background synchronization belongs in DropZone's database/automation layer and should call the real status endpoints here.

## Security

Use a server-side secret when your own backend calls the protected app endpoints:

`x-dropzone-app-secret: <DROPZONE_APP_SECRET>`

Internal supplier/admin operations use:

`x-dropzone-admin-secret: <INTERNAL_API_SECRET>`

Health is public and does not expose secrets.

Set `ALLOWED_ORIGINS` to your exact production web origin(s). For local testing it can be empty.

## Endpoints

Public:

- `GET /`
- `GET /api/health`

App-authenticated:

- `GET /api/services`
- `GET /api/services/{serviceId}`
- `POST /api/order`
- `GET /api/order/{supplierOrderId}`
- `GET /api/orders?ids=1,2,3`

Internal-authenticated:

- `GET /api/balance`
- `POST /api/refill`
- `POST /api/cancel`

## Create an order

Request headers:

`x-dropzone-app-secret: ...`

Optional:

`x-idempotency-key: a-unique-key-for-this-order-attempt`

Body:

```json
{
  "service": 4342,
  "url": "https://example.com/target",
  "quantity": 1000
}
```

Optional supported fields:

- `comments` (string or array)
- `order_reference` / `order_refference`
- `runs`
- `interval`

The response returns the real Social Rank order ID and, when immediately available, the real current provider status.

Do not send `runs` or `interval` unless the selected provider service advertises drip-feed support.

## Status

```text
GET /api/order/23501
x-dropzone-app-secret: ...
```

Returns the real supplier status, charge, start count, remains, currency, and a normalized DropZone status.

## Balance

```text
GET /api/balance
x-dropzone-admin-secret: ...
```

This is the supplier credit balance associated with the Social Rank API key. It is not a DropZone customer's wallet balance.

## Local setup

Create `.env` from `.env.example`, then fill in the rotated supplier key and fresh secrets.

Start:

```bash
node server.js
```

Health:

```bash
curl http://127.0.0.1:3000/api/health
```

The project intentionally contains no test/demo scripts. `npm run verify:config` only performs syntax checks.

## Vercel

Deploy the repository, then add the same environment variables in Vercel Project Settings -> Environment Variables.

Never commit `.env`.

Recommended production values:

- `SOCIAL_RANK_API_KEY` = rotated supplier key
- `DROPZONE_APP_SECRET` = fresh random secret
- `INTERNAL_API_SECRET` = fresh random secret
- `ALLOWED_ORIGINS` = exact Base44/custom domain(s)

## Order-status automation

The supplier API is the source of truth. This gateway provides real-time-on-request status and batch status retrieval.

For automatic background updates in a persistent DropZone order database, have the DropZone backend periodically call `/api/order/{supplierOrderId}` or `/api/orders?ids=...` for active orders and save the returned real status. That avoids fake statuses and works with the supplier's real state.
