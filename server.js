const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

loadDotEnv();

const PORT = Number(process.env.PORT || 3000);
const UPSTREAM_URL = process.env.SOCIAL_RANK_API_URL || 'https://www.socialranksmmpannel.com/api/v2';
const API_KEY = process.env.SOCIAL_RANK_API_KEY || '';
const DROPZONE_APP_SECRET = process.env.DROPZONE_APP_SECRET || '';
const INTERNAL_API_SECRET = process.env.INTERNAL_API_SECRET || '';
const UPSTREAM_TIMEOUT_MS = clampInt(process.env.UPSTREAM_TIMEOUT_MS, 5000, 60000, 15000);
const SERVICE_CACHE_TTL_MS = clampInt(process.env.SERVICE_CACHE_TTL_MS, 10000, 300000, 60000);
const UPSTREAM_READ_RETRIES = clampInt(process.env.UPSTREAM_READ_RETRIES, 0, 3, 2);
const MAX_BODY_BYTES = clampInt(process.env.MAX_BODY_BYTES, 16384, 524288, 262144);
const RATE_LIMIT_WINDOW_MS = clampInt(process.env.RATE_LIMIT_WINDOW_MS, 10000, 300000, 60000);
const RATE_LIMIT_MAX = clampInt(process.env.RATE_LIMIT_MAX, 10, 1000, 120);

let serviceCache = { data: null, expiresAt: 0, fetchedAt: 0 };
const rateBuckets = new Map();
const recentOrderRefs = new Map();

function clampInt(value, min, max, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(n)));
}

function loadDotEnv() {
  const envPath = path.join(process.cwd(), '.env');
  if (!fs.existsSync(envPath)) return;
  for (const line of fs.readFileSync(envPath, 'utf8').split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const i = trimmed.indexOf('=');
    if (i <= 0) continue;
    const key = trimmed.slice(0, i).trim();
    let value = trimmed.slice(i + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (process.env[key] === undefined) process.env[key] = value;
  }
}

function requestId() {
  return crypto.randomUUID();
}

function safeEqual(a, b) {
  const aa = Buffer.from(String(a || ''));
  const bb = Buffer.from(String(b || ''));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

function sendJson(res, status, data, extraHeaders = {}) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...extraHeaders
  });
  res.end(JSON.stringify(data));
}

function jsonError(res, id, status, code, message, extra = {}) {
  return sendJson(res, status, {
    ok: false,
    error: { code, message },
    requestId: id,
    ...extra
  });
}

function corsHeaders(origin) {
  const configured = (process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map(x => x.trim())
    .filter(Boolean);

  // Empty ALLOWED_ORIGINS is convenient for local/server-to-server development.
  // In production, set it to your exact Base44/custom-domain origins.
  if (!origin) return {};
  if (configured.length && !configured.includes(origin)) return {};

  return {
    'Access-Control-Allow-Origin': origin,
    'Vary': 'Origin',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-DropZone-App-Secret, X-DropZone-Admin-Secret, X-Idempotency-Key',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS'
  };
}

function extractSecret(req, preferredHeader) {
  const direct = req.headers[preferredHeader];
  if (direct) return String(direct);
  const auth = String(req.headers.authorization || '').trim();
  if (/^Bearer\s+/i.test(auth)) return auth.replace(/^Bearer\s+/i, '').trim();
  return '';
}

function requireSecret(req, res, id, secret, headerName, notConfiguredCode, label) {
  if (!secret || /CHANGE_THIS|PUT_YOUR_|REPLACE_ME/.test(secret)) {
    jsonError(res, id, 503, notConfiguredCode, `${label} authentication is not configured.`);
    return false;
  }
  if (!safeEqual(extractSecret(req, headerName), secret)) {
    jsonError(res, id, 401, 'UNAUTHORIZED', `Valid ${label.toLowerCase()} authentication is required.`);
    return false;
  }
  return true;
}

function requireApiKeyConfigured(res, id) {
  if (!API_KEY || /PUT_YOUR_|CHANGE_THIS|REPLACE_ME/.test(API_KEY)) {
    jsonError(res, id, 500, 'UPSTREAM_KEY_NOT_CONFIGURED', 'The Social Rank API key is not configured on the server.');
    return false;
  }
  return true;
}

function parseInteger(name, value) {
  if (value === undefined || value === null || value === '') return null;
  const n = Number(value);
  if (!Number.isInteger(n)) {
    throw Object.assign(new Error(`${name} must be an integer.`), { status: 400, code: 'INVALID_INPUT' });
  }
  return n;
}

function parseBoolean(value, fallback = false) {
  if (value === undefined || value === null || value === '') return fallback;
  if (value === true || value === 'true' || value === '1') return true;
  if (value === false || value === 'false' || value === '0') return false;
  throw Object.assign(new Error('Boolean value is invalid.'), { status: 400, code: 'INVALID_INPUT' });
}

function normalizeComments(value) {
  if (value === undefined || value === null || value === '') return undefined;
  if (Array.isArray(value)) {
    const arr = value.map(x => String(x).trim()).filter(Boolean);
    return arr.length ? arr.join('\n') : undefined;
  }
  const s = String(value).trim();
  return s || undefined;
}

function assertString(name, value, maxLength) {
  if (typeof value !== 'string' || !value.trim()) {
    throw Object.assign(new Error(`${name} is required.`), { status: 400, code: 'INVALID_INPUT' });
  }
  const trimmed = value.trim();
  if (trimmed.length > maxLength) {
    throw Object.assign(new Error(`${name} is too long.`), { status: 400, code: 'INVALID_INPUT' });
  }
  return trimmed;
}

function normalizeProviderStatus(rawStatus) {
  const raw = String(rawStatus || '').trim();
  const lower = raw.toLowerCase();
  if (!raw) return 'unknown';
  if (lower.includes('complete')) return 'completed';
  if (lower.includes('partial')) return 'partial';
  if (lower.includes('cancel')) return 'cancelled';
  if (lower.includes('fail') || lower.includes('error')) return 'failed';
  if (lower.includes('refund')) return 'refunded';
  if (lower.includes('pending') || lower.includes('await')) return 'pending';
  if (lower.includes('process') || lower.includes('progress') || lower.includes('in progress')) return 'processing';
  return 'other';
}

function estimateCharge(service, quantity) {
  const rate = Number(service?.rate);
  if (!Number.isFinite(rate) || !Number.isFinite(quantity)) return null;
  // Standard SMM panel pricing is rate per 1,000 units.
  return Number(((rate * quantity) / 1000).toFixed(12));
}

function cleanupMaps() {
  const now = Date.now();
  for (const [key, value] of rateBuckets) {
    if (value.resetAt <= now) rateBuckets.delete(key);
  }
  for (const [key, value] of recentOrderRefs) {
    if (value <= now) recentOrderRefs.delete(key);
  }
}

function clientIdentity(req) {
  const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return forwarded || req.socket?.remoteAddress || 'unknown';
}

function rateLimit(req, res, id) {
  if (!RATE_LIMIT_MAX) return true;
  cleanupMaps();
  const key = clientIdentity(req);
  const now = Date.now();
  let bucket = rateBuckets.get(key);
  if (!bucket || bucket.resetAt <= now) {
    bucket = { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS };
    rateBuckets.set(key, bucket);
  }
  bucket.count += 1;
  if (bucket.count > RATE_LIMIT_MAX) {
    res.setHeader('Retry-After', String(Math.ceil((bucket.resetAt - now) / 1000)));
    jsonError(res, id, 429, 'RATE_LIMITED', 'Too many requests. Please retry shortly.');
    return false;
  }
  return true;
}

async function readBody(req) {
  return await new Promise((resolve, reject) => {
    let raw = '';
    let settled = false;
    req.on('data', chunk => {
      raw += chunk.toString();
      if (raw.length > MAX_BODY_BYTES && !settled) {
        settled = true;
        reject(Object.assign(new Error('Request body is too large.'), { status: 413, code: 'BODY_TOO_LARGE' }));
        req.destroy();
      }
    });
    req.on('end', () => {
      if (settled) return;
      if (!raw) return resolve({});
      const contentType = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
      try {
        if (contentType === 'application/x-www-form-urlencoded') return resolve(Object.fromEntries(new URLSearchParams(raw)));
        resolve(JSON.parse(raw));
      } catch {
        reject(Object.assign(new Error('Invalid request body.'), { status: 400, code: 'INVALID_BODY' }));
      }
    });
    req.on('error', err => {
      if (!settled) reject(err);
    });
  });
}

function isRetryableReadError(err) {
  if (!err) return false;
  if (err.code === 'UPSTREAM_TIMEOUT' || err.code === 'UPSTREAM_NETWORK_ERROR') return true;
  return Number(err.httpStatus) === 408 || Number(err.httpStatus) === 425 || Number(err.httpStatus) === 429 || Number(err.httpStatus) >= 500;
}

async function callSocialRank(action, params = {}, options = {}) {
  if (!API_KEY) throw Object.assign(new Error('SOCIAL_RANK_API_KEY is not configured.'), { code: 'KEY_NOT_CONFIGURED' });

  const allowRetry = options.allowRetry === true;
  const attempts = allowRetry ? UPSTREAM_READ_RETRIES + 1 : 1;
  let lastError;

  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      const form = new URLSearchParams();
      form.set('key', API_KEY);
      form.set('action', action);
      for (const [key, value] of Object.entries(params)) {
        if (value === undefined || value === null || value === '') continue;
        form.set(key, String(value));
      }

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);

      let response;
      let raw;
      try {
        response = await fetch(UPSTREAM_URL, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
          },
          body: form,
          signal: controller.signal
        });
        raw = await response.text();
      } catch (networkErr) {
        const isTimeout = networkErr?.name === 'AbortError';
        throw Object.assign(new Error(isTimeout ? 'Social Rank request timed out.' : 'Could not reach Social Rank.'), {
          code: isTimeout ? 'UPSTREAM_TIMEOUT' : 'UPSTREAM_NETWORK_ERROR'
        });
      } finally {
        clearTimeout(timeout);
      }

      let data;
      try {
        data = JSON.parse(raw);
      } catch {
        throw Object.assign(new Error('Social Rank returned a non-JSON response.'), {
          code: 'UPSTREAM_NON_JSON',
          httpStatus: response.status,
          raw: raw.slice(0, 500)
        });
      }

      if (!response.ok) {
        throw Object.assign(new Error(String(data?.error || `Social Rank HTTP ${response.status}`)), {
          code: 'UPSTREAM_HTTP_ERROR',
          httpStatus: response.status,
          upstream: data
        });
      }

      return data;
    } catch (err) {
      lastError = err;
      if (!allowRetry || !isRetryableReadError(err) || attempt >= attempts - 1) break;
      const delay = Math.min(1500 * 2 ** attempt, 5000);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }

  throw lastError || new Error('Social Rank request failed.');
}

async function getServices(forceRefresh = false) {
  if (!forceRefresh && serviceCache.data && serviceCache.expiresAt > Date.now()) return serviceCache.data;
  const services = await callSocialRank('services', {}, { allowRetry: true });
  if (services?.error) {
    throw Object.assign(new Error(String(services.error)), { code: 'PROVIDER_ERROR', upstream: services });
  }
  if (!Array.isArray(services)) {
    throw Object.assign(new Error('Unexpected services response from Social Rank.'), { code: 'INVALID_SERVICES_RESPONSE' });
  }
  serviceCache = {
    data: services,
    expiresAt: Date.now() + SERVICE_CACHE_TTL_MS,
    fetchedAt: Date.now()
  };
  return services;
}

function findService(services, serviceId) {
  const numeric = Number(serviceId);
  return services.find(s => Number(s.service) === numeric);
}

async function validateOrder(body) {
  const serviceId = parseInteger('service', body.service);
  if (!serviceId || serviceId < 1) {
    throw Object.assign(new Error('service must be a positive integer.'), { status: 400, code: 'INVALID_SERVICE' });
  }

  let services = await getServices(false);
  let service = findService(services, serviceId);
  if (!service) {
    services = await getServices(true);
    service = findService(services, serviceId);
  }
  if (!service) {
    throw Object.assign(new Error(`Service ${serviceId} was not found in the current Social Rank catalogue.`), { status: 400, code: 'UNKNOWN_SERVICE' });
  }

  const url = assertString('url', body.url, 2000);
  const quantity = parseInteger('quantity', body.quantity);
  if (quantity === null || quantity <= 0) {
    throw Object.assign(new Error('quantity must be a positive integer.'), { status: 400, code: 'INVALID_QUANTITY' });
  }

  const min = Number(service.min);
  const max = Number(service.max);
  if (Number.isFinite(min) && quantity < min) {
    throw Object.assign(new Error(`quantity is below provider minimum ${service.min}.`), { status: 400, code: 'QUANTITY_BELOW_MIN' });
  }
  if (Number.isFinite(max) && quantity > max) {
    throw Object.assign(new Error(`quantity is above provider maximum ${service.max}.`), { status: 400, code: 'QUANTITY_ABOVE_MAX' });
  }

  const runs = parseInteger('runs', body.runs);
  const interval = parseInteger('interval', body.interval);
  if (runs !== null && runs <= 0) throw Object.assign(new Error('runs must be positive when supplied.'), { status: 400, code: 'INVALID_RUNS' });
  if (interval !== null && interval < 0) throw Object.assign(new Error('interval cannot be negative.'), { status: 400, code: 'INVALID_INTERVAL' });
  if ((runs !== null || interval !== null) && service.dripfeed !== true) {
    throw Object.assign(new Error('This service does not advertise drip-feed support.'), { status: 400, code: 'DRIPFEED_NOT_SUPPORTED' });
  }

  const referenceRaw = body.order_reference ?? body.order_refference ?? body.orderReference;
  const idempotencyKey = String(body.idempotencyKey || body.idempotency_key || '').trim() || String(Math.random()).slice(2);
  const reference = referenceRaw === undefined || referenceRaw === null || referenceRaw === '' ? `DZ-${Date.now()}-${idempotencyKey}` : String(referenceRaw).trim();
  if (reference.length > 200) throw Object.assign(new Error('order_reference is too long.'), { status: 400, code: 'INVALID_ORDER_REFERENCE' });

  const comments = normalizeComments(body.comments);
  if (comments && comments.length > 50000) throw Object.assign(new Error('comments are too long.'), { status: 400, code: 'INVALID_COMMENTS' });

  return {
    serviceId,
    service,
    url,
    quantity,
    comments,
    orderReference: reference,
    runs,
    interval,
    estimatedProviderCharge: estimateCharge(service, quantity)
  };
}

function mapOrderStatus(providerStatus) {
  const status = providerStatus && typeof providerStatus === 'object' ? providerStatus : {};
  const raw = status.status;
  return {
    providerStatus: raw ?? null,
    normalizedStatus: normalizeProviderStatus(raw),
    charge: status.charge ?? null,
    startCount: status.start_count ?? null,
    remains: status.remains ?? null,
    currency: status.currency ?? null,
    raw: status
  };
}

function providerErrorToResponse(res, id, data, fallbackCode = 'PROVIDER_ERROR') {
  if (!data?.error) return false;
  return jsonError(res, id, 400, fallbackCode, String(data.error), { providerResponse: data });
}

function getSupplierOrderIdFromResponse(upstream) {
  const value = upstream?.order;
  if (value === undefined || value === null || value === '') return null;
  const numeric = Number(value);
  return Number.isInteger(numeric) && numeric > 0 ? numeric : String(value);
}

async function route(req, res, id) {
  const parsed = new URL(req.url, 'http://localhost');
  const pathname = parsed.pathname.replace(/\/+$/, '') || '/';

  if (req.method === 'OPTIONS') return sendJson(res, 204, null, { 'Content-Length': '0' });

  if (req.method === 'GET' && pathname === '/') {
    return sendJson(res, 200, {
      ok: true,
      name: 'DropZone SMM API',
      version: '2.0.0',
      docs: '/api/health',
      requestId: id
    });
  }

  if (req.method === 'GET' && pathname === '/api/health') {
    let upstreamReachable = null;
    let serviceCount = null;
    let balance = null;

    if (API_KEY && !/PUT_YOUR_|CHANGE_THIS|REPLACE_ME/.test(API_KEY)) {
      try {
        const services = await getServices(false);
        upstreamReachable = true;
        serviceCount = services.length;
      } catch {
        upstreamReachable = false;
      }
    }

    return sendJson(res, 200, {
      ok: true,
      service: 'dropzone-smm-api',
      version: '2.0.0',
      upstream: 'social-rank',
      upstreamConfigured: Boolean(API_KEY && !/PUT_YOUR_|CHANGE_THIS|REPLACE_ME/.test(API_KEY)),
      upstreamReachable,
      cachedServiceCount: serviceCount,
      timestamp: new Date().toISOString(),
      requestId: id
    });
  }

  if (req.method === 'GET' && pathname === '/api/services') {
    if (!requireSecret(req, res, id, DROPZONE_APP_SECRET, 'x-dropzone-app-secret', 'APP_SECRET_NOT_CONFIGURED', 'DropZone app')) return;
    if (!requireApiKeyConfigured(res, id)) return;

    const forceRefresh = parsed.searchParams.get('refresh') === '1';
    const search = String(parsed.searchParams.get('search') || '').trim().toLowerCase();
    const category = String(parsed.searchParams.get('category') || '').trim().toLowerCase();
    const type = String(parsed.searchParams.get('type') || '').trim().toLowerCase();
    const limit = clampInt(parsed.searchParams.get('limit'), 1, 1000, 1000);

    try {
      const services = await getServices(forceRefresh);
      const filtered = services.filter(service => {
        if (search && !`${service.name || ''} ${service.category || ''} ${service.description || ''}`.toLowerCase().includes(search)) return false;
        if (category && !String(service.category || '').toLowerCase().includes(category)) return false;
        if (type && String(service.type || '').toLowerCase() !== type) return false;
        return true;
      });
      return sendJson(res, 200, {
        ok: true,
        count: filtered.length,
        totalCount: services.length,
        cachedAt: serviceCache.fetchedAt ? new Date(serviceCache.fetchedAt).toISOString() : null,
        services: filtered.slice(0, limit),
        requestId: id
      });
    } catch (err) {
      console.error('services error', id, err);
      return jsonError(res, id, 502, err.code || 'UPSTREAM_ERROR', err.message || 'Could not fetch services.');
    }
  }

  const serviceMatch = pathname.match(/^\/api\/services\/(\d+)$/);
  if (req.method === 'GET' && serviceMatch) {
    if (!requireSecret(req, res, id, DROPZONE_APP_SECRET, 'x-dropzone-app-secret', 'APP_SECRET_NOT_CONFIGURED', 'DropZone app')) return;
    if (!requireApiKeyConfigured(res, id)) return;
    try {
      let services = await getServices(false);
      let service = findService(services, serviceMatch[1]);
      if (!service) {
        services = await getServices(true);
        service = findService(services, serviceMatch[1]);
      }
      if (!service) return jsonError(res, id, 404, 'UNKNOWN_SERVICE', 'Service was not found in the current Social Rank catalogue.');
      return sendJson(res, 200, { ok: true, service, requestId: id });
    } catch (err) {
      console.error('service lookup error', id, err);
      return jsonError(res, id, 502, err.code || 'UPSTREAM_ERROR', err.message || 'Could not fetch service.');
    }
  }

  if (req.method === 'POST' && pathname === '/api/order') {
    if (!requireSecret(req, res, id, DROPZONE_APP_SECRET, 'x-dropzone-app-secret', 'APP_SECRET_NOT_CONFIGURED', 'DropZone app')) return;
    if (!requireApiKeyConfigured(res, id)) return;

    const idempotencyKey = String(req.headers['x-idempotency-key'] || '').trim();
    if (idempotencyKey && (idempotencyKey.length < 8 || idempotencyKey.length > 128)) {
      return jsonError(res, id, 400, 'INVALID_IDEMPOTENCY_KEY', 'X-Idempotency-Key must be 8-128 characters when supplied.');
    }

    try {
      const body = await readBody(req);
      if (idempotencyKey) {
        const refKey = `idempotency:${idempotencyKey}`;
        cleanupMaps();
        if (recentOrderRefs.has(refKey)) {
          return jsonError(res, id, 409, 'DUPLICATE_REQUEST', 'An order request with this idempotency key was recently accepted by this API instance.');
        }
        recentOrderRefs.set(refKey, Date.now() + 15 * 60 * 1000);
      }

      const order = await validateOrder({ ...body, idempotencyKey });
      const upstream = await callSocialRank('add', {
        service: order.serviceId,
        url: order.url,
        quantity: order.quantity,
        comments: order.comments,
        order_refference: order.orderReference,
        runs: order.runs,
        interval: order.interval
      }, { allowRetry: false });

      const providerError = providerErrorToResponse(res, id, upstream);
      if (providerError) {
        if (idempotencyKey) recentOrderRefs.delete(`idempotency:${idempotencyKey}`);
        return providerError;
      }

      const providerOrderId = getSupplierOrderIdFromResponse(upstream);
      if (!providerOrderId) {
        if (idempotencyKey) recentOrderRefs.delete(`idempotency:${idempotencyKey}`);
        return jsonError(res, id, 502, 'INVALID_ORDER_RESPONSE', 'Social Rank did not return an order ID.', { providerResponse: upstream });
      }

      // Fetch the actual provider status immediately so the first DropZone response
      // already contains real supplier state rather than a fabricated state.
      let initialStatus = null;
      try {
        const status = await callSocialRank('status', { order: providerOrderId }, { allowRetry: true });
        if (!status?.error) initialStatus = mapOrderStatus(status);
      } catch (statusErr) {
        console.warn('initial status lookup failed', id, statusErr?.message || statusErr);
      }

      return sendJson(res, 201, {
        ok: true,
        order: {
          providerOrderId,
          supplier: 'social-rank',
          serviceId: order.serviceId,
          serviceName: order.service?.name || null,
          quantity: order.quantity,
          target: order.url,
          supplierOrderReference: order.orderReference,
          estimatedProviderCharge: order.estimatedProviderCharge,
          status: initialStatus
        },
        providerResponse: upstream,
        requestId: id
      });
    } catch (err) {
      console.error('order error', id, err);
      // A transport timeout after the provider may have accepted an ADD request is
      // intentionally surfaced as unknown state, not retried, to avoid duplicates.
      return jsonError(res, id, err.status || 502, err.code || 'ORDER_FAILED', err.message || 'Could not create order.', {
        ambiguousProviderState: ['UPSTREAM_TIMEOUT', 'UPSTREAM_NETWORK_ERROR'].includes(err.code || '')
      });
    }
  }

  const orderMatch = pathname.match(/^\/api\/order\/(\d+)$/);
  if (req.method === 'GET' && orderMatch) {
    if (!requireSecret(req, res, id, DROPZONE_APP_SECRET, 'x-dropzone-app-secret', 'APP_SECRET_NOT_CONFIGURED', 'DropZone app')) return;
    if (!requireApiKeyConfigured(res, id)) return;
    const providerOrderId = Number(orderMatch[1]);
    try {
      const upstream = await callSocialRank('status', { order: providerOrderId }, { allowRetry: true });
      if (providerErrorToResponse(res, id, upstream)) return;
      return sendJson(res, 200, {
        ok: true,
        orderId: providerOrderId,
        status: mapOrderStatus(upstream),
        providerResponse: upstream,
        requestId: id
      });
    } catch (err) {
      console.error('status error', id, err);
      return jsonError(res, id, 502, err.code || 'UPSTREAM_ERROR', err.message || 'Could not fetch order status.');
    }
  }

  if (req.method === 'GET' && pathname === '/api/orders') {
    if (!requireSecret(req, res, id, DROPZONE_APP_SECRET, 'x-dropzone-app-secret', 'APP_SECRET_NOT_CONFIGURED', 'DropZone app')) return;
    if (!requireApiKeyConfigured(res, id)) return;
    const raw = String(parsed.searchParams.get('ids') || parsed.searchParams.get('orders') || '').trim();
    if (!raw) return jsonError(res, id, 400, 'MISSING_ORDER_IDS', 'Provide ids=1,2,3 (maximum 100).');
    const ids = raw.split(',').map(x => Number(x.trim()));
    if (ids.length > 100 || ids.some(x => !Number.isInteger(x) || x < 1)) {
      return jsonError(res, id, 400, 'INVALID_ORDER_IDS', 'Order IDs must be 1-100 positive integers.');
    }
    try {
      const upstream = await callSocialRank('status', { orders: ids.join(',') }, { allowRetry: true });
      if (providerErrorToResponse(res, id, upstream)) return;

      const normalized = Array.isArray(upstream)
        ? upstream.map(item => ({ ...mapOrderStatus(item), providerOrderId: item?.order ?? item?.id ?? null }))
        : upstream;

      return sendJson(res, 200, {
        ok: true,
        orders: normalized,
        providerResponse: upstream,
        requestId: id
      });
    } catch (err) {
      console.error('multiple status error', id, err);
      return jsonError(res, id, 502, err.code || 'UPSTREAM_ERROR', err.message || 'Could not fetch order statuses.');
    }
  }

  if (req.method === 'GET' && pathname === '/api/balance') {
    if (!requireSecret(req, res, id, INTERNAL_API_SECRET, 'x-dropzone-admin-secret', 'ADMIN_SECRET_NOT_CONFIGURED', 'Internal')) return;
    if (!requireApiKeyConfigured(res, id)) return;
    try {
      const upstream = await callSocialRank('balance', {}, { allowRetry: true });
      if (providerErrorToResponse(res, id, upstream)) return;
      const value = Number(upstream?.balance);
      return sendJson(res, 200, {
        ok: true,
        balance: {
          balance: upstream?.balance ?? null,
          numericBalance: Number.isFinite(value) ? value : null,
          currency: upstream?.currency ?? null
        },
        providerResponse: upstream,
        requestId: id
      });
    } catch (err) {
      console.error('balance error', id, err);
      return jsonError(res, id, 502, err.code || 'UPSTREAM_ERROR', err.message || 'Could not fetch balance.');
    }
  }

  for (const action of ['refill', 'cancel']) {
    if (req.method === 'POST' && pathname === `/api/${action}`) {
      if (!requireSecret(req, res, id, INTERNAL_API_SECRET, 'x-dropzone-admin-secret', 'ADMIN_SECRET_NOT_CONFIGURED', 'Internal')) return;
      if (!requireApiKeyConfigured(res, id)) return;
      try {
        const body = await readBody(req);
        const orderId = parseInteger('order', body.order ?? body.orderId);
        if (!orderId || orderId < 1) return jsonError(res, id, 400, 'INVALID_ORDER_ID', 'order must be a positive integer.');
        const upstream = await callSocialRank(action, { order: orderId }, { allowRetry: false });
        if (providerErrorToResponse(res, id, upstream)) return;
        return sendJson(res, 200, { ok: true, action, order: orderId, result: upstream, requestId: id });
      } catch (err) {
        console.error(`${action} error`, id, err);
        return jsonError(res, id, err.status || 502, err.code || 'PROVIDER_ERROR', err.message || `Could not ${action} order.`);
      }
    }
  }

  return jsonError(res, id, 404, 'NOT_FOUND', 'Endpoint not found.');
}

async function handler(req, res) {
  const id = requestId();
  for (const [key, value] of Object.entries(corsHeaders(req.headers.origin))) res.setHeader(key, value);
  res.setHeader('X-Request-Id', id);

  if (!rateLimit(req, res, id)) return;

  try {
    await route(req, res, id);
  } catch (err) {
    console.error('unhandled error', id, err);
    if (!res.headersSent) jsonError(res, id, 500, 'INTERNAL_ERROR', 'Internal server error.');
  }
}

if (require.main === module) {
  http.createServer(handler).listen(PORT, '127.0.0.1', () => {
    console.log(`DropZone SMM API running on http://127.0.0.1:${PORT}`);
    console.log(`Health:   http://127.0.0.1:${PORT}/api/health`);
    console.log(`Services: http://127.0.0.1:${PORT}/api/services`);
  });
}

module.exports = handler;
