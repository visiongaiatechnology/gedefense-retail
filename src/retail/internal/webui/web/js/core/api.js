/**
 * Typed access to the versioned HTTP API. Every endpoint here exists in
 * docs/retail/api-contract.md — the UI never invents fields or endpoints.
 * Errors carry the API error code and request id so the UI can show a concrete,
 * supportable message instead of a generic failure.
 */
import { API_BASE, GATE_API_BASE, LIST_LIMIT } from './config.js';
import { t } from '../i18n/index.js';
import { getGateToken, getToken } from './auth.js';

const DEFAULT_TIMEOUT_MS = 20_000;
const EXPORT_TIMEOUT_MS = 30_000;

const STATUS_MESSAGES = {
  400: 'Die Anfrage wurde vom Gateway abgelehnt.',
  401: t('api.error.401'),
  403: t('api.error.403'),
  404: 'Ressource wurde nicht gefunden.',
  409: 'Konflikt mit dem aktuellen Zustand.',
  429: 'Zu viele Anfragen an das Gateway.',
  500: 'Interner Fehler im Gateway.',
  503: t('api.error.503'),
};

export class ApiError extends Error {
  constructor({ status = 0, code = 'network', message = '', requestId = '', retryAfter = 0, serverMessage = '' }) {
    super(message || code);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.requestId = requestId;
    this.retryAfter = retryAfter;
    this.serverMessage = serverMessage;
  }

  get isNetworkError() {
    return this.status === 0;
  }

  get isAuthError() {
    return this.status === 401;
  }

  get isPermissionError() {
    return this.status === 403;
  }

  /** Compact diagnostic line for the UI (no secrets, no internal paths). */
  get diagnostic() {
    const parts = [];
    if (this.status) parts.push(`HTTP ${this.status}`);
    parts.push(`Code: ${this.code}`);
    if (this.requestId) parts.push(`Request-ID: ${this.requestId}`);
    if (this.serverMessage) parts.push(`Gateway: ${this.serverMessage}`);
    return parts.join(' · ');
  }
}

let unauthorizedHandler = () => {};
let gateUnauthorizedHandler = () => {};

export function setUnauthorizedHandler(handler) {
  unauthorizedHandler = typeof handler === 'function' ? handler : () => {};
}

/** Gate sessions expire independently from the monitoring token. */
export function setGateUnauthorizedHandler(handler) {
  gateUnauthorizedHandler = typeof handler === 'function' ? handler : () => {};
}

function buildUrl(base, path, params) {
  const url = new URL(base + path, window.location.origin);
  if (params) {
    for (const [key, value] of Object.entries(params)) {
      if (value === undefined || value === null || value === '') continue;
      url.searchParams.set(key, String(value));
    }
  }
  return url;
}

function encodeSegment(value) {
  return encodeURIComponent(String(value));
}

async function errorFromResponse(response) {
  let code = 'http_error';
  let serverMessage = '';
  let requestId = response.headers.get('x-request-id') || '';
  let retryAfter = Number(response.headers.get('retry-after') || 0);
  try {
    const data = await response.json();
    if (data && data.error) {
      code = data.error.code || code;
      serverMessage = data.error.message || '';
      requestId = data.error.request_id || requestId;
    }
  } catch {
    /* non-JSON error body: keep the status-derived message */
  }
  const base = STATUS_MESSAGES[response.status] || `Gateway antwortete mit HTTP ${response.status}.`;
  const message = response.status === 429 && retryAfter > 0 ? `${base} Erneut in ${retryAfter} s.` : base;
  return new ApiError({ status: response.status, code, message, requestId, retryAfter, serverMessage });
}

/**
 * Shared authenticated JSON request used by both the monitoring API and the
 * Access Gate API. The two services have separate tokens and 401 handlers.
 *
 * @param {{base: string, path: string, method?: string, params?: object, body?: unknown, headers?: object, signal?: AbortSignal, timeoutMs?: number, raw?: boolean, token?: string, onUnauthorized?: ()=>void, skipUnauthorizedHandler?: boolean}} options
 */
async function performRequest(options) {
  const {
    base,
    path,
    method = 'GET',
    params,
    body,
    headers: customHeaders,
    signal,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    raw = false,
    token = '',
    onUnauthorized = null,
    skipUnauthorizedHandler = false,
  } = options;

  const controller = new AbortController();
  const abortFromCaller = () => controller.abort();
  if (signal) {
    if (signal.aborted) controller.abort();
    else signal.addEventListener('abort', abortFromCaller, { once: true });
  }
  const timer = window.setTimeout(
    () => controller.abort(new DOMException(t('api.error.timeout_label'), 'TimeoutError')),
    timeoutMs
  );

  const headers = { Accept: 'application/json', ...(customHeaders || {}) };
  if (token) headers.Authorization = `Bearer ${token}`;

  let payload;
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    payload = JSON.stringify(body);
  }

  try {
    const response = await fetch(buildUrl(base, path, params), {
      method,
      headers,
      body: payload,
      signal: controller.signal,
      cache: 'no-store',
      credentials: 'same-origin',
      redirect: 'error',
    });

    if (response.status === 401) {
      if (!skipUnauthorizedHandler) onUnauthorized?.();
      throw await errorFromResponse(response);
    }
    if (!response.ok) throw await errorFromResponse(response);
    if (raw) return response;
    if (response.status === 204) return null;

    const text = await response.text();
    if (!text) return null;
    try {
      return JSON.parse(text);
    } catch {
      throw new ApiError({
        status: response.status,
        code: 'invalid_response',
        message: 'Die Gateway-Antwort konnte nicht gelesen werden.',
      });
    }
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (error && (error.name === 'AbortError' || error.name === 'TimeoutError')) {
      throw new ApiError({
        status: 0,
        code: 'timeout',
        message: t('api.error.timeout'),
      });
    }
    throw new ApiError({
      status: 0,
      code: 'network',
      message: t('stream.offline'),
    });
  } finally {
    window.clearTimeout(timer);
    if (signal) signal.removeEventListener('abort', abortFromCaller);
  }
}

/** Monitoring API request (retaild). */
function request(path, options = {}) {
  return performRequest({
    ...options,
    base: API_BASE,
    path,
    token: getToken(),
    onUnauthorized: unauthorizedHandler,
  });
}

/** Access Gate API request (retailgate). */
function gateRequest(path, options = {}) {
  const { skipAuth = false, skipUnauthorizedHandler = false, ...rest } = options;
  return performRequest({
    ...rest,
    base: GATE_API_BASE,
    path,
    token: skipAuth ? '' : getGateToken(),
    onUnauthorized: gateUnauthorizedHandler,
    skipUnauthorizedHandler,
  });
}

function listParams({ site_id, limit = LIST_LIMIT, offset = 0, ...rest } = {}) {
  return { site_id, limit, offset: offset || undefined, ...rest };
}

export const api = {
  // ---- health & meta ----
  getHealth: (options) => request('/health', options),
  getMeta: (options) => request('/meta', options),
  getCollectors: (options) => request('/collectors', options),

  // ---- overview & sites ----
  getOverview: (options) => request('/overview', options),
  getSites: (options) => request('/sites', options),
  getSite: (siteId, options) => request(`/sites/${encodeSegment(siteId)}`, options),

  // ---- assets ----
  getAssets: ({ site_id, type, q, limit, offset } = {}, options = {}) =>
    request('/assets', { ...options, params: listParams({ site_id, type, q, limit, offset }) }),
  getAsset: (assetId, options) => request(`/assets/${encodeSegment(assetId)}`, options),

  // ---- alerts & workflow ----
  getAlerts: ({ site_id, status, severity, category, limit, offset } = {}, options = {}) =>
    request('/alerts', {
      ...options,
      params: listParams({ site_id, status, severity, category, limit, offset }),
    }),
  getAlert: (alertId, options) => request(`/alerts/${encodeSegment(alertId)}`, options),
  ackAlert: (alertId, note = '', options = {}) =>
    request(`/alerts/${encodeSegment(alertId)}/ack`, { ...options, method: 'POST', body: { note } }),
  assignAlert: (alertId, assignee, note = '', options = {}) =>
    request(`/alerts/${encodeSegment(alertId)}/assign`, {
      ...options,
      method: 'POST',
      body: { assignee, note },
    }),
  closeAlert: (alertId, status, note = '', options = {}) =>
    request(`/alerts/${encodeSegment(alertId)}/close`, {
      ...options,
      method: 'POST',
      body: { status, note },
    }),

  // ---- cold chain ----
  getColdchain: ({ site_id, zone_id, sensor_id, since, until } = {}, options = {}) =>
    request('/coldchain', { ...options, params: { site_id, zone_id, sensor_id, since, until } }),
  getDataQuality: ({ site_id } = {}, options = {}) =>
    request('/data-quality', { ...options, params: { site_id } }),

  // ---- access ----
  getAccess: ({ site_id, since } = {}, options = {}) =>
    request('/access', { ...options, params: { site_id, since } }),
  getPolicies: ({ site_id } = {}, options = {}) =>
    request('/policies', { ...options, params: { site_id } }),

  // ---- timeline & integrity ----
  getTimeline: ({ site_id, since, limit } = {}, options = {}) =>
    request('/timeline', { ...options, params: { site_id, since, limit } }),
  getIntegrity: ({ site_id } = {}, options = {}) =>
    request('/integrity', { ...options, params: { site_id } }),

  // ---- incidents ----
  getIncidents: ({ site_id, status, limit, offset } = {}, options = {}) =>
    request('/incidents', { ...options, params: listParams({ site_id, status, limit, offset }) }),
  getIncident: (incidentId, options) =>
    request(`/incidents/${encodeSegment(incidentId)}`, options),
  addIncidentNote: (incidentId, note, options = {}) =>
    request(`/incidents/${encodeSegment(incidentId)}/note`, {
      ...options,
      method: 'POST',
      body: { note },
    }),

  /** Download the incident evidence package as JSON (authenticated). */
  async exportIncident(incidentId, options = {}) {
    const response = await request(`/incidents/${encodeSegment(incidentId)}/export`, {
      ...options,
      raw: true,
      timeoutMs: EXPORT_TIMEOUT_MS,
    });
    const blob = await response.blob();
    const disposition = response.headers.get('content-disposition') || '';
    const match = /filename="?([^";]+)"?/i.exec(disposition);
    const filename = match ? match[1] : `incident-${incidentId}.json`;
    return { blob, filename };
  },
};

/* ------------------------------------------------------------- Access Gate */

const GATE_LIST_LIMIT = 200;

/**
 * Access Gate API (retailgate). Endpoints and payloads follow
 * docs/retail/access-gate-api-contract.md; the UI never invents fields.
 */
export const gateApi = {
  // public health, allowed without a gate session
  health: (options = {}) =>
    gateRequest('/health', { skipAuth: true, skipUnauthorizedHandler: true, ...options }),

  // session
  login: ({ user_id, password, totp } = {}) =>
    gateRequest('/auth/login', {
      method: 'POST',
      body: { user_id, password, totp },
      skipAuth: true,
      skipUnauthorizedHandler: true,
    }),
  me: (options = {}) => gateRequest('/auth/me', options),
  logout: () => gateRequest('/auth/logout', { method: 'POST', skipUnauthorizedHandler: true }),

  // status & policy
  status: (options = {}) => gateRequest('/status', options),
  getPolicy: (options = {}) => gateRequest('/policy', options),
  getUsers: (options = {}) => gateRequest('/users', options),

  // plans
  getPlans: ({ state, target_id, limit = GATE_LIST_LIMIT, offset = 0 } = {}, options = {}) =>
    gateRequest('/plans', {
      ...options,
      params: { state, target_id, limit, offset: offset || undefined },
    }),
  getPlan: (planId, options = {}) => gateRequest(`/plans/${encodeSegment(planId)}`, options),
  approvePlan: (planId, mfa, comment = '', options = {}) =>
    gateRequest(`/plans/${encodeSegment(planId)}/approve`, {
      ...options,
      method: 'POST',
      body: { comment },
      headers: { 'X-Gate-MFA': String(mfa || '').trim() },
    }),
  rejectPlan: (planId, reason, options = {}) =>
    gateRequest(`/plans/${encodeSegment(planId)}/reject`, {
      ...options,
      method: 'POST',
      body: { reason },
    }),
  cancelPlan: (planId, options = {}) =>
    gateRequest(`/plans/${encodeSegment(planId)}/cancel`, { ...options, method: 'POST', body: {} }),

  // sessions
  getSessions: ({ active } = {}, options = {}) =>
    gateRequest('/sessions', { ...options, params: { active } }),
  revokeSession: (sessionId, options = {}) =>
    gateRequest(`/sessions/${encodeSegment(sessionId)}`, { ...options, method: 'DELETE' }),

  // denies & audit
  getDenies: ({ limit = GATE_LIST_LIMIT, target_id } = {}, options = {}) =>
    gateRequest('/denies', { ...options, params: { limit, target_id } }),
  getAudit: ({ limit = GATE_LIST_LIMIT } = {}, options = {}) =>
    gateRequest('/audit', { ...options, params: { limit } }),
};
