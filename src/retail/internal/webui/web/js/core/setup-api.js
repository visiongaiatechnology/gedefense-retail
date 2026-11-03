/**
 * First-run setup API client. Setup endpoints are loopback-only and outside the
 * monitoring authentication. Security contract F-SW-01/03/06:
 * - GET /state rotates and returns a short-lived `setup_session` token
 * - every POST sends X-Setup-Session
 * - a 403 `setup_session_invalid` refreshes state once and retries the POST
 * - POST /admin is idempotent; a second call returns 409 `admin_exists`
 *
 * Assumed state shape (documented in docs/retail/i18n-and-setup-ui.md):
 * {completed, completed_at, language, remote_ip, loopback, site, whitelist_cidrs,
 *  admin_created, collectors, supported_collectors, bind_hint, setup_session}.
 */
import { ApiError } from './api.js';

const BASE = '/api/v1/setup';
let sessionToken = '';
let statePromise = null;

async function rawRequest(path, { method = 'GET', body, headers: extraHeaders = {} } = {}) {
  const headers = { Accept: 'application/json', ...extraHeaders };
  if (sessionToken) headers['X-Setup-Session'] = sessionToken;
  let payload;
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    payload = JSON.stringify(body);
  }
  let response;
  try {
    response = await fetch(`${BASE}${path}`, {
      method,
      headers,
      body: payload,
      cache: 'no-store',
      credentials: 'same-origin',
      redirect: 'error',
    });
  } catch {
    throw new ApiError({ status: 0, code: 'network', message: 'Setup-Dienst nicht erreichbar.' });
  }
  const text = await response.text().catch(() => '');
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = null;
    }
  }
  if (!response.ok) {
    const error = data && data.error;
    const code = (error && typeof error === 'object' ? error.code : error) || (data && data.code) || `http_${response.status}`;
    const message = (error && typeof error === 'object' ? error.message : '') || (data && data.message) || '';
    const requestId =
      (error && typeof error === 'object' && error.request_id) ||
      response.headers.get('X-Request-Id') ||
      '';
    throw new ApiError({
      status: response.status,
      code: String(code || 'http_error'),
      message,
      serverMessage: text && !data ? text.slice(0, 300) : '',
      requestId,
    });
  }
  return data;
}

/** Fetch and cache the setup state; also stores the rotated session token. */
export async function refreshSetupState() {
  const data = await rawRequest('/state', { method: 'GET' });
  sessionToken = String(data?.setup_session || '');
  return data;
}

async function request(path, { method = 'GET', body, retry = true } = {}) {
  try {
    return await rawRequest(path, { method, body });
  } catch (error) {
    const sessionFailure = error && error.status === 403 && error.code === 'setup_session_invalid';
    if (sessionFailure && retry) {
      await refreshSetupState();
      return request(path, { method, body, retry: false });
    }
    throw error;
  }
}

export const setupApi = {
  getState: () => {
    statePromise = refreshSetupState();
    return statePromise;
  },
  setLanguage: (language) => request('/language', { method: 'POST', body: { language } }),
  setSite: (site) => request('/site', { method: 'POST', body: site }),
  setWhitelist: (cidrs) => request('/whitelist', { method: 'POST', body: { cidrs } }),
  createAdmin: (userId, name) => request('/admin', { method: 'POST', body: { user_id: userId, name } }),
  setCollectors: (adapters) => request('/collectors', { method: 'POST', body: { adapters } }),
  complete: () => request('/complete', { method: 'POST', body: {} }),
};

/** Test hook; never export raw tokens into UI state. */
export function hasSetupSession() {
  return Boolean(sessionToken);
}
