/**
 * Hash router. The API contract specifies client-side routing through
 * location.hash (`#/overview`, `#/assets`, …). Deep links carry only stable
 * context (selected asset or incident); dense table filters stay local.
 */
import { NAV, NAV_BY_ID } from './config.js';

const PATH_TO_VIEW = new Map(NAV.map((item) => [item.path, item.id]));
// Human-friendly aliases (e.g. the threat timeline as #/alerts).
PATH_TO_VIEW.set('/alerts', 'threat');
PATH_TO_VIEW.set('/cold-chain', 'coldchain');
PATH_TO_VIEW.set('/sites', 'site');
PATH_TO_VIEW.set('/cases', 'incidents');

export function parseHash(hash = window.location.hash) {
  const raw = String(hash || '').replace(/^#/, '');
  const queryIndex = raw.indexOf('?');
  const pathPart = queryIndex >= 0 ? raw.slice(0, queryIndex) : raw;
  const queryPart = queryIndex >= 0 ? raw.slice(queryIndex + 1) : '';
  let path = pathPart.trim();
  if (!path) path = '/overview';
  if (!path.startsWith('/')) path = `/${path}`;
  path = path.replace(/\/+$/, '') || '/overview';
  const viewId = PATH_TO_VIEW.get(path) || null;
  return { path, viewId, query: new URLSearchParams(queryPart) };
}

export function hrefFor(viewId, params = {}) {
  const item = NAV_BY_ID.get(viewId);
  const base = item ? item.path : '/overview';
  const query = toQueryString(params);
  return `#${base}${query ? `?${query}` : ''}`;
}

export function toQueryString(params = {}) {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue;
    search.set(key, String(value));
  }
  return search.toString();
}

/** Navigate to a view. Same-hash navigation is a no-op (no redundant reload). */
export function navigate(viewId, params = {}) {
  const target = hrefFor(viewId, params);
  if (window.location.hash === target) return false;
  window.location.hash = target;
  return true;
}

/** Replace the current history entry, used to normalise an empty hash. */
export function replaceRoute(viewId, params = {}) {
  const target = hrefFor(viewId, params);
  window.history.replaceState(null, '', target);
  return parseHash(target);
}

export function startRouter(onRoute) {
  const dispatch = () => {
    const route = parseHash();
    onRoute(route);
  };
  const handleHashChange = () => dispatch();

  window.addEventListener('hashchange', handleHashChange);
  if (!window.location.hash) {
    window.history.replaceState(null, '', hrefFor('overview'));
  }
  dispatch();

  return () => window.removeEventListener('hashchange', handleHashChange);
}
