/**
 * Shared application state with a tiny pub/sub layer.
 *
 * Views read state and subscribe to the topics they care about; they never
 * mutate another view's DOM. The store also tracks data freshness so every
 * screen can mark stale or partial data honestly.
 */
import { STORAGE } from './config.js';
import { t } from '../i18n/index.js';

/** @type {{meta: object|null, health: object|null, sites: object[], siteId: string, connection: string, connectionDetail: string, lastDataAt: number, lastStreamAt: number, siteTimezone: string, collectors: object[], openAlerts: number, criticalAlerts: number, error: object|null}} */
const state = {
  meta: null,
  health: null,
  sites: [],
  siteId: '',
  connection: 'connecting',
  connectionDetail: t('stream.connecting'),
  lastDataAt: 0,
  lastStreamAt: 0,
  siteTimezone: '',
  collectors: [],
  openAlerts: 0,
  criticalAlerts: 0,
  error: null,
};

const listeners = new Map();

/**
 * Subscribe to a topic. Returns an unsubscribe function.
 * @param {string} topic
 * @param {(payload: unknown) => void} handler
 */
export function subscribe(topic, handler) {
  if (!listeners.has(topic)) listeners.set(topic, new Set());
  listeners.get(topic).add(handler);
  return () => {
    const set = listeners.get(topic);
    if (set) set.delete(handler);
  };
}

export function emit(topic, payload) {
  const set = listeners.get(topic);
  if (!set) return;
  for (const handler of [...set]) {
    try {
      handler(payload);
    } catch (error) {
      // A failing subscriber must never break the data pipeline or other views.
      console.error('subscriber failed', error);
    }
  }
}

export function getState() {
  return state;
}

export function updateState(patch) {
  Object.assign(state, patch);
  emit('state', patch);
}

/** Mark a successful data read; drives the stale indicator. */
export function bumpData(at = Date.now()) {
  state.lastDataAt = at;
  emit('data', at);
}

export function setConnection(connection, detail = '') {
  if (state.connection === connection && state.connectionDetail === detail) return;
  state.connection = connection;
  state.connectionDetail = detail;
  emit('connection', { connection, detail });
}

export function setSites(sites, { keepSiteId = true } = {}) {
  state.sites = Array.isArray(sites) ? sites : [];
  const known = state.sites.some((site) => site.site_id === state.siteId);
  if (!keepSiteId || !known) {
    const stored = readStoredSite();
    const candidate =
      (stored && state.sites.find((site) => site.site_id === stored)) ||
      state.sites[0] ||
      null;
    state.siteId = candidate ? candidate.site_id : '';
  }
  syncSiteTimezone();
}

export function setSite(siteId, { silent = false } = {}) {
  const value = String(siteId || '');
  state.siteId = value;
  try {
    sessionStorage.setItem(STORAGE.site, value);
  } catch {
    /* optional convenience only */
  }
  syncSiteTimezone();
  if (!silent) emit('site', value);
}

export function getSiteId() {
  return state.siteId;
}

export function getSite() {
  return state.sites.find((site) => site.site_id === state.siteId) || null;
}

export function getSiteTimezone() {
  return state.siteTimezone || '';
}

function syncSiteTimezone() {
  const site = getSite();
  state.siteTimezone = site && site.timezone ? site.timezone : '';
}

function readStoredSite() {
  try {
    return sessionStorage.getItem(STORAGE.site) || '';
  } catch {
    return '';
  }
}

export function setCollectors(collectors) {
  state.collectors = Array.isArray(collectors) ? collectors : [];
  emit('collectors', state.collectors);
}

/** Transient operator feedback; rendered by the shell toast stack. */
export function toast({ variant = 'info', title, text = '', timeout = 6000 }) {
  emit('toast', { variant, title, text, timeout });
}
