/**
 * Local fixture API for design QA. Intercepts only same-origin `/api/v1/*`
 * requests made by the production application modules; everything else is
 * passed through to the real network stack (only local fixture files are read).
 *
 * Scenarios are selected from the query string of web/mock/index.html:
 *   ?state=normal|empty|error|offline|partial  (default: normal)
 *   &delay=120                                  (simulated latency in ms)
 *
 * The hash router keeps working, so every view can be screenshotted directly:
 *   /mock/?state=empty#/assets
 */
const API_PREFIX = '/api/v1';
import { createGateHandler } from './mock-gate-api.js';
import { createSetupHandler } from './mock-setup-api.js';

const ALLOWED_STATES = new Set(['normal', 'empty', 'error', 'offline', 'partial']);
const NOW = () => new Date().toISOString();

let originalFetch = null;
const fixtureCache = new Map();
const overrides = {
  alerts: new Map(),
  incidents: new Map(),
  incidentNotes: new Map(),
};

export function readMockConfig() {
  const params = new URLSearchParams(location.search);
  const requested = params.get('state') || 'normal';
  const state = ALLOWED_STATES.has(requested) ? requested : 'normal';
  const delayRaw = Number(params.get('delay'));
  const delay = Number.isFinite(delayRaw) ? Math.min(5000, Math.max(0, delayRaw)) : 120;
  const gateLogin = params.get('gateLogin') === '1';
  const setupCompleted = params.get('setupCompleted') === '1';
  return { state, delay, gateLogin, setupCompleted };
}

export function installMockApi(config) {
  originalFetch = window.fetch.bind(window);
  window.__gedefenseMock = { originalFetch, config };

  window.fetch = async (input, init = {}) => {
    let url;
    try {
      if (input instanceof URL) url = new URL(input.href);
      else if (typeof input === 'string') url = new URL(input, location.origin);
      else if (typeof Request !== 'undefined' && input instanceof Request) url = new URL(input.url, location.origin);
      else url = new URL(String(input), location.origin);
    } catch {
      return originalFetch(input, init);
    }
    if (!url.pathname.startsWith(API_PREFIX)) {
      return originalFetch(input, init);
    }
    if (config.delay > 0) await sleep(config.delay);
    if (config.state === 'offline') {
      // Transport failure, not an HTTP error: the UI must show its offline state.
      throw new TypeError('Failed to fetch (mock offline)');
    }
    try {
      return await handleRequest(url, init, config);
    } catch (error) {
      return errorResponse(500, 'mock_error', `Mock-Fixture-Fehler: ${error && error.message ? error.message : 'unbekannt'}`);
    }
  };
}

function sleep(ms) {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

async function loadFixture(path) {
  if (!fixtureCache.has(path)) {
    const response = await originalFetch(`/mock/fixtures/${path}`, { cache: 'no-store' });
    if (!response.ok) throw new Error(`Fixture ${path} fehlt (HTTP ${response.status})`);
    fixtureCache.set(path, await response.json());
  }
  return fixtureCache.get(path);
}

function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Request-Id': `mock-${Math.random().toString(36).slice(2, 12)}`,
      ...extraHeaders,
    },
  });
}

function errorResponse(status, code, message) {
  return jsonResponse(
    { error: { code, message, request_id: `mock-${Math.random().toString(36).slice(2, 12)}` } },
    status
  );
}

function parseBody(init) {
  if (!init || !init.body) return {};
  if (typeof init.body === 'string') {
    try {
      return JSON.parse(init.body);
    } catch {
      return {};
    }
  }
  return {};
}

function isBootstrapPath(path) {
  return path === '/meta' || path === '/health' || path === '/sites' || path.startsWith('/sites/') || path === '/collectors';
}

function isPartialFailure(path) {
  return (
    path.startsWith('/assets') ||
    path.startsWith('/coldchain') ||
    path.startsWith('/access') ||
    path.startsWith('/timeline') ||
    path.startsWith('/integrity') ||
    path.startsWith('/incidents') ||
    path.startsWith('/data-quality')
  );
}

async function fixturePair(file, state) {
  return loadFixture(state === 'empty' ? `empty/${file}` : file);
}

/* --------------------------------------------------------------- routing */

let setupHandlerInstance = null;
function setupHandler() {
  if (!setupHandlerInstance) {
    setupHandlerInstance = createSetupHandler({ loadFixture, jsonResponse, errorResponse, parseBody });
  }
  return setupHandlerInstance;
}

let gateHandlerInstance = null;
function gateHandler() {
  if (!gateHandlerInstance) {
    gateHandlerInstance = createGateHandler({ loadFixture, jsonResponse, errorResponse, parseBody });
  }
  return gateHandlerInstance;
}

async function handleRequest(url, init, config) {
  const method = (init.method || 'GET').toUpperCase();
  const path = url.pathname.slice(API_PREFIX.length) || '/';
  const params = url.searchParams;

  if (config.state === 'error' && !isBootstrapPath(path)) {
    return errorResponse(503, 'unavailable', 'Gateway nicht verfügbar (Mock-Szenario „error“).');
  }
  if (config.state === 'partial' && isPartialFailure(path)) {
    return errorResponse(503, 'unavailable', 'Teilausfall (Mock-Szenario „partial“): Datenquelle nicht verfügbar.');
  }

  // ---- live stream ----
  if (path === '/stream' && method === 'GET') {
    return streamResponse(config);
  }

  // ---- access gate (separate service, same mock harness) ----
  if (path === '/gate' || path.startsWith('/gate/')) {
    return gateHandler()(path, method, params, init, config);
  }

  // ---- first-run setup (separate, loopback-only service) ----
  if (path === '/setup' || path.startsWith('/setup/')) {
    return setupHandler()(path, method, params, init, config);
  }

  // ---- bootstrap ----
  if (path === '/health') return jsonResponse(await fixturePair('health.json', config.state));
  if (path === '/meta') return jsonResponse(await fixturePair('meta.json', config.state));
  if (path === '/collectors') {
    const list = await fixturePair('collectors.json', config.state);
    return jsonResponse({ items: Array.isArray(list) ? list : [] });
  }
  if (path === '/overview') return jsonResponse(await fixturePair('overview.json', config.state));

  // ---- sites ----
  if (path === '/sites') return jsonResponse(await fixturePair('sites.json', config.state));
  const siteMatch = path.match(/^\/sites\/([^/]+)$/);
  if (siteMatch && method === 'GET') {
    const details = await loadFixture('site-details.json');
    const entry = details[decodeURIComponent(siteMatch[1])];
    if (!entry) return errorResponse(404, 'not_found', 'Filiale nicht gefunden (Mock).');
    return jsonResponse(entry);
  }

  // ---- assets ----
  if (path === '/assets' && method === 'GET') {
    const data = await fixturePair('assets.json', config.state);
    const filtered = filterAssets(data, params);
    return jsonResponse(filtered);
  }
  const assetMatch = path.match(/^\/assets\/([^/]+)$/);
  if (assetMatch && method === 'GET') {
    const details = await loadFixture('asset-details.json');
    const id = decodeURIComponent(assetMatch[1]);
    if (details[id]) return jsonResponse(details[id]);
    const assets = await loadFixture('assets.json');
    const asset = assets.items.find((item) => item.asset_id === id);
    if (!asset) return errorResponse(404, 'not_found', 'Anlage nicht gefunden (Mock).');
    return jsonResponse({ asset, sensors: [], alerts: [], recent_events: [] });
  }

  // ---- alerts ----
  if (path === '/alerts' && method === 'GET') {
    const data = await fixturePair('alerts.json', config.state);
    return jsonResponse(filterAlerts(await mergeAlertOverrides(data), params));
  }
  const alertActionMatch = path.match(/^\/alerts\/([^/]+)\/(ack|assign|close)$/);
  if (alertActionMatch && method === 'POST') {
    return handleAlertAction(alertActionMatch[1], alertActionMatch[2], parseBody(init));
  }
  const alertMatch = path.match(/^\/alerts\/([^/]+)$/);
  if (alertMatch && method === 'GET') {
    const id = decodeURIComponent(alertMatch[1]);
    const details = await loadFixture('alert-details.json');
    const base = details[id];
    if (!base) return errorResponse(404, 'not_found', 'Alarm nicht gefunden (Mock).');
    return jsonResponse(mergeAlertDetailOverride(id, base));
  }

  // ---- cold chain ----
  if (path === '/coldchain' && method === 'GET') {
    const data = await fixturePair('coldchain.json', config.state);
    const zoneId = params.get('zone_id');
    const sensorId = params.get('sensor_id');
    if (zoneId || sensorId) {
      const items = (data.items || []).filter(
        (item) => (!zoneId || item.sensor?.zone_id === zoneId) && (!sensorId || item.sensor?.sensor_id === sensorId)
      );
      return jsonResponse({ ...data, items });
    }
    return jsonResponse(data);
  }
  if (path === '/data-quality' && method === 'GET') {
    const data = await loadFixture('data-quality.json');
    return jsonResponse({ items: data, total: data.length, limit: 50, offset: 0 });
  }

  // ---- access ----
  if (path === '/access' && method === 'GET') return jsonResponse(await fixturePair('access.json', config.state));

  // ---- timeline ----
  if (path === '/timeline' && method === 'GET') {
    const data = await fixturePair('timeline.json', config.state);
    const limit = Math.min(200, Math.max(1, Number(params.get('limit') || 100)));
    return jsonResponse({ items: (data.items || []).slice(0, limit), total: data.total ?? (data.items || []).length });
  }

  // ---- integrity ----
  if (path === '/integrity' && method === 'GET') return jsonResponse(await fixturePair('integrity.json', config.state));

  // ---- incidents ----
  if (path === '/incidents' && method === 'GET') {
    const data = await fixturePair('incidents.json', config.state);
    return jsonResponse(filterIncidents(data, params));
  }
  const exportMatch = path.match(/^\/incidents\/([^/]+)\/export$/);
  if (exportMatch && method === 'GET') {
    const incidentId = decodeURIComponent(exportMatch[1]);
    const bundle = await loadFixture('export.json');
    const payload = { ...bundle, generated_at: NOW(), incident: { ...bundle.incident, incident_id: incidentId } };
    return new Response(JSON.stringify(payload), {
      status: 200,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Disposition': `attachment; filename="incident-${incidentId}.json"`,
        'Cache-Control': 'no-store',
      },
    });
  }
  const noteMatch = path.match(/^\/incidents\/([^/]+)\/note$/);
  if (noteMatch && method === 'POST') {
    return handleIncidentNote(decodeURIComponent(noteMatch[1]), parseBody(init));
  }
  const incidentMatch = path.match(/^\/incidents\/([^/]+)$/);
  if (incidentMatch && method === 'GET') {
    const id = decodeURIComponent(incidentMatch[1]);
    const details = await loadFixture('incident-details.json');
    const base = details[id];
    if (!base) return errorResponse(404, 'not_found', 'Vorfall nicht gefunden (Mock).');
    return jsonResponse(mergeIncidentOverrides(id, base));
  }

  // ---- policies ----
  if (path === '/policies' && method === 'GET') {
    return jsonResponse(await loadFixture('policy.json'));
  }

  return errorResponse(404, 'not_found', `Mock-Endpunkt ${path} ist nicht implementiert.`);
}

/* --------------------------------------------------------------- filters */

function filterAssets(data, params) {
  let items = Array.isArray(data.items) ? [...data.items] : [];
  const siteId = params.get('site_id');
  if (siteId) items = items.filter((asset) => asset.site_id === siteId);
  const type = params.get('type');
  if (type) items = items.filter((asset) => asset.asset_type === type);
  const query = (params.get('q') || '').trim().toLowerCase();
  if (query) {
    items = items.filter((asset) =>
      [asset.name, asset.vendor, asset.model, asset.asset_id]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(query))
    );
  }
  const total = items.length;
  const offset = Math.max(0, Number(params.get('offset') || 0));
  const limit = Math.min(200, Math.max(1, Number(params.get('limit') || 50)));
  return { items: items.slice(offset, offset + limit), total, limit, offset };
}

async function mergeAlertOverrides(data) {
  const items = (Array.isArray(data.items) ? data.items : []).map((alert) => {
    const override = overrides.alerts.get(alert.alert_id);
    return override ? { ...alert, ...override } : alert;
  });
  return { ...data, items, total: items.length };
}

function filterAlerts(data, params) {
  let items = Array.isArray(data.items) ? [...data.items] : [];
  const siteId = params.get('site_id');
  if (siteId) items = items.filter((alert) => alert.site_id === siteId);
  const status = params.get('status');
  if (status) items = items.filter((alert) => alert.status === status);
  const severity = params.get('severity');
  if (severity) items = items.filter((alert) => alert.severity === severity);
  const category = params.get('category');
  if (category) items = items.filter((alert) => alert.category === category);
  const offset = Math.max(0, Number(params.get('offset') || 0));
  const limit = Math.min(200, Math.max(1, Number(params.get('limit') || 50)));
  return { items: items.slice(offset, offset + limit), total: items.length, limit, offset };
}

function filterIncidents(data, params) {
  let items = Array.isArray(data.items) ? [...data.items] : [];
  const siteId = params.get('site_id');
  if (siteId) items = items.filter((incident) => incident.site_id === siteId);
  const status = params.get('status');
  if (status) items = items.filter((incident) => incident.status === status);
  const offset = Math.max(0, Number(params.get('offset') || 0));
  const limit = Math.min(200, Math.max(1, Number(params.get('limit') || 50)));
  return { items: items.slice(offset, offset + limit), total: items.length, limit, offset };
}

/* --------------------------------------------------------------- actions */

async function handleAlertAction(alertId, action, body) {
  const id = decodeURIComponent(alertId);
  const data = await loadFixture('alerts.json');
  const base = data.items.find((entry) => entry.alert_id === id);
  if (!base) return errorResponse(404, 'not_found', 'Alarm nicht gefunden (Mock).');
  const updated = {
    ...base,
    updated_at: NOW(),
    audit_history: [
      ...(base.audit_history || []),
      { at: NOW(), actor: 'mock-operator', role: 'operator', action: `alert.${action}`, note: body.note || '' },
    ],
  };
  if (action === 'ack') updated.status = 'acknowledged';
  if (action === 'assign') updated.assignee = body.assignee || 'mock-operator';
  if (action === 'close') updated.status = body.status || 'resolved';
  overrides.alerts.set(id, updated);
  return jsonResponse({ alert: updated });
}

async function handleIncidentNote(incidentId, body) {
  const id = decodeURIComponent(incidentId);
  const note = String(body.note || '').trim();
  if (!note) return errorResponse(400, 'invalid_request', 'note must not be empty');
  const details = await loadFixture('incident-details.json');
  const base = details[id];
  if (!base) return errorResponse(404, 'not_found', 'Vorfall nicht gefunden (Mock).');
  const notes = overrides.incidentNotes.get(id) || [];
  notes.push({ at: NOW(), actor: 'mock-operator', role: 'operator', note, pinned: false });
  overrides.incidentNotes.set(id, notes);
  const merged = mergeIncidentOverrides(id, base);
  return jsonResponse({ incident: merged.incident });
}

function mergeAlertDetailOverride(id, base) {
  const override = overrides.alerts.get(id);
  if (!override) return base;
  return { ...base, alert: { ...base.alert, ...override } };
}

function mergeIncidentOverrides(id, base) {
  const override = overrides.incidents.get(id);
  const extraNotes = overrides.incidentNotes.get(id) || [];
  const incident = {
    ...base.incident,
    ...(override || {}),
    notes: [...(base.incident.notes || []), ...extraNotes],
  };
  return { ...base, incident };
}

/* ---------------------------------------------------------------- stream */

function streamResponse(config) {
  const encoder = new TextEncoder();
  let pingTimer = 0;

  const body = new ReadableStream({
    async start(controller) {
      try {
        const collectors = await loadFixture('collectors.json');
        controller.enqueue(
          encoder.encode(`event: health\ndata: ${JSON.stringify(collectors)}\n\n`)
        );
      } catch {
        // Keep the stream open even when the collectors fixture is unreadable.
      }
      pingTimer = window.setInterval(() => {
        try {
          controller.enqueue(encoder.encode(': ping\n\n'));
        } catch {
          window.clearInterval(pingTimer);
        }
      }, 15_000);
    },
    cancel() {
      window.clearInterval(pingTimer);
    },
  });

  void config;
  return new Response(body, {
    status: 200,
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-store',
      'X-Request-Id': `mock-stream-${Math.random().toString(36).slice(2, 10)}`,
    },
  });
}
