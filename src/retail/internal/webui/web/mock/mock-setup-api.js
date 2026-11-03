/**
 * First-run setup fixture handler for the design-QA harness. Mirrors
 * setup-and-whitelist-contract.md §5 closely enough to exercise every wizard
 * step without a backend. The admin token is a dummy and is never persisted.
 */
export function createSetupHandler({ loadFixture, jsonResponse, errorResponse, parseBody }) {
  let statePromise = null;
  let state = null;

  async function ensureState(config) {
    if (!statePromise) {
      statePromise = loadFixture('setup/state.json').then((fixture) => {
        state = {
          ...fixture,
          whitelist_cidrs: Array.isArray(fixture.whitelist_cidrs) ? [...fixture.whitelist_cidrs] : [],
          collectors: Array.isArray(fixture.collectors) ? [...fixture.collectors] : [],
          supported_collectors: Array.isArray(fixture.supported_collectors) ? [...fixture.supported_collectors] : [],
        };
        if (config.state === 'empty') {
          state.whitelist_cidrs = [];
          state.collectors = [];
        }
        if (config.setupCompleted) {
          state.completed = true;
          state.completed_at = new Date().toISOString();
          state.admin_created = true;
          state.whitelist_cidrs = ['127.0.0.1/32'];
          state.site = { site_id: 'filiale-001', name: 'Markt Nord', country: 'DE', timezone: 'Europe/Berlin', zones: [] };
          state.bind_hint = '127.0.0.1:8443';
        }
        return state;
      });
    }
    return statePromise;
  }

  function snapshot() {
    return {
      completed: state.completed,
      completed_at: state.completed_at,
      language: state.language,
      remote_ip: state.remote_ip,
      loopback: state.loopback,
      site: state.site,
      whitelist_cidrs: state.whitelist_cidrs,
      admin_created: state.admin_created,
      collectors: state.collectors,
      supported_collectors: state.supported_collectors,
      bind_hint: state.bind_hint || '',
    };
  }

  function requireOpen() {
    return !state.completed;
  }

  function rotateSession() {
    state.setup_session = `setup-dummy-${Math.random().toString(16).slice(2).padEnd(24, '0')}`;
    return state.setup_session;
  }

  function headerValue(init, name) {
    const headers = new Headers((init && init.headers) || {});
    return headers.get(name) || '';
  }

  return async function handleSetupRequest(path, method, params, init, config) {
    await ensureState(config);
    const route = path.slice('/setup'.length) || '/';
    if (route === '/state' && method === 'GET') {
      rotateSession();
      return jsonResponse({ ...snapshot(), setup_session: state.setup_session });
    }
    if (method !== 'GET' && headerValue(init, 'X-Setup-Session') !== state.setup_session) {
      return errorResponse(403, 'setup_session_invalid', 'setup session missing or invalid');
    }
    if (route === '/language' && method === 'POST') {
      const body = parseBody(init);
      const allowed = ['en', 'de', 'fr', 'it', 'es', 'ja', 'zh', 'ru'];
      if (!allowed.includes(body.language)) {
        return errorResponse(400, 'invalid_language', 'language is not in the allowlist');
      }
      state.language = body.language;
      return jsonResponse({ language: state.language });
    }
    if (!requireOpen()) return errorResponse(404, 'setup_completed', 'setup is already completed');
    if (route === '/site' && method === 'POST') {
      const body = parseBody(init);
      if (!body.site_id || !body.name || !body.country || !body.timezone) {
        return errorResponse(400, 'invalid_site', 'site_id, name, country and timezone are required');
      }
      state.site = {
        site_id: String(body.site_id),
        name: String(body.name),
        country: String(body.country),
        timezone: String(body.timezone),
        zones: Array.isArray(body.zones) ? body.zones : [],
      };
      return jsonResponse({ site: state.site });
    }
    if (route === '/whitelist' && method === 'POST') {
      const body = parseBody(init);
      const cidrs = Array.isArray(body.cidrs) ? body.cidrs.map((value) => String(value).trim()).filter(Boolean) : null;
      if (!cidrs) return errorResponse(400, 'invalid_whitelist', 'cidrs must be an array');
      if (cidrs.length > 64) return errorResponse(400, 'invalid_whitelist', 'at most 64 cidrs are allowed');
      for (const cidr of cidrs) {
        if (!/^[0-9a-fA-F:.]+(\/\d{1,3})?$/.test(cidr)) {
          return errorResponse(400, 'invalid_cidr', `invalid CIDR/IP: ${cidr}`);
        }
      }
      state.whitelist_cidrs = cidrs;
      return jsonResponse({ cidrs, remote_ip: state.remote_ip });
    }
    if (route === '/admin' && method === 'POST') {
      const body = parseBody(init);
      if (!body.user_id || !body.name) return errorResponse(400, 'invalid_admin', 'user_id and name are required');
      if (state.admin_created) return errorResponse(409, 'admin_exists', 'admin user already created');
      state.admin_created = true;
      state.admin_user_id = String(body.user_id);
      return jsonResponse({
        user_id: String(body.user_id),
        token: `admin-dummy-token-${Math.random().toString(16).slice(2).padEnd(24, '0')}`,
        token_sha256: 'dummy-sha256-not-a-real-hash',
      });
    }
    if (route === '/collectors' && method === 'POST') {
      const body = parseBody(init);
      const known = new Set(state.supported_collectors.map((entry) => entry.id));
      const adapters = Array.isArray(body.adapters) ? body.adapters.filter((id) => known.has(id)) : [];
      state.collectors = adapters;
      return jsonResponse({ adapters });
    }
    if (route === '/complete' && method === 'POST') {
      if (!state.admin_created || state.whitelist_cidrs.length === 0) {
        return errorResponse(409, 'setup_incomplete', 'admin and whitelist are required before completion');
      }
      state.completed = true;
      state.completed_at = new Date().toISOString();
      state.bind_hint = '127.0.0.1:8443';
      return jsonResponse({ completed: true, restart_required: true, bind_hint: state.bind_hint });
    }
    return errorResponse(404, 'not_found', `Mock-Setup-Endpunkt ${route} ist nicht implementiert.`);
  };
}
