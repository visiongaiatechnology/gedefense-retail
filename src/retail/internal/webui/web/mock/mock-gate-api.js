/**
 * Access-Gate fixture handler for the design-QA harness. Extracted from
 * mock-api.js so both files stay inside the file-size budget. Dummy tokens only;
 * no real secrets and no network access.
 */
export function createGateHandler({ loadFixture, jsonResponse, errorResponse, parseBody }) {
  const overrides = { gatePlans: new Map(), gateSessions: new Map() };

async function gateFixture(file, state) {
  return loadFixture(state === 'empty' ? `empty/gate-${file}` : `gate/${file}`);
}

function mergeGatePlans(data) {
  const items = (Array.isArray(data.items) ? data.items : []).map((plan) => {
    const override = overrides.gatePlans.get(plan.plan_id);
    return override ? { ...plan, ...override } : plan;
  });
  return { ...data, items, total: items.length };
}

function mergeGateSessions(data) {
  const items = (Array.isArray(data.items) ? data.items : []).map((session) => {
    const override = overrides.gateSessions.get(session.session_id);
    return override ? { ...session, ...override } : session;
  });
  return { ...data, items, total: items.length };
}

function dummyToken() {
  const random = Math.random().toString(16).slice(2).padEnd(12, '0');
  return `dummy-one-time-token-${random}`;
}

function parseGatePath(path) {
  return path.slice('/gate'.length) || '/';
}

async function handleGateRequest(path, method, params, init, config) {
  const gatePath = parseGatePath(path);

  // ---- public health & session ----
  if (gatePath === '/health' && method === 'GET') {
    return jsonResponse(await gateFixture('health.json', config.state));
  }
  if (gatePath === '/auth/login' && method === 'POST') {
    const body = parseBody(init);
    if (!body.user_id || !body.password) {
      return errorResponse(400, 'invalid_request', 'user_id and password are required');
    }
    if (!body.totp) {
      return errorResponse(403, 'mfa_required', 'TOTP code required');
    }
    const me = await gateFixture('me.json', config.state);
    return jsonResponse({
      session_token: `gst_dummy_${Math.random().toString(16).slice(2).padEnd(24, '0')}`,
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
      user: me.user,
      mfa_ok: true,
    });
  }
  if (gatePath === '/auth/me' && method === 'GET') {
    return jsonResponse(await gateFixture('me.json', config.state));
  }
  if (gatePath === '/auth/logout' && method === 'POST') {
    return new Response(null, { status: 204, headers: { 'Cache-Control': 'no-store' } });
  }

  // ---- status, policy, audit ----
  if (gatePath === '/status' && method === 'GET') {
    return jsonResponse(await gateFixture('status.json', config.state));
  }
  if (gatePath === '/policy' && method === 'GET') {
    return jsonResponse(await gateFixture('policy.json', config.state));
  }
  if (gatePath === '/audit' && method === 'GET') {
    return jsonResponse(await gateFixture('audit.json', config.state));
  }
  if (gatePath === '/users' && method === 'GET') {
    const me = await gateFixture('me.json', config.state);
    return jsonResponse({ items: [me.user] });
  }

  // ---- plans ----
  if (gatePath === '/plans' && method === 'GET') {
    const data = mergeGatePlans(await gateFixture('plans.json', config.state));
    let items = [...data.items];
    const state = params.get('state');
    if (state) items = items.filter((plan) => plan.state === state);
    const target = params.get('target_id');
    if (target) items = items.filter((plan) => plan.target_id === target);
    const offset = Math.max(0, Number(params.get('offset') || 0));
    const limit = Math.min(200, Math.max(1, Number(params.get('limit') || 100)));
    return jsonResponse({ items: items.slice(offset, offset + limit), total: items.length, limit, offset });
  }
  const approveMatch = gatePath.match(/^\/plans\/([^/]+)\/approve$/);
  if (approveMatch && method === 'POST') {
    return handleGateApprove(decodeURIComponent(approveMatch[1]), parseBody(init), config);
  }
  const rejectMatch = gatePath.match(/^\/plans\/([^/]+)\/reject$/);
  if (rejectMatch && method === 'POST') {
    return handleGateReject(decodeURIComponent(rejectMatch[1]), parseBody(init), config);
  }
  const cancelMatch = gatePath.match(/^\/plans\/([^/]+)\/cancel$/);
  if (cancelMatch && method === 'POST') {
    return handleGateCancel(decodeURIComponent(cancelMatch[1]), config);
  }
  const planMatch = gatePath.match(/^\/plans\/([^/]+)$/);
  if (planMatch && method === 'GET') {
    const id = decodeURIComponent(planMatch[1]);
    const plans = mergeGatePlans(await gateFixture('plans.json', config.state)).items;
    const plan = plans.find((entry) => entry.plan_id === id);
    if (!plan) return errorResponse(404, 'not_found', 'Plan nicht gefunden (Mock).');
    return jsonResponse({ plan });
  }

  // ---- sessions ----
  if (gatePath === '/sessions' && method === 'GET') {
    const data = mergeGateSessions(await gateFixture('sessions.json', config.state));
    let items = [...data.items];
    const active = params.get('active');
    if (active === 'true') items = items.filter((session) => !session.revoked);
    if (active === 'false') items = items.filter((session) => session.revoked);
    return jsonResponse({ items, total: items.length, limit: 100, offset: 0 });
  }
  const revokeMatch = gatePath.match(/^\/sessions\/([^/]+)$/);
  if (revokeMatch && method === 'DELETE') {
    const id = decodeURIComponent(revokeMatch[1]);
    const data = mergeGateSessions(await gateFixture('sessions.json', config.state));
    const session = data.items.find((entry) => entry.session_id === id);
    if (!session) return errorResponse(404, 'not_found', 'Session nicht gefunden (Mock).');
    const revoked = {
      ...session,
      revoked: true,
      revoked_at: new Date().toISOString(),
      revoked_by: 'approver-01',
    };
    overrides.gateSessions.set(id, revoked);
    return jsonResponse({ session: revoked });
  }

  // ---- denies ----
  if (gatePath === '/denies' && method === 'GET') {
    const data = await gateFixture('denies.json', config.state);
    let items = Array.isArray(data.items) ? [...data.items] : [];
    const target = params.get('target_id');
    if (target) items = items.filter((deny) => deny.target_id === target);
    const limit = Math.min(200, Math.max(1, Number(params.get('limit') || 100)));
    return jsonResponse({ items: items.slice(0, limit), total: items.length, limit, offset: 0 });
  }

  return errorResponse(404, 'not_found', `Mock-Gate-Endpunkt ${gatePath} ist nicht implementiert.`);
}

async function findGatePlan(planId, config) {
  const data = mergeGatePlans(await gateFixture('plans.json', config.state));
  return data.items.find((plan) => plan.plan_id === planId) || null;
}

async function handleGateApprove(planId, body, config) {
  const plan = await findGatePlan(planId, config);
  if (!plan) return errorResponse(404, 'not_found', 'Plan nicht gefunden (Mock).');
  if (plan.state !== 'pending') {
    return errorResponse(409, 'plan_already_decided', 'Plan is not pending anymore');
  }
  const approvals = Array.isArray(plan.approvals) ? [...plan.approvals] : [];
  const positive = new Set(
    approvals.filter((entry) => entry.approved).map((entry) => entry.approver_id)
  );
  const required = plan.critical || plan.four_eyes ? 2 : 1;
  approvals.push({
    approval_id: `apr-mock-${Date.now()}`,
    plan_id: plan.plan_id,
    approver_id: positive.size === 0 ? 'mock-approver' : 'mock-master-admin',
    role: positive.size === 0 ? 'approver' : 'master_admin',
    approved: true,
    comment: String(body.comment || ''),
    plan_hash: plan.plan_hash,
    mfa_used: true,
    at: new Date().toISOString(),
  });
  const count = new Set(approvals.filter((entry) => entry.approved).map((entry) => entry.approver_id)).size;
  const final = count >= required;
  const updated = {
    ...plan,
    approvals,
    state: final ? 'approved' : 'pending',
    updated_at: new Date().toISOString(),
  };
  overrides.gatePlans.set(planId, updated);
  return jsonResponse({
    plan: updated,
    token: final
      ? {
          token: dummyToken(),
          expires_at: new Date(Date.now() + 300_000).toISOString(),
        }
      : null,
  });
}

async function handleGateReject(planId, body, config) {
  const plan = await findGatePlan(planId, config);
  if (!plan) return errorResponse(404, 'not_found', 'Plan nicht gefunden (Mock).');
  if (plan.state !== 'pending') {
    return errorResponse(409, 'plan_already_decided', 'Plan is not pending anymore');
  }
  const reason = String(body.reason || '').trim();
  if (!reason) return errorResponse(400, 'invalid_request', 'reason is required');
  const approvals = Array.isArray(plan.approvals) ? [...plan.approvals] : [];
  approvals.push({
    approval_id: `apr-mock-${Date.now()}`,
    plan_id: plan.plan_id,
    approver_id: 'mock-approver',
    role: 'approver',
    approved: false,
    comment: reason,
    plan_hash: plan.plan_hash,
    mfa_used: true,
    at: new Date().toISOString(),
  });
  const updated = {
    ...plan,
    approvals,
    state: 'rejected',
    updated_at: new Date().toISOString(),
  };
  overrides.gatePlans.set(planId, updated);
  return jsonResponse({ plan: updated });
}

async function handleGateCancel(planId, config) {
  const plan = await findGatePlan(planId, config);
  if (!plan) return errorResponse(404, 'not_found', 'Plan nicht gefunden (Mock).');
  if (plan.state === 'approved') {
    return errorResponse(409, 'plan_already_decided', 'Approved plans cannot be cancelled');
  }
  const updated = { ...plan, state: 'cancelled', updated_at: new Date().toISOString() };
  overrides.gatePlans.set(planId, updated);
  return jsonResponse({ plan: updated });
}

  return handleGateRequest;
}
