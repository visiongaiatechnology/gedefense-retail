/**
 * Access Gate — status and configuration. Shows the gate health, fail-safe
 * state, audit-chain health, plan/session/deny counters, target listeners and
 * the active policy summary. Read-only: policy changes stay server-side.
 */
import { el, clear } from '../../core/dom.js';
import { gateApi } from '../../core/api.js';
import { formatDateTime, formatDuration, formatCount } from '../../core/format.js';
import { targetStateChip } from '../../components/chips.js';
import { panel } from '../../components/panel.js';
import { emptyState, errorState, banner, partialBanner, skeletonPage } from '../../components/states.js';
import { icon } from '../../core/icons.js';
import { t } from '../../i18n/index.js';
import { buildIntegrityPanel } from './gate-integrity.js';

let loadSeq = 0;

export async function renderStatus(host, ctx) {
  const contentHost = el('div', { class: 'gate-status' });
  host.append(contentHost);
  await load(host, contentHost, ctx);
}

async function load(host, contentHost, ctx) {
  const sequence = ++loadSeq;
  clear(contentHost);
  contentHost.append(skeletonPage(t('gate.status.loading')));
  const results = await Promise.allSettled([
    gateApi.health(),
    gateApi.status(),
    gateApi.getPolicy(),
    gateApi.getAudit({ limit: 20 }),
    gateApi.getIntegrity(),
  ]);
  if (sequence !== loadSeq) return;

  const health = results[0].status === 'fulfilled' ? results[0].value : null;
  const status = results[1].status === 'fulfilled' ? results[1].value : null;
  const policy = results[2].status === 'fulfilled' ? results[2].value : null;
  const audit = results[3].status === 'fulfilled' ? results[3].value : null;
  const integrity = results[4] && results[4].status === 'fulfilled' ? results[4].value : null;
  const integrityError = results[4] && results[4].status === 'rejected' ? results[4].reason : null;

  clear(contentHost);
  if (!health && !status) {
    const error = (results[0].reason || results[1].reason || null);
    contentHost.append(
      errorState({
        title: t('gate.status.error_title'),
        error,
        actions: [
          el('button', {
            type: 'button',
            class: 'btn btn--primary',
            text: t('gate.common.reload'),
            on: { click: () => void load(host, contentHost, ctx) },
          }),
        ],
      })
    );
    return;
  }

  const failsafe = (status && status.failsafe) || (health && health.failsafe) || { active: false, reason: '' };
  const chainOk = (status && status.audit && status.audit.chain_ok) ?? (health && health.audit_chain_ok) ?? null;

  if (failsafe.active) {
    contentHost.append(
      banner({
        variant: 'critical',
        title: t('gate.status.failsafe_banner_title'),
        text: t('gate.status.failsafe_banner_text', { reason: failsafe.reason || t('gate.common.not_specified') }),
      })
    );
  }
  if (chainOk === false) {
    contentHost.append(
      banner({
        variant: 'critical',
        title: t('gate.status.chain_banner_title'),
        text: t('gate.status.chain_banner_text'),
      })
    );
  }

  // Counter strip — one plane, no KPI card wall.
  if (status) {
    const plans = status.plans || {};
    const sessions = status.sessions || {};
    const denies = status.denies || {};
    contentHost.append(
      counterStrip([
        [t('gate.status.counter_pending'), formatCount(plans.pending), t('gate.status.counter_pending_hint')],
        [t('gate.status.counter_approved'), formatCount(plans.approved), t('gate.status.counter_approved_hint')],
        [t('gate.status.counter_executed'), formatCount(plans.executed), t('gate.status.counter_executed_hint')],
        [t('gate.status.counter_rejected'), `${formatCount(plans.rejected)} / ${formatCount(plans.expired)}`, t('gate.status.counter_rejected_hint')],
        [t('gate.status.counter_active_sessions'), formatCount(sessions.active), t('gate.status.counter_active_sessions_hint', { count: formatCount(sessions.revoked_today) })],
        [t('gate.status.counter_denies'), formatCount(denies.last_24h), t('gate.status.counter_denies_hint')],
      ])
    );
  }

  contentHost.append(buildIntegrityPanel(integrity, integrityError, () => void load(host, contentHost, ctx)));

  const grid = el('div', { class: 'gate-status__grid' });

  grid.append(
    panel({
      title: t('gate.status.health_title'),
      sub: t('gate.status.health_subtitle'),
      body: buildHealth(health, status),
    }),
    panel({
      title: t('gate.status.who_title'),
      sub: t('gate.status.who_subtitle'),
      actions: [
        el('button', {
          type: 'button',
          class: 'btn btn--ghost btn--sm',
          text: t('gate.status.open_sessions'),
          on: { click: () => ctx.setTab('sessions') },
        }),
      ],
      body: buildActiveSessions(status),
    }),
    panel({
      title: t('gate.status.audit_title'),
      sub: t('gate.status.audit_subtitle'),
      body: buildAudit(status, audit),
    }),
    panel({
      title: t('gate.status.policy_title'),
      sub: t('gate.status.policy_subtitle'),
      body: buildPolicy(policy, results[2]),
    })
  );

  if (!status) {
    grid.prepend(partialBanner({ title: t('gate.status.partial_title'), text: t('gate.status.partial_text') }));
  }
  contentHost.append(grid);
  contentHost.append(
    el('p', {
      class: 'provenance',
      text: t('gate.status.footer_note'),
    })
  );
}

function counterStrip(items) {
  const strip = el('section', { class: 'instrument gate-instrument', attrs: { 'aria-label': t('gate.status.counters_aria') } });
  for (const [label, value, hint] of items) {
    const item = el('div', { class: 'instrument__item' });
    item.append(
      el('span', { class: 'instrument__label', text: label }),
      el('span', { class: 'instrument__value' }, el('span', { text: value })),
      el('span', { class: 'instrument__hint', text: hint })
    );
    strip.append(item);
  }
  return strip;
}

function buildHealth(health, status) {
  const wrapper = el('div', { class: 'stack' });
  if (!health) {
    wrapper.append(el('p', { class: 'provenance', text: t('gate.status.health_unavailable') }));
    return wrapper;
  }
  const failsafe = health.failsafe || (status && status.failsafe) || { active: false, reason: '' };
  const details = el('dl', { class: 'gate-dl' });
  appendRow(details, t('gate.common.status'), health.status === 'ok' ? 'ok' : String(health.status || '—'));
  appendRow(details, t('gate.common.version'), health.version || '—');
  appendRow(details, t('gate.status.uptime'), Number.isFinite(Number(health.uptime_s)) ? formatDuration(health.uptime_s) : '—');
  appendRow(details, t('gate.status.audit_chain'), health.audit_chain_ok ? t('gate.common.verified') : t('gate.common.not_verified'));
  appendRow(details, t('gate.status.failsafe'), failsafe.active ? t('gate.status.failsafe_row_active', { reason: failsafe.reason || t('gate.status.no_reason') }) : t('gate.status.failsafe_inactive'));
  appendRow(details, t('gate.status.now'), formatDateTime(health.now));
  wrapper.append(details);

  const targets = Array.isArray(health.targets) ? health.targets : Array.isArray(status?.targets) ? status.targets : [];
  if (targets.length === 0) {
    wrapper.append(emptyState({ icon: 'gate', title: t('gate.status.targets_empty_title'), text: t('gate.status.targets_empty_text') }));
  } else {
    const list = el('div', { class: 'gate-target-list' });
    for (const target of targets) {
      const row = el('div', { class: 'gate-target-row' });
      const main = el('div', { class: 'gate-target-row__main' });
      main.append(
        el('span', { class: 'gate-target-row__id', text: target.target_id || '—' }),
        el('span', { class: 'gate-target-row__meta' }, [
          el('span', { class: 'chip chip--protocol', text: String(target.protocol || '—') }),
          targetStateChip(target.state),
        ])
      );
      row.append(main);
      list.append(row);
    }
    wrapper.append(el('h4', { class: 'gate-section__title', text: t('gate.status.targets_title') }), list);
  }
  return wrapper;
}

function buildActiveSessions(status) {
  const sessions = status && status.sessions ? status.sessions : null;
  const wrapper = el('div', { class: 'stack' });
  if (!sessions) {
    wrapper.append(el('p', { class: 'provenance', text: t('gate.status.sessions_unavailable') }));
    return wrapper;
  }
  wrapper.append(
    el('div', { class: 'gate-big-number' }, [
      el('span', { class: 'gate-big-number__value', text: formatCount(sessions.active) }),
      el('span', { class: 'gate-big-number__hint', text: t('gate.status.active_sessions_hint', { count: formatCount(sessions.revoked_today) }) }),
    ]),
    banner({
      variant: 'accent',
      title: t('gate.status.sessions_banner_title'),
      text: t('gate.status.sessions_banner_text'),
    })
  );
  return wrapper;
}

function buildAudit(status, audit) {
  const wrapper = el('div', { class: 'stack' });
  const chainOk = audit ? audit.chain_ok : status?.audit?.chain_ok;
  const entries = audit ? audit.items : null;
  wrapper.append(
    el('div', { class: 'cluster' }, [
      el('span', {
        class: 'chip chip--status',
        dataset: { status: chainOk ? 'resolved' : 'open' },
        text: chainOk ? t('gate.status.chain_ok') : t('gate.status.chain_bad'),
      }),
      el('span', { class: 'provenance', text: t('gate.status.audit_entries', { count: formatCount(status?.audit?.entries) }) }),
    ])
  );
  if (!Array.isArray(entries) || entries.length === 0) {
    wrapper.append(el('p', { class: 'provenance', text: audit ? t('gate.status.audit_empty') : t('gate.status.audit_unavailable') }));
    return wrapper;
  }
  const list = el('div', { class: 'gate-audit-list' });
  for (const entry of entries.slice(0, 5)) {
    const row = el('div', { class: 'gate-audit-row' });
    row.append(
      el('span', { class: 'mono', text: `#${entry.seq}` }),
      el('span', { class: 'gate-audit-row__main' }, [
        el('span', { class: 'gate-audit-row__action', text: entry.action || '—' }),
        el('span', { class: 'gate-audit-row__meta' }, [
          el('span', { text: entry.actor || '—' }),
          el('span', { text: formatDateTime(entry.at) }),
          el('span', { class: 'mono', text: entry.object_id || '' }),
        ]),
      ])
    );
    list.append(row);
  }
  wrapper.append(list);
  return wrapper;
}

function buildPolicy(policyResponse, policyResult) {
  const wrapper = el('div', { class: 'stack' });
  if (policyResult.status !== 'fulfilled' || !policyResponse) {
    const reason = policyResult.reason;
    wrapper.append(
      reason && reason.status === 403
        ? el('p', { class: 'provenance', text: t('gate.status.policy_role_denied') })
        : el('p', { class: 'provenance', text: t('gate.status.policy_unavailable') })
    );
    return wrapper;
  }
  const policy = policyResponse.policy || {};
  const details = el('dl', { class: 'gate-dl' });
  appendRow(details, t('gate.status.policy_id'), policy.policy_id || '—');
  appendRow(details, t('gate.common.version'), String(policy.version ?? '—'));
  appendRow(details, t('gate.status.policy_updated'), formatDateTime(policy.updated_at));
  appendRow(details, t('gate.status.policy_updated_by'), policy.updated_by || '—');
  appendRow(details, t('gate.status.policy_default'), policy.default_deny ? t('gate.status.default_deny') : t('gate.status.not_default_deny'));
  appendRow(details, t('gate.status.policy_token'), t('gate.status.policy_token_value', { uses: policy.token?.max_uses ?? '—', binding: policy.token?.bind_source_ip ? t('gate.common.active') : t('gate.common.inactive') }));
  appendRow(
    details,
    t('gate.status.policy_allowlists'),
    t('gate.status.policy_allowlists_value', {
      modbus: Array.isArray(policy.modbus_write_allowlist) ? policy.modbus_write_allowlist.length : 0,
      http: Array.isArray(policy.http_write_allowlist) ? policy.http_write_allowlist.length : 0,
    })
  );
  wrapper.append(details);
  const criticalAssets = Array.isArray(policy.critical_assets) ? policy.critical_assets : [];
  wrapper.append(
    banner({
      variant: criticalAssets.length > 0 ? 'warn' : 'info',
      title: t('gate.status.critical_assets_title', { count: criticalAssets.length }),
      text:
        criticalAssets.length > 0
          ? t('gate.status.critical_assets_text', { assets: criticalAssets.join(', ') })
          : t('gate.status.critical_assets_none'),
    })
  );
  wrapper.append(
    el('p', {
      class: 'provenance',
      text: t('gate.status.policy_note'),
    })
  );
  return wrapper;
}

function appendRow(dl, label, value) {
  dl.append(el('dt', { text: label }), el('dd', { text: value === null || value === undefined || value === '' ? '—' : String(value) }));
}

void icon;
