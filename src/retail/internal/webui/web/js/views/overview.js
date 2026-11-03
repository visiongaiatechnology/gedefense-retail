/**
 * Overview — the fleet situation. One instrument strip (not a KPI card wall),
 * the fleet as a readable list, recent facts in the rail. Everything shown comes
 * from /overview; counters without data are shown as unknown, never invented.
 */
import { api } from '../core/api.js';
import { el, clear } from '../core/dom.js';
import { getState, getSiteTimezone, setSite, setSites, updateState } from '../core/store.js';
import { formatDateTime, formatDuration, formatRelative, formatCount, formatClock } from '../core/format.js';
import { navigate, hrefFor } from '../core/router.js';
import { pageHeader, panel } from '../components/panel.js';
import { emptyState } from '../components/states.js';
import {
  alertStatusChip,
  categoryChip,
  collectorStateChip,
  readOnlyBadge,
  severityChip,
  siteStatusChip,
} from '../components/chips.js';
import { icon } from '../core/icons.js';

import { t, ruleTitle } from '../i18n/index.js';
export async function mount({ root, rerender }) {
  const data = await api.getOverview();
  const timeZone = getSiteTimezone();
  syncStore(data);
  const view = buildView({ data, timeZone, rerender });
  clear(root);
  root.append(view);
}

function syncStore(data) {
  const state = getState();
  const totals = data.totals || {};
  updateState({
    openAlerts: Number(totals.open_alerts) || 0,
    criticalAlerts: Number(totals.critical) || 0,
  });
  if (!state.sites.length && Array.isArray(data.sites)) {
    const sites = data.sites.map((entry) => entry.site).filter(Boolean);
    if (sites.length > 0) setSites(sites);
  }
}

function buildView({ data, timeZone, rerender }) {
  const view = el('div', { class: 'view view--overview' });
  const totals = data.totals || {};
  const sites = Array.isArray(data.sites) ? data.sites : [];

  const generatedAt = data.generated_at ? formatClock(data.generated_at) : null;
  const header = pageHeader({
    eyebrow: [
      el('span', { text: 'Lagebild' }),
      generatedAt ? el('span', { text: t('view.overview.as_of_p1', { p1: generatedAt }) }) : null,
      readOnlyBadge(),
    ].filter(Boolean),
    title: 'Lagebild',
    subtitle:
      t('view.overview.stores_cold_chain_and_collectors_at_a_glance_pas'),
    actions: [
      navLink(t('view.overview.check_cold_chain'), 'coldchain', 'btn btn--ghost'),
      navLink(t('view.overview.open_store'), 'site', 'btn btn--secondary'),
    ],
  });

  const onlineCount = sites.filter((entry) => entry.site_status === 'online').length;
  const violations = sites.reduce((sum, entry) => sum + (Number(entry.coldchain?.limit_violations) || 0), 0);
  const qualityIssues = sites.reduce((sum, entry) => sum + (Number(entry.coldchain?.data_quality_issues) || 0), 0);
  const running = Number(totals.collectors_running) || 0;
  const failed = Number(totals.collectors_failed) || 0;

  const instrument = el('section', {
    class: 'instrument',
    attrs: { 'aria-label': t('view.overview.security_posture_metrics') },
  });
  const items = [
    {
      label: t('view.overview.stores'),
      value: formatCount(totals.sites),
      hint: t('view.overview.p1_online_p2_restricted_offline', { p1: formatCount(onlineCount), p2: formatCount(Math.max(0, (Number(totals.sites) || 0) - onlineCount)) }),
    },
    {
      label: t('view.overview.systems'),
      value: formatCount(totals.assets),
      hint: t('view.overview.p1_sensors_p2_known_peers', { p1: formatCount(totals.sensors), p2: formatCount(totals.peers) }),
    },
    {
      label: t('view.overview.open_alerts'),
      value: formatCount(totals.open_alerts),
      hint: t('view.overview.p1_critical_p2_high', { p1: formatCount(totals.critical), p2: formatCount(totals.high) }),
      severity: Number(totals.critical) > 0 ? 'critical' : Number(totals.high) > 0 ? 'warning' : '',
    },
    {
      label: t('nav.coldchain'),
      value: formatCount(violations),
      hint: violations > 0 ? t('view.overview.limit_violations_in_the_time_window') : t('view.overview.no_limit_violations_reported'),
      severity: violations > 0 ? 'warning' : '',
    },
    {
      label: t('enum.category.data_quality'),
      value: formatCount(qualityIssues),
      hint: qualityIssues > 0 ? t('view.overview.notices_frozen_gap_clock_divergence') : t('view.overview.no_anomalies_reported'),
      severity: qualityIssues > 0 ? 'warning' : '',
    },
    {
      label: t('view.overview.collectors'),
      value: `${formatCount(running)}/${formatCount(running + failed)}`,
      hint: failed > 0 ? t('view.overview.p1_failed', { p1: formatCount(failed) }) : t('view.overview.all_read_only_adapters_active'),
      severity: failed > 0 ? 'critical' : '',
    },
  ];
  for (const item of items) {
    instrument.append(instrumentItem(item));
  }

  const fleetPanel = panel({
    title: t('view.overview.stores'),
    sub: t('view.overview.status_from_the_latest_observation_not_derived_f'),
    actions: [
      el('button', {
        type: 'button',
        class: 'btn btn--ghost btn--sm',
        attrs: { 'aria-label': t('view.overview.reload_store_data') },
        on: { click: () => rerender?.() },
      }, icon('refresh', { size: 'sm' }), el('span', { text: t('nav.refresh') })),
    ],
    body: sites.length === 0 ? buildFleetEmpty(rerender) : buildFleet(sites, timeZone),
    flush: true,
  });

  const recentAlerts = Array.isArray(data.recent_alerts) ? data.recent_alerts : [];
  const alertPanel = panel({
    title: t('view.overview.latest_alerts'),
    sub: t('view.overview.facts_from_detection_details_in_the_threat_timel'),
    actions: [navLink(t('gate.common.filter_all'), 'threat', 'btn btn--ghost btn--sm')],
    body: recentAlerts.length === 0 ? el('p', { class: 'panel__body', text: t('view.overview.no_alerts_in_the_current_data_set') }) : buildAlertList(recentAlerts, timeZone),
    flush: true,
  });

  const collectors = Array.isArray(data.collectors) ? data.collectors : [];
  const collectorPanel = panel({
    title: t('view.overview.collectors'),
    sub: t('view.overview.read_only_adapters_and_their_runtime'),
    body: collectors.length === 0 ? el('p', { class: 'panel__body', text: t('view.overview.no_collectors_reported') }) : buildCollectors(collectors, timeZone),
    flush: true,
  });

  const health = getState().health;
  const dataPanel = panel({
    title: t('view.overview.data_status'),
    sub: t('view.overview.local_gateway_state'),
    body: buildDataState(health),
  });

  const limitsPanel = panel({
    title: t('view.overview.limits_of_this_view'),
    body: el('div', { class: 'stack stack--tight' }, [
      el('p', {
        class: 'provenance',
        text: t('view.overview.gedefense_retail_observes_passively_it_does_not'),
      }),
      el('p', {
        class: 'provenance',
        text: t('view.overview.temperature_limits_and_escalation_paths_come_exc'),
      }),
      el('p', {
        class: 'provenance',
        text: t('view.overview.alerts_separate_observation_hypothesis_and_recom'),
      }),
    ]),
  });

  const rail = el('aside', { class: 'view__rail view__rail--sticky', attrs: { 'aria-label': t('view.overview.alerts_and_system_state') } });
  rail.append(alertPanel, collectorPanel, dataPanel, limitsPanel);

  const main = el('div', { class: 'view__main' });
  main.append(fleetPanel);

  const grid = el('div', { class: 'view__grid' });
  grid.append(main, rail);

  view.append(header, instrument, grid);
  return view;
}

function instrumentItem({ label, value, hint, severity }) {
  const item = el('div', {
    class: 'instrument__item',
    dataset: severity ? { severity } : {},
  });
  item.append(
    el('span', { class: 'instrument__label', text: label }),
    el('span', { class: 'instrument__value' }, [
      el('span', { text: value }),
    ]),
    el('span', { class: 'instrument__hint', text: hint })
  );
  return item;
}

function buildFleet(sites, timeZone) {
  const list = el('div', { class: 'fleet' });
  for (const entry of sites) {
    const site = entry.site || {};
    const cold = entry.coldchain || {};
    const violations = Number(cold.limit_violations) || 0;
    const quality = Number(cold.data_quality_issues) || 0;
    const issues = violations + quality;
    const level = issues === 0 ? 'none' : issues <= 2 ? 'low' : issues <= 5 ? 'medium' : 'high';

    const row = el('button', {
      type: 'button',
      class: 'fleet-row',
      attrs: {
        'aria-label': t('view.overview.open_store_p1', { p1: site.name || site.site_id }),
      },
      on: {
        click: () => {
          if (site.site_id) setSite(site.site_id, { silent: true });
          navigate('site');
        },
      },
    });

    const identity = el('span', { class: 'fleet-row__identity' });
    const name = el('span', { class: 'fleet-row__name' }, [
      el('span', { text: site.name || t('view.overview.unnamed_store') }),
      siteStatusChip(entry.site_status || site.status || 'unknown'),
    ]);
    identity.append(name, el('span', { class: 'fleet-row__id', text: site.site_id || '' }));

    const stats = el('span', { class: 'fleet-row__stats' });
    stats.append(
      statBlock(t('view.overview.systems'), formatCount(entry.assets)),
      statBlock(t('enum.alert_status.open'), formatCount(entry.open_alerts), Number(entry.critical) > 0 ? 'critical' : Number(entry.open_alerts) > 0 ? 'warning' : ''),
      statBlock(t('enum.criticality.critical'), formatCount(entry.critical), Number(entry.critical) > 0 ? 'critical' : '')
    );

    const coldBlock = el('span', { class: 'fleet-row__cold' });
    coldBlock.append(el('span', { class: 'fleet-row__cold-label', text: t('view.overview.cold_chain_p1_limits_p2_dq', { p1: formatCount(violations), p2: formatCount(quality) }) }));
    const band = el('span', { class: 'cold-band', dataset: { level }, attrs: { 'aria-hidden': 'true' } });
    band.append(el('span', { class: 'cold-band__fill' }));
    coldBlock.append(band);

    const meta = el('span', { class: 'fleet-row__meta' });
    if (entry.gateway?.status) {
      meta.append(el('span', { class: 'chip chip--status', dataset: { status: entry.gateway.status === 'online' ? 'resolved' : 'investigating' }, text: t('view.overview.gateway_p1', { p1: entry.gateway.status }) }));
    }
    meta.append(
      el('span', {
        text: entry.last_event_at ? t('view.overview.event_p1', { p1: formatRelative(entry.last_event_at) }) : t('view.overview.no_event_observed'),
        attrs: entry.last_event_at ? { title: formatDateTime(entry.last_event_at, timeZone) } : {},
      })
    );

    row.append(identity, stats, coldBlock, meta);
    list.append(row);
  }
  return list;
}

function statBlock(label, value, tone = '') {
  const block = el('span', { class: 'fleet-row__stat' });
  block.append(
    el('span', { class: 'fleet-row__stat-label', text: label }),
    el('span', { class: 'fleet-row__stat-value', dataset: tone ? { tone } : {}, text: value })
  );
  return block;
}

function buildFleetEmpty(rerender) {
  return el('div', { class: 'panel__body' }, [
    emptyState({
      icon: 'store',
      title: t('view.overview.no_store_configured'),
      text: t('view.overview.the_gateway_reports_no_store_check_the_site_sect'),
      actions: [
        el('button', {
          type: 'button',
          class: 'btn btn--primary',
          text: t('view.overview.check_again'),
          on: { click: () => rerender?.() },
        }),
        el('a', { class: 'btn btn--ghost', href: hrefFor('threat'), text: t('view.overview.open_threat_timeline') }),
      ],
    }),
  ]);
}

function buildAlertList(alerts, timeZone) {
  const list = el('div', { class: 'record-list' });
  for (const alert of alerts) {
    const link = el('a', {
      class: 'record',
      href: hrefFor('threat', { alert: alert.alert_id }),
      attrs: { 'aria-label': t('view.overview.open_alert_p1_in_the_threat_timeline', { p1: ruleTitle(alert.rule_id, alert.title) || '' }) },
    });
    const main = el('span', { class: 'record__main' });
    const title = el('span', { class: 'record__title' }, [
      severityChip(alert.severity),
      el('span', { text: ruleTitle(alert.rule_id, alert.title) || t('view.overview.alert_without_title') }),
    ]);
    const meta = el('span', { class: 'record__meta' }, [
      categoryChip(alert.category),
      alertStatusChip(alert.status),
      el('span', { text: formatRelative(alert.last_seen_at, Date.now()) }),
    ]);
    main.append(title, meta);
    const side = el('span', { class: 'record__side' });
    side.append(icon('chevron-right', { size: 'sm' }));
    link.append(main, side);
    list.append(link);
  }
  return list;
}

function buildCollectors(collectors, timeZone) {
  const list = el('div', { class: 'collector-list' });
  for (const collector of collectors) {
    const row = el('div', { class: 'collector-row' });
    const main = el('div', { class: 'collector-row__main' });
    main.append(
      el('span', { class: 'collector-row__id', text: collector.adapter_id || '—' }),
      el('span', {
        class: 'collector-row__counters',
        text: t('view.overview.events_p1_errors_p2_parser_p3', { p1: formatCount(collector.events), p2: formatCount(collector.errors), p3: formatCount(collector.parser_errors) }),
      }),
      el('span', {
        class: 'collector-row__counters',
        text: collector.last_event_at ? t('view.overview.latest_event_p1', { p1: formatRelative(collector.last_event_at) }) : t('view.overview.no_event_yet'),
        attrs: collector.last_event_at ? { title: formatDateTime(collector.last_event_at, timeZone) } : {},
      })
    );
    row.append(main, el('span', { class: 'collector-row__state' }, collectorStateChip(collector.state)));
    list.append(row);
  }
  return list;
}

function buildDataState(health) {
  const wrapper = el('div', { class: 'stack' });
  if (!health) {
    wrapper.append(el('p', { class: 'provenance', text: t('view.overview.gateway_health_data_is_currently_unavailable') }));
    return wrapper;
  }
  const storage = health.storage || {};
  const line = el('div', { class: 'storage-line' });
  line.append(
    el('span', { text: t('view.overview.events_p1', { p1: formatCount(storage.events) }) }),
    el('span', { text: t('view.overview.alerts_p1', { p1: formatCount(storage.alerts) }) }),
    el('span', { text: t('view.overview.audit_chain', { p1: storage.audit_chain_ok ? t('view.overview.audit_verified') : t('view.overview.audit_not_verified') }) })
  );
  wrapper.append(line);
  if (Number.isFinite(Number(health.uptime_s))) {
    wrapper.append(el('p', { class: 'provenance', text: t('view.overview.gateway_uptime_p1', { p1: formatDuration(health.uptime_s) }) }));
  }
  if (health.read_only === true) {
    wrapper.append(el('p', { class: 'provenance', text: t('view.overview.gateway_is_running_in_read_only_mode') }));
  }
  return wrapper;
}

function navLink(label, viewId, className) {
  return el('a', { class: className, href: hrefFor(viewId), text: label });
}
