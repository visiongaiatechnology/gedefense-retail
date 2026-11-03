/**
 * Access view — service windows and observed maintenance sessions on one time
 * axis. A session outside an approved window is a first-class anomaly; the UI
 * never presents a session as approved just because it exists.
 */
import { api } from '../core/api.js';
import { el, clear, render, svg } from '../core/dom.js';
import { getSiteId, getSiteTimezone } from '../core/store.js';
import {
  formatClock,
  formatDateTime,
  formatRelative,
  formatCount,
  sinceIso,
  nowIso,
} from '../core/format.js';
import { windowStatusLabel } from '../core/labels.js';
import { hrefFor } from '../core/router.js';
import { pageHeader, panel } from '../components/panel.js';
import { segmented } from '../components/filters.js';
import { emptyState, errorState, skeletonPage } from '../components/states.js';
import { alertStatusChip, inWindowChip, readOnlyBadge, severityChip, windowStatusChip } from '../components/chips.js';
import { icon } from '../core/icons.js';

import { t, ruleTitle } from '../i18n/index.js';
const WINDOWS = [
  { id: '6h', label: '6 h', hours: 6 },
  { id: '24h', label: '24 h', hours: 24 },
  { id: '7d', label: t('view.access.m_7_days'), hours: 24 * 7 },
];

export async function mount({ root }) {
  const siteId = getSiteId();
  if (!siteId) {
    render(root, buildNoSite());
    return;
  }

  const timeZone = getSiteTimezone();
  const state = { windowId: '24h' };

  const summaryHost = el('div');
  const axisHost = el('div');
  const windowsHost = el('div');
  const sessionsHost = el('div');
  const anomaliesHost = el('div');

  const windowControl = segmented({
    label: t('view.coldchain.time_window'),
    options: WINDOWS.map((entry) => ({ value: entry.id, label: entry.label })),
    value: state.windowId,
    onChange: (value) => {
      state.windowId = value;
      void loadData();
    },
  });

  const header = pageHeader({
    eyebrow: [t('view.access.maintenance_access'), readOnlyBadge()],
    title: t('view.access.access'),
    subtitle:
      t('view.access.approved_maintenance_windows_observed_sessions_a'),
    actions: [windowControl, el('a', { class: 'btn btn--ghost', href: hrefFor('site'), text: t('view.overview.open_store') })],
  });

  const axisPanel = panel({
    title: t('view.access.timeline'),
    sub: t('view.access.windows_sessions_and_anomalies_in_the_selected_p'),
    body: axisHost,
  });
  const windowsPanel = panel({ title: 'Wartungsfenster', sub: t('view.access.operator_approvals'), body: windowsHost, flush: true });
  const sessionsPanel = panel({ title: t('view.access.sessions'), sub: t('view.access.observed_or_reported'), body: sessionsHost, flush: true });
  const anomalyPanel = panel({
    title: t('view.access.access_anomalies'),
    sub: t('view.access.alerts_of_category_access'),
    body: anomaliesHost,
    flush: true,
  });

  const main = el('div', { class: 'view__main' });
  main.append(summaryHost, axisPanel, el('div', { class: 'split' }, [windowsPanel, sessionsPanel]), anomalyPanel);

  const rail = el('aside', { class: 'view__rail view__rail--sticky', attrs: { 'aria-label': t('view.access.review_criteria') } });
  rail.append(
    panel({
      title: t('view.access.review_criteria'),
      sub: t('view.access.how_the_gateway_justifies_an_access_anomaly'),
      body: buildCriteria(),
    }),
    panel({
      title: t('view.integrity.boundaries'),
      body: el('div', { class: 'stack stack--tight' }, [
        el('p', {
          class: 'provenance',
          text: t('view.access.maintenance_windows_are_created_and_closed_via_t'),
        }),
        el('p', {
          class: 'provenance',
          text: t('view.access.sessions_without_approval_are_a_review_task_not'),
        }),
      ]),
    })
  );

  const layout = el('div', { class: 'view view--access' });
  const grid = el('div', { class: 'view__grid' });
  grid.append(main, rail);
  layout.append(header, grid);
  render(root, layout);

  await loadData();

  async function loadData() {
    const entry = WINDOWS.find((windowOption) => windowOption.id === state.windowId) || WINDOWS[1];
    const since = sinceIso(entry.hours);
    const until = nowIso();
    for (const host of [summaryHost, axisHost, windowsHost, sessionsHost, anomaliesHost]) {
      clear(host);
    }
    axisHost.append(skeletonPage(t('view.access.loading_maintenance_access')));

    try {
      const data = await api.getAccess({ site_id: siteId, since });
      const windows = Array.isArray(data.windows) ? data.windows : [];
      const sessions = Array.isArray(data.sessions) ? data.sessions : [];
      const anomalies = Array.isArray(data.anomalies) ? data.anomalies : [];
      renderData({ windows, sessions, anomalies }, { since, until, timeZone });
    } catch (error) {
      clear(axisHost);
      axisHost.append(
        errorState({
          title: t('view.access.maintenance_access_could_not_be_loaded'),
          error,
          actions: [el('button', { type: 'button', class: 'btn btn--primary', text: t('view.assets.reload'), on: { click: () => void loadData() } })],
        })
      );
    }
  }

  function renderData({ windows, sessions, anomalies }, { since, until }) {
    const outsideWindow = sessions.filter((session) => session.in_window === false);
    renderSummary(windows, sessions, anomalies, outsideWindow);
    renderAxis({ windows, sessions, anomalies, since, until });
    renderWindows(windows);
    renderSessions(sessions, windows, timeZone);
    renderAnomalies(anomalies);
  }

  function renderSummary(windows, sessions, anomalies, outsideWindow) {
    const instrument = el('section', { class: 'instrument', attrs: { 'aria-label': t('view.access.access_metrics') } });
    instrument.append(
      instrumentItem(t('view.access.windows'), formatCount(windows.length), windows.some((windowEntry) => windowEntry.status === 'active') ? t('view.access.at_least_one_active_window') : t('view.access.no_active_window')),
      instrumentItem(t('view.access.sessions'), formatCount(sessions.length), t('view.access.p1_observed', { p1: formatCount(sessions.filter((session) => session.observed).length) })),
      instrumentItem(
        t('view.access.outside_window'),
        formatCount(outsideWindow.length),
        outsideWindow.length > 0 ? t('view.access.review_required') : t('view.access.all_sessions_within_the_window'),
        outsideWindow.length > 0 ? 'critical' : ''
      ),
      instrumentItem(
        t('view.access.anomalies'),
        formatCount(anomalies.length),
        anomalies.length > 0 ? t('view.access.alerts_of_category_access') : t('view.access.no_alerts_reported'),
        anomalies.length > 0 ? 'warning' : ''
      )
    );
    clear(summaryHost);
    summaryHost.append(instrument);
  }

  function renderAxis({ windows, sessions, anomalies, since, until }) {
    clear(axisHost);
    if (windows.length === 0 && sessions.length === 0) {
      axisHost.append(
        emptyState({
          icon: 'key',
          title: t('view.access.no_maintenance_access_in_the_period'),
          text: t('view.access.neither_approved_windows_nor_sessions_were_obser'),
          actions: [
            el('button', {
              type: 'button',
              class: 'btn btn--secondary',
              text: t('view.access.set_time_window_to_7_days'),
              on: {
                click: () => {
                  state.windowId = '7d';
                  void loadData();
                },
              },
            }),
          ],
        })
      );
      return;
    }
    axisHost.append(buildAxis({ windows, sessions, anomalies, since, until, timeZone }));
  }

  function renderWindows(windows) {
    clear(windowsHost);
    if (windows.length === 0) {
      windowsHost.append(el('div', { class: 'panel__body' }, el('p', { class: 'provenance', text: t('view.access.no_maintenance_windows_in_the_period') })));
      return;
    }
    for (const windowEntry of sortByTime(windows, 'starts_at')) {
      windowsHost.append(buildWindowCard(windowEntry, timeZone));
    }
  }

  function renderSessions(sessions, windows, tz) {
    clear(sessionsHost);
    if (sessions.length === 0) {
      sessionsHost.append(el('div', { class: 'panel__body' }, el('p', { class: 'provenance', text: t('view.access.no_sessions_in_the_period') })));
      return;
    }
    const windowVendors = new Map(windows.map((windowEntry) => [windowEntry.maintenance_window_id, windowEntry.vendor]));
    for (const session of sortByTime(sessions, 'started_at')) {
      sessionsHost.append(buildSessionRow(session, windowVendors, tz));
    }
  }

  function renderAnomalies(anomalies) {
    clear(anomaliesHost);
    if (anomalies.length === 0) {
      anomaliesHost.append(el('div', { class: 'panel__body' }, el('p', { class: 'provenance', text: t('view.access.no_access_alerts_in_the_period') })));
      return;
    }
    const list = el('div', { class: 'record-list' });
    for (const alert of anomalies) {
      const link = el('a', {
        class: 'record',
        href: hrefFor('threat', { alert: alert.alert_id }),
        attrs: { 'aria-label': t('view.overview.open_alert_p1_in_the_threat_timeline', { p1: ruleTitle(alert.rule_id, alert.title) || '' }) },
      });
      const main = el('span', { class: 'record__main' });
      main.append(
        el('span', { class: 'record__title' }, [severityChip(alert.severity), el('span', { text: ruleTitle(alert.rule_id, alert.title) || t('view.overview.alerte_sans_titre') })]),
        el('span', { class: 'record__meta' }, [
          alertStatusChip(alert.status),
          el('span', { text: formatRelative(alert.last_seen_at) }),
          el('span', { text: alert.rule_id || '' }),
        ])
      );
      link.append(main, el('span', { class: 'record__side' }, icon('chevron-right', { size: 'sm' })));
      list.append(link);
    }
    anomaliesHost.append(list);
  }
}

/* ----------------------------------------------------------------- axis */

function buildAxis({ windows, sessions, anomalies, since, until, timeZone }) {
  const width = 860;
  const height = 200;
  const pad = { left: 96, right: 20, top: 22, bottom: 30 };
  const plotW = width - pad.left - pad.right;
  const start = new Date(since).getTime();
  const end = new Date(until).getTime();
  const span = Math.max(1, end - start);

  const root = svg('svg', {
    class: 'access-axis__svg',
    viewBox: `0 0 ${width} ${height}`,
    role: 'img',
    'aria-label': t('view.access.timeline_of_maintenance_windows_sessions_and_ano'),
  });
  const title = svg('title');
  title.textContent = t('view.access.maintenance_access_timeline');
  const desc = svg('desc');
  desc.textContent = `${windows.length} Wartungsfenster, ${sessions.length} Sitzungen, ${anomalies.length} Anomalien zwischen ${formatDateTime(
    since,
    timeZone
  )} und ${formatDateTime(until, timeZone)}.`;
  root.append(title, desc);

  const toX = (iso) => pad.left + ((new Date(iso).getTime() - start) / span) * plotW;
  const clampX = (value) => Math.min(pad.left + plotW, Math.max(pad.left, value));
  const lanes = [
    { key: 'windows', label: t('view.access.windows'), y: pad.top, height: 14 },
    { key: 'sessions', label: t('view.access.sessions'), y: pad.top + 44, height: 12 },
    { key: 'anomalies', label: t('view.access.anomalies'), y: pad.top + 88, height: 14 },
  ];

  for (const lane of lanes) {
    root.append(
      svg('text', { x: pad.left - 10, y: lane.y + 11, 'text-anchor': 'end', class: 'row-label' }, lane.label)
    );
    root.append(
      svg('line', {
        x1: pad.left,
        y1: lane.y + lane.height + 8,
        x2: pad.left + plotW,
        y2: lane.y + lane.height + 8,
        class: 'grid-line',
        stroke: 'var(--line)',
      })
    );
  }

  // Time grid + labels.
  const ticks = 6;
  for (let index = 0; index < ticks; index += 1) {
    const at = start + (span * index) / (ticks - 1);
    const x = pad.left + (plotW * index) / (ticks - 1);
    root.append(svg('line', { x1: x, y1: pad.top - 8, x2: x, y2: height - pad.bottom + 4, class: 'grid-line' }));
    root.append(svg('text', { x, y: height - pad.bottom + 18, 'text-anchor': 'middle' }, formatClock(at, timeZone)));
  }

  // Windows lane.
  for (const windowEntry of windows) {
    const x1 = toX(windowEntry.starts_at);
    const x2 = toX(windowEntry.ends_at);
    const left = clampX(Math.min(x1, x2));
    const right = clampX(Math.max(x1, x2));
    const bar = svg('rect', {
      x: left,
      y: lanes[0].y,
      width: Math.max(4, right - left),
      height: lanes[0].height,
      class: windowEntry.status === 'closed' || windowEntry.status === 'cancelled' ? 'window-bar window-bar--closed' : 'window-bar',
    });
    const barTitle = svg('title');
    barTitle.textContent = `${windowEntry.vendor || t('view.access.maintenance')} · ${windowStatusLabel(windowEntry.status)} · ${formatDateTime(
      windowEntry.starts_at,
      timeZone
    )} – ${formatDateTime(windowEntry.ends_at, timeZone)}`;
    bar.append(barTitle);
    root.append(bar);
  }

  // Session lane.
  for (const session of sessions) {
    const x = clampX(toX(session.started_at));
    const startedAt = new Date(session.started_at).getTime();
    const endedAt = session.ended_at ? new Date(session.ended_at).getTime() : startedAt + 20 * 60 * 1000;
    const width = Math.max(4, clampX(toX(new Date(endedAt).toISOString())) - x);
    const bar = svg('rect', {
      x,
      y: lanes[1].y,
      width,
      height: lanes[1].height,
      class: session.in_window === false ? 'session-bar session-bar--anomaly' : 'session-bar',
    });
    const sessionTitle = svg('title');
    sessionTitle.textContent = `${session.vendor || session.user || t('view.access.session')} · ${session.in_window === false ? t('view.access.outside_window_2') : t('view.access.within_window')} · ${formatClock(
      session.started_at,
      timeZone
    )}`;
    bar.append(sessionTitle);
    root.append(bar);
  }

  // Anomaly lane (diamonds).
  for (const anomaly of anomalies) {
    const x = clampX(toX(anomaly.first_seen_at || anomaly.last_seen_at));
    const y = lanes[2].y + 7;
    const diamond = svg('path', {
      d: `M${x} ${y - 6} L${x + 6} ${y} L${x} ${y + 6} L${x - 6} ${y} Z`,
      class: 'session-bar session-bar--anomaly',
    });
    const anomalyTitle = svg('title');
    anomalyTitle.textContent = `${anomaly.title || 'Anomalie'} · ${formatDateTime(anomaly.first_seen_at, timeZone)}`;
    diamond.append(anomalyTitle);
    root.append(diamond);
  }

  // "Now" marker.
  const nowX = clampX(toX(until));
  root.append(svg('line', { x1: nowX, y1: pad.top - 6, x2: nowX, y2: height - pad.bottom + 4, class: 'now-line' }));

  const figure = el('figure', { class: 'chart-figure' });
  figure.append(
    root,
    el('figcaption', {
      text: t('view.access.p1_p2_windows_sessions_and_anomalies_details_in', { p1: formatDateTime(since, timeZone), p2: formatDateTime(until, timeZone) }),
    })
  );
  return figure;
}

/* --------------------------------------------------------------- cards */

function buildWindowCard(windowEntry, timeZone) {
  const card = el('div', { class: 'window-card' });
  const head = el('div', { class: 'window-card__head' });
  head.append(
    windowStatusChip(windowEntry.status),
    el('span', { class: 'window-card__vendor', text: windowEntry.vendor || t('view.access.unknown_vendor') }),
    windowEntry.ticket_ref ? el('span', { class: 'chip chip--protocol', text: windowEntry.ticket_ref }) : null,
    el('span', { class: 'mono provenance', text: windowEntry.maintenance_window_id || '' })
  );
  card.append(head);

  const grid = el('div', { class: 'window-card__grid' });
  grid.append(
    field(t('view.access.period'), `${formatDateTime(windowEntry.starts_at, timeZone)} – ${formatDateTime(windowEntry.ends_at, timeZone)}`),
    field(t('view.access.approved_by'), windowEntry.approved_by || '—'),
    field(t('view.access.approval_time'), formatDateTime(windowEntry.approved_at, timeZone)),
    field(t('view.incident.zones'), Array.isArray(windowEntry.zone_ids) && windowEntry.zone_ids.length > 0 ? windowEntry.zone_ids.join(', ') : t('view.access.whole_store')),
    field(
      t('view.access.target_systems'),
      Array.isArray(windowEntry.target_asset_ids) && windowEntry.target_asset_ids.length > 0
        ? windowEntry.target_asset_ids.join(', ')
        : t('view.access.all_equipment_of_the_zones')
    ),
    field(
      t('view.access.allowed_sources'),
      Array.isArray(windowEntry.allowed_source_cidrs) && windowEntry.allowed_source_cidrs.length > 0
        ? windowEntry.allowed_source_cidrs.join(', ')
        : t('view.access.not_restricted')
    )
  );
  card.append(grid);
  if (windowEntry.notes) card.append(el('p', { class: 'provenance', text: windowEntry.notes }));
  return card;
}

function buildSessionRow(session, windowVendors, timeZone) {
  const row = el('div', { class: 'session-row' });
  const main = el('div', { class: 'session-row__main' });
  const meta = el('div', { class: 'mini-list__title' });
  meta.append(
    inWindowChip(session.in_window !== false),
    el('span', { text: session.vendor || session.user || session.session_id || t('view.access.session') }),
    el('span', { class: 'badge badge--muted', text: session.observed ? 'beobachtet' : 'gemeldet' })
  );
  main.append(meta);
  const details = el('div', { class: 'session-row__meta' });
  details.append(
    el('span', { text: t('view.access.target_p1', { p1: session.target_asset || '—' }) }),
    el('span', { text: t('view.threat.source_p1', { p1: session.source_device || '—' }) }),
    el('span', { text: t('view.access.method_p1', { p1: session.method || '—' }) }),
    el('span', { text: formatDateTime(session.started_at, timeZone) }),
    session.ended_at ? el('span', { text: t('view.access.ends_p1', { p1: formatDateTime(session.ended_at, timeZone) }) }) : el('span', { text: t('view.access.still_open') }),
    session.window_id
      ? el('span', { text: t('view.access.window_p1', { p1: windowVendors.get(session.window_id) || session.window_id }) })
      : el('span', { text: t('view.access.no_window_assigned') }),
    el('span', { class: 'mono', text: session.session_id || '' })
  );
  main.append(details);
  row.append(main);
  return row;
}

function field(label, value) {
  const wrapper = el('div');
  wrapper.append(
    el('div', { class: 'window-card__label', text: label }),
    el('div', { class: 'detail-field__value', text: value || '—' })
  );
  return wrapper;
}

function buildCriteria() {
  const list = el('ul', { class: 'list-disc stack stack--tight' });
  const items = [
    t('view.access.session_outside_an_approved_maintenance_window_i'),
    t('view.access.source_device_not_in_allowed_source_cidrs_of_the'),
    t('view.access.target_asset_outside_the_target_asset_ids_of_the'),
    t('view.access.vendor_not_in_maintenance_trusted_vendors_of_the'),
    t('view.access.new_source_device_not_previously_observed_in_the'),
  ];
  for (const item of items) list.append(el('li', { class: 'provenance', text: item }));
  return list;
}

function instrumentItem(label, value, hint, severity = '') {
  const item = el('div', { class: 'instrument__item', dataset: severity ? { severity } : {} });
  item.append(
    el('span', { class: 'instrument__label', text: label }),
    el('span', { class: 'instrument__value' }, el('span', { text: value })),
    el('span', { class: 'instrument__hint', text: hint })
  );
  return item;
}

function sortByTime(items, key) {
  return [...items].sort((a, b) => new Date(a[key] || 0).getTime() - new Date(b[key] || 0).getTime());
}

function buildNoSite() {
  const view = el('div', { class: 'view' });
  view.append(
    el('h1', { class: 'view__title', text: t('view.access.access') }),
    emptyState({
      icon: 'key',
      title: t('view.site.no_store_selected'),
      text: t('view.access.select_a_store_above_to_see_maintenance_windows'),
      actions: [el('a', { class: 'btn btn--primary', href: hrefFor('overview'), text: t('notfound.action') })],
    })
  );
  return view;
}
