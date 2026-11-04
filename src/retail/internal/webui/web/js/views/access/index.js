/**
 * Access view — service windows and observed maintenance sessions on one time
 * axis. A session outside an approved window is a first-class anomaly; the UI
 * never presents a session as approved just because it exists.
 */
import { api } from '../../core/api.js';
import { el, clear, render, svg } from '../../core/dom.js';
import { getSiteId, getSiteTimezone, toast } from '../../core/store.js';
import {
  formatClock,
  formatDateTime,
  formatRelative,
  formatCount,
  sinceIso,
  nowIso,
} from '../../core/format.js';
import { windowStatusLabel } from '../../core/labels.js';
import { hrefFor } from '../../core/router.js';
import { pageHeader, panel } from '../../components/panel.js';
import { segmented } from '../../components/filters.js';
import { emptyState, errorState, skeletonPage } from '../../components/states.js';
import { alertStatusChip, inWindowChip, readOnlyBadge, severityChip, windowStatusChip } from '../../components/chips.js';
import { icon } from '../../core/icons.js';

import { t, ruleTitle } from '../../i18n/index.js';
import { buildAxis } from './axis.js';
import { buildCriteria, buildWindowCard, buildSessionRow, buildNoSite, instrumentItem, sortByTime } from './blocks.js';
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
  let lastCounts = { windows: 0, sessions: 0, anomalies: 0 };

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

  /** Reflect a programmatic period change in the segmented control. */
  function setPeriodControl(id) {
    const target = WINDOWS.find((entry) => entry.id === id);
    if (!target) return;
    for (const button of windowControl.querySelectorAll('button')) {
      button.setAttribute('aria-pressed', String(button.textContent.trim() === String(target.label).trim()));
    }
    state.windowId = id;
  }

  /** Jump to a seven-day period and tell the operator when it is still empty. */
  async function widenToSevenDays() {
    setPeriodControl('7d');
    await loadData();
    if (lastCounts.windows === 0 && lastCounts.sessions === 0) {
      toast({
        variant: 'info',
        title: t('view.access.widened_empty_title'),
        text: t('view.access.widened_empty_text'),
      });
    }
  }

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
    lastCounts = { windows: windows.length, sessions: sessions.length, anomalies: anomalies.length };
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
                  void widenToSevenDays();
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
