/**
 * Threat timeline — correlated events with the three-layer evidence contract.
 * Observed facts, the derived hypothesis and recommended checks are presented
 * in separate labelled blocks; raw events never masquerade as an attack.
 */
import { api } from '../core/api.js';
import { el, clear, render } from '../core/dom.js';
import { getSiteId, getSiteTimezone } from '../core/store.js';
import { formatDateTime, formatCount, sinceIso } from '../core/format.js';
import { SEVERITY_OPTIONS, CATEGORY_OPTIONS, categoryLabel } from '../core/labels.js';
import { hrefFor } from '../core/router.js';
import { detailGrid, pageHeader, panel } from '../components/panel.js';
import { filterBar, segmented } from '../components/filters.js';
import { emptyState, errorState, partialBanner, skeletonPage } from '../components/states.js';
import { threatTimeline } from '../components/timeline.js';
import { correlationBlocks, evidenceItems, recommendedActions, safetyConstraints } from '../components/evidence.js';
import { alertStatusChip, categoryChip, confidenceMeter, incidentStatusChip, readOnlyBadge, severityChip } from '../components/chips.js';
import { icon } from '../core/icons.js';

import { t, ruleTitle, ruleSummary } from '../i18n/index.js';
const TIME_WINDOWS = [
  { id: '6h', label: '6 h', hours: 6 },
  { id: '24h', label: '24 h', hours: 24 },
  { id: '7d', label: t('view.access.m_7_days'), hours: 24 * 7 },
];

export async function mount({ root, query }) {
  const siteId = getSiteId();
  if (!siteId) {
    render(root, buildNoSite());
    return;
  }

  const timeZone = getSiteTimezone();
  const state = {
    windowId: '24h',
    severity: '',
    category: '',
    correlatedOnly: false,
    selected: null,
  };
  const detailCache = new Map();
  let timelineItems = [];
  let correlatedIds = new Set();
  let detailsUnavailable = false;
  let requestSeq = 0;

  const timelineHost = el('div');
  const detailHost = el('div');
  const detailPanelTitle = el('span', { text: t('view.threat.correlation_file') });

  const windowControl = segmented({
    label: t('view.coldchain.time_window'),
    options: TIME_WINDOWS.map((entry) => ({ value: entry.id, label: entry.label })),
    value: state.windowId,
    onChange: (value) => {
      state.windowId = value;
      void loadTimeline();
    },
  });

  const filter = filterBar({
    fields: [
      { type: 'select', key: 'severity', label: t('view.threat.severity'), value: '', options: [{ value: '', label: t('view.assets.all_levels') }, ...SEVERITY_OPTIONS] },
      { type: 'select', key: 'category', label: t('view.threat.category'), value: '', options: [{ value: '', label: t('view.threat.all_categories') }, ...CATEGORY_OPTIONS] },
      { type: 'checkbox', key: 'correlatedOnly', label: t('view.threat.correlated_chains_only'), value: false },
    ],
    summary: t('view.assets.loading'),
    onChange: (key, value) => {
      if (key === 'correlatedOnly') state.correlatedOnly = value === '1';
      else state[key] = value;
      renderTimeline();
    },
  });

  const header = pageHeader({
    eyebrow: [t('view.threat.threat_timeline'), readOnlyBadge()],
    title: t('view.threat.threats'),
    subtitle:
      t('view.threat.events_alerts_and_incidents_in_chronological_ord'),
    actions: [windowControl, el('a', { class: 'btn btn--ghost', href: hrefFor('access'), text: t('view.threat.access_view') })],
  });

  const timelinePanel = panel({
    title: t('view.threat.event_timeline'),
    sub: t('view.threat.facts_from_events_alerts_access_and_incidents_no'),
    body: timelineHost,
    flush: true,
  });

  const detailPanel = panel({
    title: detailPanelTitle,
    sub: t('view.threat.review_selected_entry'),
    body: detailHost,
  });

  const left = el('div', { class: 'stack' });
  left.append(filter.element, timelinePanel);
  const right = el('aside', { class: 'view__rail view__rail--sticky', attrs: { 'aria-label': t('view.threat.details_of_the_selected_event') } });
  right.append(detailPanel);

  const layout = el('div', { class: 'view view--threat' });
  const grid = el('div', { class: 'threat-layout' });
  grid.append(left, right);
  layout.append(header, grid);
  render(root, layout);

  await loadTimeline();

  async function loadTimeline() {
    const entry = TIME_WINDOWS.find((windowEntry) => windowEntry.id === state.windowId) || TIME_WINDOWS[1];
    const since = sinceIso(entry.hours);
    const sequence = ++requestSeq;
    clear(timelineHost);
    timelineHost.append(el('div', { class: 'panel__body' }, skeletonPage(t('view.threat.loading_timeline'))));
    filter.setSummary(t('view.assets.loading'));

    try {
      const [timeline, alertsResponse] = await Promise.all([
        api.getTimeline({ site_id: siteId, since, limit: 200 }),
        api.getAlerts({ site_id: siteId, limit: 200 }).catch(() => null),
      ]);
      if (sequence !== requestSeq) return;

      timelineItems = Array.isArray(timeline.items) ? timeline.items : [];
      const alerts = Array.isArray(alertsResponse?.items) ? alertsResponse.items : [];
      correlatedIds = new Set(alerts.filter((alert) => alert.correlation).map((alert) => alert.alert_id));
      detailsUnavailable = !alertsResponse;

      renderTimeline();
      if (!alertsResponse) {
        filter.setSummary(t('view.threat.p1_entries_alert_details_unavailable', { p1: formatCount(timelineItems.length) }));
      }
      preselectFromQuery(query);
    } catch (error) {
      if (sequence !== requestSeq) return;
      clear(timelineHost);
      timelineHost.append(
        el('div', { class: 'panel__body' }, [
          errorState({
            title: t('view.threat.threat_timeline_could_not_be_loaded'),
            error,
            actions: [el('button', { type: 'button', class: 'btn btn--primary', text: t('view.assets.reload'), on: { click: () => void loadTimeline() } })],
          }),
        ])
      );
      filter.setSummary(t('gate.common.error'));
    }
  }

  function filteredItems() {
    return timelineItems.filter((item) => {
      if (state.severity && item.severity !== state.severity) return false;
      if (state.category && item.category !== state.category) return false;
      if (state.correlatedOnly) {
        if (item.kind === 'alert') return correlatedIds.has(item.ref_id);
        // Incidents only exist as correlated chains by construction.
        if (item.kind === 'incident') return true;
        return false;
      }
      return true;
    });
  }

  function renderTimeline() {
    clear(timelineHost);
    if (detailsUnavailable) {
      timelineHost.append(
        el('div', { class: 'panel__body' }, [
          partialBanner({
            title: t('view.threat.partial_data_alert_details_unavailable'),
            text: t('view.threat.the_event_timeline_was_loaded_the_alert_list_was'),
          }),
        ])
      );
    }
    const items = filteredItems();
    filter.setSummary(t('view.threat.p1_of_p2_entries', { p1: formatCount(items.length), p2: formatCount(timelineItems.length) }));
    if (items.length === 0) {
      timelineHost.append(
        el('div', { class: 'panel__body' }, [
          emptyState({
            icon: 'radar',
            title: timelineItems.length === 0 ? t('view.threat.no_events_in_the_time_window') : t('view.threat.no_entries_for_these_filters'),
            text:
              timelineItems.length === 0
                ? t('view.threat.the_timeline_contains_only_facts_from_events_ale')
                : t('view.threat.adjust_severity_category_or_the_correlation_sele'),
            actions: [
              theEndButton(),
              el('button', {
                type: 'button',
                class: 'btn btn--ghost',
                text: t('gate.denies.reset_filters'),
                on: {
                  click: () => {
                    state.severity = '';
                    state.category = '';
                    state.correlatedOnly = false;
                    filter.setValue('severity', '');
                    filter.setValue('category', '');
                    filter.setValue('correlatedOnly', false);
                    renderTimeline();
                  },
                },
              }),
            ],
          }),
        ])
      );
      return;
    }

    const mapped = items.map((item) => ({
      key: `${item.kind}:${item.ref_id}`,
      at: item.at,
      kind: item.kind,
      severity: item.severity || 'info',
      title: item.title || t('enum.timeline_kind.event'),
      category: item.category,
      refId: item.ref_id,
    }));

    const timeline = threatTimeline({
      items: mapped,
      selectedKey: state.selected ? `${state.selected.kind}:${state.selected.refId}` : '',
      timeZone,
      onSelect: (item) => {
        state.selected = { kind: item.kind, refId: item.refId };
        renderTimeline();
        void loadDetail(item.kind, item.refId, item);
      },
    });
    timelineHost.append(timeline || el('p', { class: 'panel__body' }));
  }

  function theEndButton() {
    return el('button', {
      type: 'button',
      class: 'btn btn--secondary',
      text: t('view.access.set_time_window_to_7_days'),
      on: {
        click: () => {
          state.windowId = '7d';
          void loadTimeline();
        },
      },
    });
  }

  function preselectFromQuery(searchParams) {
    const alertId = searchParams.get('alert');
    const incidentId = searchParams.get('incident');
    if (alertId) {
      state.selected = { kind: 'alert', refId: alertId };
      renderTimeline();
      void loadDetail('alert', alertId);
      return;
    }
    if (incidentId) {
      state.selected = { kind: 'incident', refId: incidentId };
      renderTimeline();
      void loadDetail('incident', incidentId);
      return;
    }
    const first = timelineItems.find((item) => item.kind === 'alert' && correlatedIds.has(item.ref_id)) || timelineItems.find((item) => item.kind === 'alert');
    if (first) {
      state.selected = { kind: first.kind, refId: first.ref_id };
      renderTimeline();
      void loadDetail(first.kind, first.ref_id);
    } else {
      clear(detailHost);
      detailHost.append(
        el('p', { class: 'provenance', text: t('view.threat.select_an_entry_on_the_left_to_see_facts_hypothe') })
      );
    }
  }

  async function loadDetail(kind, refId, item = null) {
    clear(detailHost);
    detailHost.append(skeletonPage(t('view.threat.loading_details')));
    try {
      if (kind === 'alert') {
        const data = await cachedAlert(refId);
        renderAlertDetail(data.alert, data.evidence_events || []);
      } else if (kind === 'incident') {
        const data = await cachedIncident(refId);
        renderIncidentDetail(data);
      } else {
        renderRawEvent(item || timelineItems.find((entry) => entry.ref_id === refId));
      }
    } catch (error) {
      clear(detailHost);
      detailHost.append(
        errorState({
          title: t('view.threat.could_not_load_details'),
          error,
          actions: [
            el('button', {
              type: 'button',
              class: 'btn btn--secondary',
              text: t('view.threat.try_again'),
              on: { click: () => void loadDetail(kind, refId, item) },
            }),
          ],
        })
      );
    }
  }

  async function cachedAlert(alertId) {
    if (!detailCache.has(`alert:${alertId}`)) {
      detailCache.set(`alert:${alertId}`, await api.getAlert(alertId));
    }
    return detailCache.get(`alert:${alertId}`);
  }

  async function cachedIncident(incidentId) {
    if (!detailCache.has(`incident:${incidentId}`)) {
      detailCache.set(`incident:${incidentId}`, await api.getIncident(incidentId));
    }
    return detailCache.get(`incident:${incidentId}`);
  }

  function renderAlertDetail(alert, evidenceEvents) {
    clear(detailHost);
    if (!alert) {
      detailHost.append(el('p', { class: 'provenance', text: t('view.threat.alert_data_is_missing') }));
      return;
    }
    const head = el('div', { class: 'stack stack--tight' });
    head.append(
      el('div', { class: 'cluster' }, [
        severityChip(alert.severity),
        categoryChip(alert.category),
        alertStatusChip(alert.status),
        confidenceMeter(alert.confidence, { label: t('view.threat.alert_confidence') }),
      ]),
      el('h3', { class: 'inspector__title', text: ruleTitle(alert.rule_id, alert.title) || t('enum.timeline_kind.alert') }),
      el('p', { class: 'provenance', text: ruleSummary(alert.rule_id, alert.summary) || '' })
    );
    detailHost.append(head);

    const correlation = correlationBlocks(alert);
    if (correlation) detailHost.append(correlation);
    else {
      detailHost.append(
        el('div', { class: 'banner banner--warn', attrs: { role: 'status' } }, [
          icon('warning', { size: 'sm' }),
          el('div', { class: 'banner__body' }, [
            el('span', { class: 'banner__title', text: t('view.threat.no_correlation_file_stored') }),
            el('span', { class: 'banner__text', text: t('view.threat.this_alert_is_a_single_observation_it_is_not_pre') }),
          ]),
        ])
      );
    }

    detailHost.append(sectionBlock(t('view.threat.evidence'), evidenceItems(alert.evidence)));
    if (Array.isArray(evidenceEvents) && evidenceEvents.length > 0) {
      detailHost.append(sectionBlock(t('view.threat.documented_events'), buildEvidenceEvents(evidenceEvents)));
    }
    const actions = recommendedActions(alert.recommended_actions);
    if (actions) detailHost.append(sectionBlock(t('view.threat.recommended_actions'), actions));
    const constraints = safetyConstraints(alert.safety_constraints);
    if (constraints) detailHost.append(constraints);

    detailHost.append(
      detailGrid([
        { label: t('view.threat.rule'), value: `${alert.rule_id || '—'} · v${alert.rule_version || '—'}`, mono: true },
        { label: t('view.threat.first_seen'), value: formatDateTime(alert.first_seen_at, timeZone) },
        { label: t('view.threat.last_seen'), value: formatDateTime(alert.last_seen_at, timeZone) },
        { label: t('view.threat.case_file'), value: alert.incident_id || '—', mono: true },
      ])
    );

    const links = el('div', { class: 'cluster' });
    if (alert.incident_id) links.append(el('a', { class: 'btn btn--secondary btn--sm', href: hrefFor('incidents', { id: alert.incident_id }), text: t('view.threat.open_case_file') }));
    if (alert.category === 'access') links.append(el('a', { class: 'btn btn--ghost btn--sm', href: hrefFor('access'), text: t('view.threat.access_view') }));
    if (links.childNodes.length > 0) detailHost.append(links);
  }

  function renderIncidentDetail(data) {
    clear(detailHost);
    const incident = data.incident || {};
    detailHost.append(
      el('div', { class: 'stack stack--tight' }, [
        el('div', { class: 'cluster' }, [severityChip(incident.severity), incidentStatusChip(incident.status)]),
        el('h3', { class: 'inspector__title', text: incident.title || t('view.incident.incident') }),
        el('p', { class: 'provenance', text: incident.summary || '' }),
      ])
    );
    const correlation = correlationBlocks(incident);
    if (correlation) detailHost.append(correlation);
    if (Array.isArray(data.alerts) && data.alerts.length > 0) {
      detailHost.append(
        sectionBlock(
          t('view.threat.linked_alerts'),
          el(
            'div',
            { class: 'cluster' },
            data.alerts.map((alert) =>
              severityChipRow(alert, () => {
                state.selected = { kind: 'alert', refId: alert.alert_id };
                renderTimeline();
                void loadDetail('alert', alert.alert_id);
              })
            )
          )
        )
      );
    }
    detailHost.append(
      el('div', { class: 'cluster' }, [
        el('a', { class: 'btn btn--secondary btn--sm', href: hrefFor('incidents', { id: incident.incident_id }), text: t('view.threat.open_case_file_in_workspace') }),
      ])
    );
  }

  function severityChipRow(alert, onClick) {
    const button = el('button', {
      type: 'button',
      class: 'btn btn--ghost btn--sm',
      attrs: { 'aria-label': t('view.threat.open_alert_p1', { p1: ruleTitle(alert.rule_id, alert.title) || '' }) },
      on: { click: onClick },
    });
    button.append(severityChip(alert.severity), el('span', { text: ruleTitle(alert.rule_id, alert.title) || alert.alert_id }));
    return button;
  }

  function buildEvidenceEvents(events) {
    const list = el('div', { class: 'mini-list' });
    for (const event of events) {
      const row = el('div', { class: 'mini-list__item' });
      const main = el('div', { class: 'mini-list__main' });
      main.append(
        el('div', { class: 'mini-list__title' }, [
          el('span', { text: String(event.kind || t('enum.timeline_kind.event')) }),
          el('span', { class: 'mono provenance', text: event.event_id || '' }),
        ]),
        el('div', { class: 'mini-list__meta' }, [
          el('span', { text: formatDateTime(event.observed_at, timeZone) }),
          el('span', { text: t('view.threat.source_p1', { p1: event.source || '—' }) }),
          event.quality ? el('span', { text: t('view.threat.quality_p1', { p1: event.quality }) }) : null,
        ].filter(Boolean))
      );
      row.append(main);
      list.append(row);
    }
    return list;
  }

  function renderRawEvent(item) {
    clear(detailHost);
    if (!item) {
      detailHost.append(el('p', { class: 'provenance', text: t('view.threat.no_details_available') }));
      return;
    }
    detailHost.append(
      el('div', { class: 'stack' }, [
        el('div', { class: 'cluster' }, [
          el('span', { class: 'chip chip--category', text: item.kind || t('enum.timeline_kind.event') }),
          item.severity ? severityChip(item.severity) : null,
          item.category ? categoryChip(item.category) : null,
        ].filter(Boolean)),
        el('h3', { class: 'inspector__title', text: item.title || t('enum.timeline_kind.event') }),
        detailGrid([
          { label: t('view.threat.timestamp'), value: formatDateTime(item.at, timeZone) },
          { label: t('view.threat.reference'), value: item.ref_id || '—', mono: true },
          { label: t('view.threat.category'), value: item.category ? categoryLabel(item.category) : '—' },
        ]),
        el('p', {
          class: 'provenance',
          text: t('view.threat.raw_events_have_no_dedicated_detail_endpoint_in'),
        }),
      ])
    );
  }
}

function sectionBlock(title, content) {
  const section = el('section', { class: 'stack stack--tight' });
  section.append(el('h3', { class: 'section-head__title', text: title }), content);
  return section;
}

function buildNoSite() {
  const view = el('div', { class: 'view' });
  view.append(
    el('h1', { class: 'view__title', text: t('view.threat.threats') }),
    emptyState({
      icon: 'radar',
      title: t('view.site.no_store_selected'),
      text: t('view.threat.select_a_store_above_to_see_the_correlated_event'),
      actions: [el('a', { class: 'btn btn--primary', href: hrefFor('overview'), text: t('notfound.action') })],
    })
  );
  return view;
}
