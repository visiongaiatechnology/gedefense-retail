/**
 * Cold-chain view: temperature series against the operator policy band, limit
 * violations and data-quality findings. Without a configured policy limit the
 * view says so explicitly — GeDefense never invents temperature thresholds.
 */
import { api } from '../../core/api.js';
import { el, clear, render } from '../../core/dom.js';
import { getSite, getSiteId, getSiteTimezone, toast } from '../../core/store.js';
import {
  formatCelsius,
  formatCount,
  formatDateTime,
  formatRelative,
  sinceIso,
  nowIso,
} from '../../core/format.js';
import { dataQualityKindLabel, limitKindLabel } from '../../core/labels.js';
import { hrefFor } from '../../core/router.js';
import { TIME_WINDOWS, DEFAULT_TIME_WINDOW } from '../../core/config.js';
import { pageHeader, panel } from '../../components/panel.js';
import { segmented } from '../../components/filters.js';
import { emptyState, errorState, skeletonChart } from '../../components/states.js';
import { temperatureChart, seriestable } from '../../components/chart.js';
import { qualityChip, readOnlyBadge } from '../../components/chips.js';
import { icon } from '../../core/icons.js';

import { t } from '../../i18n/index.js';
import { buildNoSite, hasLimit, instrumentItem, lastPointOf, limitText, qualityKind, uniqueLimits } from './helpers.js';
export async function mount({ root }) {
  const siteId = getSiteId();
  if (!siteId) {
    render(root, buildNoSite());
    return;
  }

  const timeZone = getSiteTimezone();
  const state = {
    windowId: DEFAULT_TIME_WINDOW,
    zoneId: '',
    selected: new Set(),
  };
  let lastItems = null;
  let lastViolations = [];
  let lastRange = { since: '', until: '' };

  const instrumentHost = el('div');
  const chartHost = el('div');
  const legendHost = el('div', { class: 'chart-legend' });
  const violationsHost = el('div');
  const dqHost = el('div');
  const sensorHost = el('div');
  const limitNoteHost = el('div');
  const zoneSelect = el('select', { class: 'select', attrs: { 'aria-label': t('view.coldchain.filter_zone') } });
  zoneSelect.addEventListener('change', () => {
    state.zoneId = zoneSelect.value;
    void loadData();
  });
  zoneSelect.append(el('option', { text: t('view.site.all_zones'), attrs: { value: '' } }));

  const windowControl = segmented({
    label: t('view.coldchain.time_window'),
    options: TIME_WINDOWS.map((windowOption) => ({ value: windowOption.id, label: windowOption.label })),
    value: state.windowId,
    onChange: (value) => {
      state.windowId = value;
      void loadData();
    },
  });

  const header = pageHeader({
    eyebrow: [t('nav.coldchain'), readOnlyBadge()],
    title: t('nav.coldchain'),
    subtitle:
      t('view.coldchain.temperature_trends_limit_violations_and_data_qua'),
    actions: [windowControl, el('a', { class: 'btn btn--ghost', href: hrefFor('site'), text: t('view.overview.open_store') })],
  });

  const chartPanel = panel({
    title: 'Temperaturverlauf',
    sub: t('view.coldchain.measurements_in_c_limit_band_from_policy_2'),
    actions: [el('span', { class: 'badge badge--muted', text: 'SVG · lokal gerendert' })],
    body: el('div', { class: 'coldchain__stage' }, [limitNoteHost, legendHost, chartHost]),
  });
  const violationsPanel = panel({
    title: t('view.coldchain.limit_violations'),
    sub: t('view.coldchain.documented_exceedances_in_the_time_window'),
    body: violationsHost,
    flush: true,
  });
  const dqPanel = panel({
    title: t('enum.category.data_quality'),
    sub: t('view.coldchain.frozen_gap_clock_offset_divergence'),
    body: dqHost,
    flush: true,
  });

  const sensorPanel = panel({
    title: t('view.site.sensors'),
    sub: t('view.coldchain.selection_controls_the_comparison_in_the_chart'),
    actions: [zoneSelect],
    body: sensorHost,
    flush: true,
  });

  const main = el('div', { class: 'view__main' });
  main.append(instrumentHost, chartPanel, el('div', { class: 'cc-grid' }, [violationsPanel, dqPanel]));
  const rail = el('aside', { class: 'view__rail view__rail--sticky', attrs: { 'aria-label': t('view.coldchain.sensor_selection') } });
  rail.append(
    sensorPanel,
    panel({
      title: t('view.coldchain.reading'),
      body: el('div', { class: 'stack stack--tight' }, [
        el('p', {
          class: 'provenance',
          text: t('view.coldchain.a_value_outside_the_operator_limits_is_a_technic'),
        }),
        el('p', {
          class: 'provenance',
          text: t('view.coldchain.data_quality_is_separated_from_process_safety_fr'),
        }),
      ]),
    })
  );

  const layout = el('div', { class: 'view view--coldchain' });
  const grid = el('div', { class: 'view__grid' });
  grid.append(main, rail);
  layout.append(header, grid);
  render(root, layout);

  await loadData();

  /** Reflect a programmatic period change in the segmented control. */
  function setPeriodControl(id) {
    const target = TIME_WINDOWS.find((entry) => entry.id === id);
    if (!target) return false;
    let matched = false;
    for (const button of windowControl.querySelectorAll('button')) {
      const isTarget = button.textContent.trim() === String(target.label).trim();
      button.setAttribute('aria-pressed', String(isTarget));
      matched = matched || isTarget;
    }
    state.windowId = id;
    return matched;
  }

  /** Widen the period and select the first three available series, or explain why not. */
  async function pickFirstThree() {
    if (!lastItems || lastItems.length === 0) {
      const current = TIME_WINDOWS.findIndex((entry) => entry.id === state.windowId);
      const wider = TIME_WINDOWS[Math.min(current + 1, TIME_WINDOWS.length - 1)];
      if (wider && wider.id !== state.windowId) {
        setPeriodControl(wider.id);
        await loadData();
      }
      if (!lastItems || lastItems.length === 0) {
        toast({
          variant: 'info',
          title: t('view.coldchain.widened_empty_title'),
          text: t('view.coldchain.widened_empty_text'),
        });
        return;
      }
    }
    state.selected = new Set(lastItems.slice(0, 3).map((item) => item.sensor?.sensor_id).filter(Boolean));
    renderSensors(lastItems, timeZone);
    renderChart(lastItems, lastViolations, lastRange.since, lastRange.until);
  }

  function currentWindow() {
    const selected = TIME_WINDOWS.find((windowOption) => windowOption.id === state.windowId) || TIME_WINDOWS[2];
    return selected;
  }

  function zoneName(zoneId) {
    const site = getSite();
    const zone = (site?.zones || []).find((entry) => entry.zone_id === zoneId);
    return zone?.name || zoneId;
  }

  async function loadData() {
    const windowOption = currentWindow();
    const since = sinceIso(windowOption.hours);
    const until = nowIso();
    clear(chartHost);
    chartHost.append(skeletonChart());
    clear(violationsHost);
    clear(dqHost);
    clear(sensorHost);
    sensorHost.append(el('div', { class: 'panel__body' }, el('div', { class: 'skeleton skeleton--row' })));

    try {
      const data = await api.getColdchain({
        site_id: siteId,
        zone_id: state.zoneId || undefined,
        since,
        until,
      });
      // Prefer the server-reported window so chart domain and point data agree.
      const windowInfo = data && data.window ? data.window : {};
      renderData(data, {
        since: windowInfo.since || since,
        until: windowInfo.until || until,
        timeZone,
      });
    } catch (error) {
      clear(chartHost);
      chartHost.append(
        errorState({
          title: t('view.coldchain.cold_chain_could_not_be_loaded'),
          error,
          actions: [el('button', { type: 'button', class: 'btn btn--primary', text: t('view.assets.reload'), on: { click: () => void loadData() } })],
        })
      );
      clear(violationsHost);
      clear(dqHost);
      clear(sensorHost);
      clear(legendHost);
      clear(instrumentHost);
      clear(limitNoteHost);
    }
  }

  function renderData(data, { since, until }) {
    const items = Array.isArray(data.items) ? data.items : [];
    const violations = Array.isArray(data.limit_violations) ? data.limit_violations : [];
    const qualityIssues = Array.isArray(data.data_quality) ? data.data_quality : [];

    updateZoneOptions(items);
    updateInstrument(items, violations, qualityIssues);

    const availableIds = items.map((item) => item.sensor?.sensor_id).filter(Boolean);
    const kept = [...state.selected].filter((id) => availableIds.includes(id));
    if (kept.length > 0) {
      state.selected = new Set(kept);
    } else {
      state.selected = new Set(availableIds.slice(0, 3));
    }

    renderSensors(items, timeZone);
    renderChart(items, violations, since, until);
    renderViolations(violations, items, timeZone);
    renderQuality(qualityIssues, items, timeZone);
  }

  function updateZoneOptions(items) {
    const current = zoneSelect.value;
    clear(zoneSelect);
    zoneSelect.append(el('option', { text: t('view.site.all_zones'), attrs: { value: '' } }));
    const zones = new Map();
    for (const item of items) {
      const sensor = item.sensor || {};
      if (sensor.zone_id && !zones.has(sensor.zone_id)) zones.set(sensor.zone_id, sensor.zone_id);
    }
    for (const [zoneId] of zones) {
      zoneSelect.append(el('option', { text: zoneId, attrs: { value: zoneId } }));
    }
    zoneSelect.value = current && [...zones.keys()].includes(current) ? current : state.zoneId;
  }

  function updateInstrument(items, violations, qualityIssues) {
    const points = items.reduce((sum, item) => sum + (Array.isArray(item.series?.points) ? item.series.points.length : 0), 0);
    const withLimits = items.filter((item) => hasLimit(item.limit)).length;
    clear(instrumentHost);
    const instrument = el('section', { class: 'instrument', attrs: { 'aria-label': t('view.coldchain.cold_chain_metrics') } });
    instrument.append(
      instrumentItem(t('view.site.sensors'), formatCount(items.length), t('view.coldchain.p1_data_points_in_the_window', { p1: formatCount(points) })),
      instrumentItem(t('view.coldchain.limit_violations'), formatCount(violations.length), violations.length > 0 ? t('view.coldchain.documented_policy_exceedances') : t('view.coldchain.none_reported'), violations.length > 0 ? 'warning' : ''),
      instrumentItem(t('enum.category.data_quality'), formatCount(qualityIssues.length), qualityIssues.length > 0 ? t('view.coldchain.reliability_notices') : t('view.coldchain.no_anomalies'), qualityIssues.length > 0 ? 'warning' : ''),
      instrumentItem(
        t('view.coldchain.limits'),
        `${formatCount(withLimits)}/${formatCount(items.length)}`,
        withLimits === 0 ? t('view.coldchain.no_policy_limits_no_thermal_alerting') : t('view.coldchain.from_operator_policy'),
        withLimits === 0 && items.length > 0 ? 'critical' : ''
      )
    );
    instrumentHost.append(instrument);
  }

  function renderSensors(items, timeZone) {
    clear(sensorHost);
    if (items.length === 0) {
      sensorHost.append(el('div', { class: 'panel__body' }, el('p', { class: 'provenance', text: t('view.coldchain.no_sensors_in_the_time_window') })));
      return;
    }
    const list = el('div', { class: 'coldchain__rail-list', attrs: { role: 'group', 'aria-label': t('view.coldchain.select_sensors') } });
    items.forEach((item, index) => {
      const sensor = item.sensor || {};
      const sensorId = sensor.sensor_id || `sensor-${index}`;
      const pressed = state.selected.has(sensorId);
      const button = el('button', {
        type: 'button',
        class: 'sensor-toggle',
        dataset: { series: String((index % 6) + 1) },
        attrs: { 'aria-pressed': pressed ? 'true' : 'false', 'aria-label': t('view.coldchain.chart_sensor_toggle', { p1: sensor.name || sensorId, p2: pressed ? t('view.coldchain.chart_hide') : t('view.coldchain.chart_show') }) },
        on: { click: () => toggleSensor(sensorId) },
      });
      const check = el('span', { class: 'sensor-toggle__check', attrs: { 'aria-hidden': 'true' } }, icon('check', { size: 'sm' }));
      const main = el('span', { class: 'sensor-toggle__main' });
      const title = el('span', { class: 'sensor-toggle__name' });
      title.append(el('span', { text: sensor.name || sensorId }));
      if (sensor.independent) title.append(el('span', { class: 'badge badge--muted', text: t('view.coldchain.independent') }));
      main.append(title);
      const meta = el('span', { class: 'sensor-toggle__meta' });
      meta.append(
        sensor.zone_id ? el('span', { text: zoneName(sensor.zone_id) }) : null,
        el('span', { text: limitText(item.limit) }),
        item.last_seen_at ? el('span', { text: formatRelative(item.last_seen_at), attrs: { title: formatDateTime(item.last_seen_at, timeZone) } }) : null
      );
      if (!meta.childNodes.length) meta.append(el('span', { text: t('view.coldchain.without_additional_information') }));
      const lastPoint = lastPointOf(item);
      if (lastPoint) meta.append(qualityChip(lastPoint.quality));
      main.append(meta);
      button.append(check, main, el('span', { class: 'sensor-toggle__value', text: lastPoint ? formatCelsius(lastPoint.value) : '—' }));
      list.append(button);
    });
    sensorHost.append(list);
  }

  function toggleSensor(sensorId) {
    if (state.selected.has(sensorId)) state.selected.delete(sensorId);
    else state.selected.add(sensorId);
    const items = lastItems;
    if (!items) return;
    renderSensors(items, timeZone);
    renderChart(items, lastViolations, lastRange.since, lastRange.until);
  }

  function renderChart(items, violations, since, until) {    lastItems = items;
    lastViolations = violations;
    lastRange = { since, until };
    clear(chartHost);
    clear(legendHost);
    clear(limitNoteHost);

    const selected = items.filter((item) => item.sensor && state.selected.has(item.sensor.sensor_id));
    if (selected.length === 0) {
      chartHost.append(
        emptyState({
          icon: 'thermometer',
          title: t('view.coldchain.no_series_selected'),
          text: t('view.coldchain.select_at_least_one_sensor_in_the_sensor_list_wi'),
          actions: [
            el('button', {
              type: 'button',
              class: 'btn btn--secondary',
              text: t('view.coldchain.select_first_three_sensors'),
              on: {
                click: () => {
                  void pickFirstThree();
                },
              },
            }),
          ],
        })
      );
      return;
    }

    const limits = selected.map((item) => item.limit || null);
    const unique = uniqueLimits(limits);
    const sharedLimit = unique.length === 1 ? unique[0] : null;
    const anyLimit = selected.some((item) => hasLimit(item.limit));

    if (!anyLimit) {
      limitNoteHost.append(
        el('div', { class: 'banner banner--accent', attrs: { role: 'status' } }, [
          icon('info', { size: 'sm' }),
          el('div', { class: 'banner__body' }, [
            el('span', { class: 'banner__title', text: t('view.coldchain.no_limits_configured') }),
            el('span', {
              class: 'banner__text',
              text: t('view.coldchain.no_operator_policy_with_min_c_max_c_is_stored_fo'),
            }),
          ]),
        ])
      );
    } else if (unique.length > 1) {
      limitNoteHost.append(
        el('div', { class: 'banner banner--warn', attrs: { role: 'status' } }, [
          icon('warning', { size: 'sm' }),
          el('div', { class: 'banner__body' }, [
            el('span', { class: 'banner__title', text: t('view.coldchain.different_limits_per_zone') }),
            el('span', { class: 'banner__text', text: t('view.coldchain.the_selected_sensors_have_different_policy_limit') }),
          ]),
        ])
      );
    }

    const series = selected.map((item, index) => ({
      id: item.sensor?.sensor_id || `series-${index}`,
      label: item.sensor?.name || item.sensor?.sensor_id || t('view.coldchain.sensor'),
      points: Array.isArray(item.series?.points) ? item.series.points : [],
      unit: item.series?.unit || 'celsius',
      // Stable colour slot per sensor: toggling the selection must not recolour.
      colorIndex: items.indexOf(item) + 1,
    }));

    chartHost.append(temperatureChart({ series, limit: sharedLimit, violations, since, until, timeZone }));
    chartHost.append(seriestable(series, timeZone));

    selected.forEach((item) => {
      const colorSlot = ((items.indexOf(item) % 6) + 1);
      const legend = el('span', { class: 'legend-item', dataset: { series: String(colorSlot) } });
      legend.append(
        el('span', { class: 'legend-swatch' }),
        el('span', { text: item.sensor?.name || item.sensor?.sensor_id || t('view.coldchain.sensor') })
      );
      legendHost.append(legend);
    });

    // Quality encoding is never colour-only: dashed line plus this explanation.
    const qualityLegend = el('span', { class: 'legend-item' });
    qualityLegend.append(
      el('span', { class: 'legend-swatch legend-swatch--dashed' }),
      el('span', { text: t('view.coldchain.dashed_data_quality_not_good') })
    );
    legendHost.append(qualityLegend);
  }

  function renderViolations(violations, items, timeZone) {
    clear(violationsHost);
    if (violations.length === 0) {
      violationsHost.append(el('div', { class: 'panel__body' }, el('p', { class: 'provenance', text: t('view.coldchain.no_limit_violations_reported_in_the_time_window') })));
      return;
    }
    const names = new Map(items.map((item) => [item.sensor?.sensor_id, item.sensor?.name || item.sensor?.sensor_id]));
    const list = el('div');
    for (const violation of violations) {
      const row = el('div', { class: 'violation-row' });
      const main = el('div', { class: 'violation-row__main' });
      main.append(
        el('div', { class: 'mini-list__title' }, [
          el('span', { class: 'chip chip--sev', dataset: { severity: violation.kind === 'above_max' ? 'high' : 'medium' }, text: limitKindLabel(violation.kind) }),
          el('span', { text: names.get(violation.sensor_id) || violation.sensor_id || t('view.coldchain.sensor') }),
        ]),
        el('div', { class: 'mini-list__meta' }, [
          el('span', { text: formatDateTime(violation.at, timeZone) }),
          el('span', { text: violation.sensor_id || '' }),
        ])
      );
      row.append(main, el('span', { class: 'violation-row__value', text: formatCelsius(violation.value) }));
      list.append(row);
    }
    violationsHost.append(list);
  }

  function renderQuality(issues, items, timeZone) {
    clear(dqHost);
    if (issues.length === 0) {
      dqHost.append(el('div', { class: 'panel__body' }, el('p', { class: 'provenance', text: t('view.coldchain.no_data_quality_notices_in_the_time_window') })));
      return;
    }
    const names = new Map(items.map((item) => [item.sensor?.sensor_id, item.sensor?.name || item.sensor?.sensor_id]));
    const list = el('div');
    for (const issue of issues) {
      const row = el('div', { class: 'dq-row' });
      const main = el('div', { class: 'dq-row__main' });
      main.append(
        el('div', { class: 'mini-list__title' }, [
          el('span', { class: 'chip chip--quality', dataset: { quality: qualityKind(issue.kind) }, text: dataQualityKindLabel(issue.kind) }),
          el('span', { text: names.get(issue.sensor_id) || issue.sensor_id || t('view.coldchain.sensor') }),
        ]),
        el('div', { class: 'mini-list__meta' }, [
          issue.since ? el('span', { text: t('view.coldchain.since_p1', { p1: formatDateTime(issue.since, timeZone) }) }) : null,
          issue.detail ? el('span', { text: String(issue.detail) }) : null,
        ].filter(Boolean))
      );
      row.append(main);
      list.append(row);
    }
    dqHost.append(list);
  }
}
