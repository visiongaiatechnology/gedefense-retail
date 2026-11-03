/**
 * Asset detail inspector. Shared by the asset inventory and the site view so the
 * provenance rules (confidence, source, classification) are rendered once.
 */
import { api } from '../core/api.js';
import { el, clear } from '../core/dom.js';
import { formatDateTime, formatRelative } from '../core/format.js';
import { qualityLabel } from '../core/labels.js';
import { navigate } from '../core/router.js';
import { openInspector } from './inspector.js';
import { errorState, skeletonPage } from './states.js';
import {
  alertStatusChip,
  assetTypeChip,
  confidenceMeter,
  criticalityChip,
  qualityChip,
  severityChip,
} from './chips.js';
import { detailGrid } from './panel.js';
import { icon } from '../core/icons.js';
import { t, ruleTitle } from '../i18n/index.js';

export async function openAssetInspector(assetId, { onClose = null } = {}) {
  const inspector = openInspector({
    eyebrow: t('component.asset_inspector.eyebrow'),
    title: t('component.asset_inspector.loading_title'),
    content: skeletonPage(t('component.asset_inspector.loading')),
    onClose,
  });

  try {
    const data = await api.getAsset(assetId);
    const asset = data.asset || {};
    inspector.setTitle(asset.name || assetId);
    clear(inspector.body);
    inspector.body.append(...buildContent(data));
  } catch (error) {
    clear(inspector.body);
    inspector.body.append(
      errorState({
        title: t('component.asset_inspector.unavailable'),
        error,
        actions: [
          el('button', {
            type: 'button',
            class: 'btn btn--secondary',
            text: t('component.inspector.close_aria'),
            on: { click: () => inspector.close() },
          }),
        ],
      })
    );
  }
  return inspector;
}

function buildContent(data) {
  const asset = data.asset || {};
  const blocks = [];

  const badges = el('div', { class: 'cluster' });
  badges.append(
    assetTypeChip(asset.asset_type),
    criticalityChip(asset.criticality),
    el('span', {
      class: 'chip chip--category',
      text: asset.classification_source === 'manual' ? t('component.asset_inspector.manual_classified') : t('component.asset_inspector.passive_classified'),
    })
  );
  if (asset.retired) badges.append(el('span', { class: 'badge badge--muted', text: t('component.asset_inspector.retired') }));
  badges.append(confidenceMeter(asset.confidence, { label: t('component.asset_inspector.confidence_label') }));
  blocks.push(badges);

  blocks.push(
    detailGrid([
      { label: t('component.asset_inspector.field_id'), value: asset.asset_id, mono: true },
      { label: t('component.asset_inspector.field_site'), value: asset.site_id, mono: true },
      { label: t('component.asset_inspector.field_zone'), value: asset.zone_id || '—', mono: true },
      { label: t('component.asset_inspector.field_vendor'), value: asset.vendor || t('component.asset_inspector.not_proven') },
      { label: t('component.asset_inspector.field_model'), value: asset.model || t('component.asset_inspector.not_proven') },
      { label: t('component.asset_inspector.field_firmware'), value: asset.firmware_version || t('component.asset_inspector.not_proven') },
      {
        label: t('component.asset_inspector.field_firmware_source'),
        value: asset.firmware_source
          ? `${asset.firmware_source}${
              Number.isFinite(Number(asset.firmware_confidence))
                ? ` · ${Math.round(Number(asset.firmware_confidence) * 100)} %`
                : ''
            }`
          : t('component.asset_inspector.no_source'),
        mono: true,
      },
      { label: t('component.asset_inspector.field_collection'), value: asset.source || '—', mono: true },
      { label: t('component.asset_inspector.field_first_seen'), value: formatDateTime(asset.first_seen_at) },
      { label: t('component.asset_inspector.field_last_seen'), value: formatDateTime(asset.last_seen_at) },
    ])
  );

  if (asset.operator_notes) {
    blocks.push(sectionBlock(t('component.asset_inspector.section_notes'), el('p', { class: 'provenance', text: asset.operator_notes })));
  }

  blocks.push(sectionBlock(t('component.asset_inspector.section_network'), buildNetworkIds(asset.network_identifiers)));
  blocks.push(sectionBlock(t('component.asset_inspector.section_sensors'), buildSensors(data.sensors)));
  blocks.push(sectionBlock(t('component.asset_inspector.section_alerts'), buildAlerts(data.alerts)));
  blocks.push(sectionBlock(t('component.asset_inspector.section_events'), buildEvents(data.recent_events)));
  blocks.push(
    el('p', {
      class: 'provenance',
      text: t('component.asset_inspector.confidence_note'),
    })
  );
  return blocks;
}

function sectionBlock(title, content) {
  const section = el('section', { class: 'stack stack--tight' });
  section.append(el('h3', { class: 'section-head__title', text: title }), content);
  return section;
}

function buildNetworkIds(identifiers) {
  if (!Array.isArray(identifiers) || identifiers.length === 0) {
    return el('p', { class: 'provenance', text: t('component.asset_inspector.network_empty') });
  }
  const list = el('div', { class: 'mini-list' });
  for (const item of identifiers) {
    const row = el('div', { class: 'mini-list__item' });
    const main = el('div', { class: 'mini-list__main' });
    main.append(
      el('div', { class: 'mini-list__title' }, [
        el('span', { class: 'mono', text: item.value }),
        el('span', { class: 'chip chip--category', text: String(item.kind || '—') }),
      ]),
      el('div', { class: 'mini-list__meta' }, [
        el('span', { text: t('component.asset_inspector.source_ref', { value: item.source || '—' }) }),
        item.first_seen ? el('span', { text: t('component.asset_inspector.first_seen_ref', { time: formatDateTime(item.first_seen) }) }) : null,
        item.last_seen ? el('span', { text: t('component.asset_inspector.last_seen_ref', { relative: formatRelative(item.last_seen) }) }) : null,
      ].filter(Boolean))
    );
    row.append(main);
    if (Number.isFinite(Number(item.confidence))) {
      row.append(confidenceMeter(item.confidence, { label: t('component.asset_inspector.identifier_confidence') }));
    }
    list.append(row);
  }
  return list;
}

function buildSensors(sensors) {
  if (!Array.isArray(sensors) || sensors.length === 0) {
    return el('p', { class: 'provenance', text: t('component.asset_inspector.sensors_empty') });
  }
  const list = el('div', { class: 'mini-list' });
  for (const sensor of sensors) {
    const row = el('div', { class: 'mini-list__item' });
    const main = el('div', { class: 'mini-list__main' });
    main.append(
      el('div', { class: 'mini-list__title' }, [
        el('span', { text: sensor.name || sensor.sensor_id }),
        sensor.independent ? el('span', { class: 'badge badge--muted', text: t('component.asset_inspector.sensor_independent') }) : null,
        sensor.critical ? el('span', { class: 'chip chip--sev', dataset: { severity: 'high' }, text: t('component.asset_inspector.sensor_critical') }) : null,
      ].filter(Boolean)),
      el('div', { class: 'mini-list__meta' }, [
        el('span', { class: 'mono', text: sensor.sensor_id }),
        el('span', { text: `${sensor.metric || '—'} · ${sensor.unit || '—'}` }),
        sensor.last_seen_at ? el('span', { text: formatRelative(sensor.last_seen_at) }) : null,
      ].filter(Boolean))
    );
    row.append(main);
    list.append(row);
  }
  return list;
}

function buildAlerts(alerts) {
  if (!Array.isArray(alerts) || alerts.length === 0) {
    return el('p', { class: 'provenance', text: t('component.asset_inspector.alerts_empty') });
  }
  const list = el('div', { class: 'mini-list' });
  for (const alert of alerts) {
    const row = el('div', { class: 'mini-list__item' });
    const main = el('div', { class: 'mini-list__main' });
    main.append(
      el('div', { class: 'mini-list__title' }, [severityChip(alert.severity), el('span', { text: ruleTitle(alert.rule_id, alert.title) || t('component.asset_inspector.alert_fallback') })]),
      el('div', { class: 'mini-list__meta' }, [
        alertStatusChip(alert.status),
        el('span', { text: formatRelative(alert.last_seen_at) }),
      ])
    );
    const link = el('button', {
      type: 'button',
      class: 'btn btn--ghost btn--sm',
      attrs: { 'aria-label': t('component.asset_inspector.open_alert_aria') },
      on: { click: () => navigate('threat', { alert: alert.alert_id }) },
    });
    link.append(icon('chevron-right', { size: 'sm' }));
    row.append(main, link);
    list.append(row);
  }
  return list;
}

function buildEvents(events) {
  if (!Array.isArray(events) || events.length === 0) {
    return el('p', { class: 'provenance', text: t('component.asset_inspector.events_empty') });
  }
  const list = el('div', { class: 'mini-list' });
  for (const event of events) {
    const row = el('div', { class: 'mini-list__item' });
    const main = el('div', { class: 'mini-list__main' });
    const title = el('div', { class: 'mini-list__title' }, [el('span', { text: String(event.kind || t('component.asset_inspector.event_fallback')) })]);
    if (event.quality) title.append(qualityChip(event.quality));
    main.append(
      title,
      el('div', { class: 'mini-list__meta' }, [
        el('span', { text: formatDateTime(event.observed_at) }),
        el('span', { class: 'mono', text: event.source || '' }),
        event.event_id ? el('span', { class: 'mono', text: event.event_id }) : null,
        event.measurement ? el('span', { text: `${event.measurement.value} ${event.measurement.unit}` }) : null,
      ].filter(Boolean))
    );
    row.append(main);
    if (event.quality) {
      row.append(el('span', { class: 'chip chip--quality', dataset: { quality: event.quality }, text: qualityLabel(event.quality) }));
    }
    list.append(row);
  }
  return list;
}
