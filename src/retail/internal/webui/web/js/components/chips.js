/**
 * Status primitives. Every chip carries a text label; colour is never the only
 * carrier of meaning.
 */
import { el, fragment } from '../core/dom.js';
import { icon } from '../core/icons.js';
import { formatConfidence } from '../core/format.js';
import {
  alertStatusLabel,
  assetTypeLabel,
  categoryLabel,
  confidenceTone,
  criticalityLabel,
  gateRoleLabel,
  incidentStatusLabel,
  planStateLabel,
  protocolLabel,
  qualityLabel,
  severityLabel,
  siteStatusLabel,
  targetStateLabel,
  windowStatusLabel,
} from '../core/labels.js';
import { t } from '../i18n/index.js';

export function severityChip(severity) {
  return el('span', {
    class: 'chip chip--sev',
    dataset: { severity },
    text: severityLabel(severity),
  });
}

export function criticalityChip(criticality) {
  const mapped = { low: 'info', medium: 'medium', high: 'high', critical: 'critical' }[criticality] || 'info';
  return el('span', {
    class: 'chip chip--sev',
    dataset: { severity: mapped },
    text: criticalityLabel(criticality),
    attrs: { title: t('component.chips.criticality_title') },
  });
}

export function alertStatusChip(status) {
  return el('span', {
    class: 'chip chip--status',
    dataset: { status },
    text: alertStatusLabel(status),
  });
}

export function incidentStatusChip(status) {
  return el('span', {
    class: 'chip chip--status',
    dataset: { status },
    text: incidentStatusLabel(status),
  });
}

export function windowStatusChip(status) {
  return el('span', {
    class: 'chip chip--status',
    dataset: { status: status === 'active' ? 'acknowledged' : status === 'planned' ? 'open' : 'closed' },
    text: windowStatusLabel(status),
  });
}

export function qualityChip(quality, { label = '' } = {}) {
  return el('span', {
    class: 'chip chip--quality',
    dataset: { quality },
    text: label || qualityLabel(quality),
    attrs: { title: t('component.chips.quality_title') },
  });
}

export function categoryChip(category) {
  return el('span', { class: 'chip chip--category', text: categoryLabel(category) });
}

export function assetTypeChip(type) {
  return el('span', { class: 'chip chip--category', text: assetTypeLabel(type) });
}


export function protocolChips(protocols) {
  if (!Array.isArray(protocols) || protocols.length === 0) {
    return el('span', { class: 'provenance', text: t('component.chips.protocol_unknown') });
  }
  const frag = fragment();
  for (const value of protocols) {
    frag.append(el('span', { class: 'chip chip--protocol', text: protocolLabel(value) }));
  }
  return el('div', { class: 'cluster' }, frag);
}

export function siteStatusChip(status) {
  const chip = el('span', {
    class: 'chip chip--status',
    dataset: { status: status === 'online' ? 'resolved' : status === 'degraded' ? 'investigating' : status === 'offline' ? 'open' : 'closed' },
    attrs: { title: t('component.chips.site_status_title') },
  });
  chip.append(
    el('span', { class: 'dot', dataset: { siteStatus: status }, attrs: { 'aria-hidden': 'true' } }),
    el('span', { text: siteStatusLabel(status) })
  );
  return chip;
}



/**
 * Confidence as a real progress element plus numeric value. Confidence is
 * provenance of a classification, not a probability of an attack.
 */
export function confidenceMeter(confidence, { label = t('component.chips.confidence') } = {}) {
  const value = Number(confidence);
  const tone = confidenceTone(value);
  const wrapper = el('span', { class: 'confidence', dataset: { tone } });
  wrapper.append(
    el('progress', {
      class: 'meter',
      attrs: {
        max: '1',
        value: Number.isFinite(value) ? String(Math.max(0, Math.min(1, value))) : '0',
        'aria-label': t('component.chips.confidence_aria', { label }),
        title: label,
      },
    }),
    el('span', { class: 'confidence__value', text: formatConfidence(value) })
  );
  return wrapper;
}


/** Collector state → familiar reachability words (never colour-only). */
export function collectorStateChip(state) {
  const map = {
    running: { label: t('component.chips.collector_running'), status: 'resolved' },
    degraded: { label: t('component.chips.collector_degraded'), status: 'investigating' },
    stopped: { label: t('component.chips.collector_stopped'), status: 'closed' },
    failed: { label: t('component.chips.collector_failed'), status: 'open' },
  };
  const entry = map[state] || { label: state || t('enum.fallback.unknown'), status: 'closed' };
  return el('span', { class: 'chip chip--status', dataset: { status: entry.status }, text: entry.label });
}

export function inWindowChip(inWindow) {
  return el('span', {
    class: 'chip chip--sev',
    dataset: { severity: inWindow ? 'low' : 'critical' },
    text: inWindow ? t('component.chips.in_window') : t('component.chips.outside_window'),
  });
}


export function readOnlyBadge() {
  const badge = el('span', {
    class: 'badge badge--accent',
    attrs: { title: t('component.chips.readonly_title') },
  });
  badge.append(icon('shield', { size: 'sm' }), el('span', { text: t('component.chips.readonly_label') }));
  return badge;
}

/* ------------------------------------------------------------- Access Gate */

export function planStateChip(state) {
  const map = {
    pending: 'open',
    approved: 'resolved',
    rejected: 'closed',
    expired: 'closed',
    executed: 'resolved',
    cancelled: 'closed',
  };
  return el('span', {
    class: 'chip chip--status',
    dataset: { status: map[state] || 'closed' },
    text: planStateLabel(state),
  });
}

export function targetStateChip(state) {
  const map = {
    listening: 'resolved',
    connected: 'resolved',
    degraded: 'investigating',
    failed: 'open',
    stopped: 'closed',
    unknown: 'closed',
  };
  return el('span', {
    class: 'chip chip--status',
    dataset: { status: map[state] || 'closed' },
    text: targetStateLabel(state),
  });
}

export function gateRoleChip(role) {
  return el('span', { class: 'chip chip--category', text: gateRoleLabel(role) });
}

export function bypassChip() {
  return el('span', {
    class: 'chip chip--sev',
    dataset: { severity: 'critical' },
    text: t('component.chips.bypass_label'),
    attrs: { title: t('component.chips.bypass_title') },
  });
}


