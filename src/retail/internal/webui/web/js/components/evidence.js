/**
 * The three-layer evidence contract (safety invariant): observed facts,
 * derived hypothesis and recommended checks are rendered in separate, clearly
 * labelled blocks. They are never mixed into one alarm paragraph.
 */
import { el } from '../core/dom.js';
import { icon } from '../core/icons.js';
import { formatDateTime, formatUTC } from '../core/format.js';
import { alertStatusLabel, categoryLabel, severityLabel } from '../core/labels.js';
import { t } from '../i18n/index.js';
import { severityChip } from './chips.js';
import { detailField, detailGrid } from './panel.js';

function labelledBlock({ variant, label, iconName, children }) {
  const block = el('section', { class: `evidence-block evidence-block--${variant}` });
  const headline = el('h4', { class: 'evidence-block__label' });
  headline.append(icon(iconName, { size: 'sm' }), el('span', { text: label }));
  block.append(headline);
  block.append(children);
  return block;
}

function stringList(values, className = 'evidence-block__list') {
  const list = el('ul', { class: className });
  for (const value of values || []) {
    if (!value) continue;
    list.append(el('li', { text: String(value) }));
  }
  return list;
}

/**
 * @param {{correlation?: object|null}} alertLike
 */
export function correlationBlocks(alertLike) {
  const correlation = alertLike?.correlation;
  if (!correlation) return null;
  const grid = el('div', { class: 'evidence-grid' });

  grid.append(
    labelledBlock({
      variant: 'facts',
      label: t('component.evidence.facts_label'),
      iconName: 'check',
      children: stringList(correlation.observed_facts),
    })
  );

  const hypothesisChildren = el('div', { class: 'stack stack--tight' });
  hypothesisChildren.append(
    el('p', { class: 'evidence-block__text', text: correlation.hypothesis || t('component.evidence.hypothesis_missing') })
  );
  if (Array.isArray(correlation.alternative_explanations) && correlation.alternative_explanations.length > 0) {
    const alt = el('p', { class: 'alt-note' });
    alt.append(el('strong', { text: t('component.evidence.alternatives_label') }));
    alt.append(el('span', { text: correlation.alternative_explanations.join(' · ') }));
    hypothesisChildren.append(alt);
  }
  grid.append(
    labelledBlock({
      variant: 'hypothesis',
      label: t('component.evidence.hypothesis_label'),
      iconName: 'info',
      children: hypothesisChildren,
    })
  );

  const checksChildren = el('div', { class: 'stack stack--tight' });
  checksChildren.append(stringList(correlation.recommended_checks));
  grid.append(
    labelledBlock({
      variant: 'checks',
      label: t('component.evidence.checks_label'),
      iconName: 'key',
      children: checksChildren,
    })
  );

  const section = el('div', { class: 'stack' });
  section.append(grid);
  if (Array.isArray(correlation.indicators) && correlation.indicators.length > 0) {
    const indicators = el('div', { class: 'stack stack--tight' });
    indicators.append(el('span', { class: 'provenance', text: t('component.evidence.indicators_label') }));
    const cluster = el('div', { class: 'indicator-list' });
    for (const indicator of correlation.indicators) {
      cluster.append(el('span', { class: 'indicator', text: indicator }));
    }
    indicators.append(cluster);
    section.append(indicators);
  }
  return section;
}

/** Evidence items behind an alert, with provenance and confidence. */
export function evidenceItems(evidence) {
  if (!Array.isArray(evidence) || evidence.length === 0) {
    return el('p', { class: 'provenance', text: t('component.evidence.empty') });
  }
  const list = el('div', { class: 'mini-list' });
  for (const item of evidence) {
    const row = el('div', { class: 'mini-list__item' });
    const main = el('div', { class: 'mini-list__main' });
    const title = el('div', { class: 'mini-list__title' });
    title.append(el('span', { text: item.description || item.kind || t('component.evidence.item_fallback') }));
    main.append(title);
    const meta = el('div', { class: 'mini-list__meta' });
    if (item.kind) meta.append(el('span', { class: 'chip chip--category', text: item.kind }));
    if (item.at) meta.append(el('span', { text: formatDateTime(item.at) }));
    if (item.source) meta.append(el('span', { class: 'mono', text: item.source }));
    if (item.value) meta.append(el('span', { text: String(item.value) }));
    if (item.ref_id) meta.append(el('span', { class: 'mono', text: item.ref_id }));
    main.append(meta);
    row.append(main);
    if (Number.isFinite(Number(item.confidence))) {
      row.append(el('span', { class: 'confidence__value', text: `${Math.round(Number(item.confidence) * 100)} %` }));
    }
    list.append(row);
  }
  return list;
}

/** Recommended actions with the explicit approval/safety contract. */
export function recommendedActions(actions) {
  if (!Array.isArray(actions) || actions.length === 0) return null;
  const wrapper = el('div', { class: 'stack stack--tight' });
  for (const action of actions) {
    const item = el('div', { class: 'stack stack--tight' });
    const title = el('p', { class: 'evidence-block__text', text: action.action });
    item.append(title);
    const meta = el('div', { class: 'cluster' });
    if (action.requires_approval) {
      meta.append(el('span', { class: 'badge badge--accent', text: t('component.evidence.approval_required') }));
    }
    item.append(meta);
    if (action.safety_note) item.append(el('p', { class: 'safety-note', text: action.safety_note }));
    wrapper.append(item);
  }
  return wrapper;
}

export function safetyConstraints(constraints) {
  if (!Array.isArray(constraints) || constraints.length === 0) return null;
  const wrapper = el('div', { class: 'stack stack--tight' });
  wrapper.append(el('span', { class: 'provenance', text: t('component.evidence.safety_label') }));
  const cluster = el('div', { class: 'cluster' });
  for (const value of constraints) cluster.append(el('span', { class: 'chip chip--category', text: value }));
  wrapper.append(cluster);
  return wrapper;
}

/** Compact header facts used by inspector and case detail. */
export function alertFacts(alert, timeZone = '') {
  const grid = detailGrid([
    { label: t('component.evidence.field_category'), value: categoryLabel(alert.category) },
    { label: t('component.evidence.field_rule'), value: `${alert.rule_id || '—'} (v${alert.rule_version || '—'})`, mono: true },
    { label: t('component.evidence.field_first_seen'), value: formatDateTime(alert.first_seen_at, timeZone) },
    { label: t('component.evidence.field_last_seen'), value: formatDateTime(alert.last_seen_at, timeZone) },
    { label: t('component.evidence.field_dedup'), value: alert.dedup_key || '—', mono: true },
    { label: t('component.evidence.field_confidence'), value: Number.isFinite(Number(alert.confidence)) ? `${Math.round(Number(alert.confidence) * 100)} %` : '—' },
  ]);
  return grid;
}

export function alertBadgeRow(alert) {
  const row = el('div', { class: 'cluster' });
  row.append(severityChip(alert.severity), el('span', { class: 'chip chip--category', text: severityLabel(alert.severity) }));
  if (alert.status) row.append(el('span', { class: 'chip chip--status', dataset: { status: alert.status }, text: alertStatusLabel(alert.status) }));
  return row;
}

export { detailField, formatUTC };
