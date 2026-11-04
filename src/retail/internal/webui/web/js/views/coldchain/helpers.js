/**
 * Cold-chain view — pure formatting/derivation helpers. Extracted from
 * coldchain.js; no API access and no view state.
 */
import { el } from '../../core/dom.js';
import { formatCelsius } from '../../core/format.js';
import { emptyState } from '../../components/states.js';
import { hrefFor } from '../../core/router.js';
import { t } from '../../i18n/index.js';

export function qualityKind(kind) {
  return { frozen: 'frozen', gap: 'missing', clock_skew: 'clock_uncertain', divergence: 'uncertain' }[kind] || 'uncertain';
}

export function instrumentItem(label, value, hint, severity = '') {
  const item = el('div', { class: 'instrument__item', dataset: severity ? { severity } : {} });
  item.append(
    el('span', { class: 'instrument__label', text: label }),
    el('span', { class: 'instrument__value' }, el('span', { text: value })),
    el('span', { class: 'instrument__hint', text: hint })
  );
  return item;
}

export function hasLimit(limit) {
  return Boolean(limit) && (Number.isFinite(Number(limit.min_c)) || Number.isFinite(Number(limit.max_c)));
}

export function limitText(limit) {
  if (!limit) return t('view.coldchain.no_limit');
  const parts = [];
  if (Number.isFinite(Number(limit.min_c))) parts.push(t('view.coldchain.min_p1', { p1: formatCelsius(limit.min_c) }));
  if (Number.isFinite(Number(limit.max_c))) parts.push(t('view.coldchain.max_p1', { p1: formatCelsius(limit.max_c) }));
  if (Number.isFinite(Number(limit.max_rate_c_per_min))) parts.push(t('view.coldchain.rate_p1_c_min', { p1: Number(limit.max_rate_c_per_min) }));
  return parts.length > 0 ? parts.join(' · ') : t('view.coldchain.no_limit');
}

export function uniqueLimits(limits) {
  const seen = new Map();
  for (const limit of limits) {
    if (!hasLimit(limit)) continue;
    const key = `${limit.min_c ?? ''}|${limit.max_c ?? ''}|${limit.max_rate_c_per_min ?? ''}`;
    if (!seen.has(key)) seen.set(key, limit);
  }
  return [...seen.values()];
}

export function lastPointOf(item) {
  const points = Array.isArray(item.series?.points) ? item.series.points : [];
  for (let index = points.length - 1; index >= 0; index -= 1) {
    if (Number.isFinite(Number(points[index].value))) return points[index];
  }
  return null;
}

export function buildNoSite() {
  const view = el('div', { class: 'view' });
  view.append(
    el('h1', { class: 'view__title', text: t('nav.coldchain') }),
    emptyState({
      icon: 'thermometer',
      title: t('view.site.no_store_selected'),
      text: t('view.coldchain.select_a_store_above_to_see_temperature_trends_a'),
      actions: [el('a', { class: 'btn btn--primary', href: hrefFor('overview'), text: t('notfound.action') })],
    })
  );
  return view;
}
