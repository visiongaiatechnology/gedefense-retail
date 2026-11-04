/**
 * Access view — window cards, session rows, criteria and small helpers. Pure
 * rendering; data loading and orchestration stay in index.js.
 */
import { el } from '../../core/dom.js';
import { formatDateTime } from '../../core/format.js';
import { inWindowChip, windowStatusChip } from '../../components/chips.js';
import { emptyState } from '../../components/states.js';
import { hrefFor } from '../../core/router.js';
import { t } from '../../i18n/index.js';

/* --------------------------------------------------------------- cards */

export function buildWindowCard(windowEntry, timeZone) {
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

export function buildSessionRow(session, windowVendors, timeZone) {
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

export function buildCriteria() {
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

export function instrumentItem(label, value, hint, severity = '') {
  const item = el('div', { class: 'instrument__item', dataset: severity ? { severity } : {} });
  item.append(
    el('span', { class: 'instrument__label', text: label }),
    el('span', { class: 'instrument__value' }, el('span', { text: value })),
    el('span', { class: 'instrument__hint', text: hint })
  );
  return item;
}

export function sortByTime(items, key) {
  return [...items].sort((a, b) => new Date(a[key] || 0).getTime() - new Date(b[key] || 0).getTime());
}

export function buildNoSite() {
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
