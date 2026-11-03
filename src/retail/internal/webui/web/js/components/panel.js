/**
 * Composition primitives shared by all views: page header, content plane,
 * section head, detail fields and a precise timestamp node. Keeping these in
 * one place is what prevents a homogeneous card wall.
 */
import { el, uid } from '../core/dom.js';

export function pageHeader({ eyebrow = [], title, subtitle = '', actions = [] }) {
  const header = el('header', { class: 'view__header' });
  const heading = el('div', { class: 'view__heading' });
  if (eyebrow.length > 0) heading.append(el('div', { class: 'view__eyebrow' }, eyebrow));
  heading.append(el('h1', { class: 'view__title', text: title }));
  if (subtitle) heading.append(el('p', { class: 'view__subtitle', text: subtitle }));
  header.append(heading);
  if (actions.length > 0) header.append(el('div', { class: 'view__actions' }, actions));
  return header;
}

/**
 * A content plane with a functional boundary. Glass is opt-in and reserved for
 * functional floating layers; data-heavy content uses the opaque plane.
 */
export function panel({
  title = '',
  sub = '',
  actions = [],
  body = null,
  flush = false,
  foot = null,
  className = '',
  glass = false,
  focus = false,
  titleLevel = 2,
  describedBy = '',
} = {}) {
  const titleId = title ? uid('panel-title') : '';
  const classes = ['plane'];
  if (glass) classes.push('glass');
  if (focus) classes.push('plane--focus');
  if (className) classes.push(className);
  const section = el('section', {
    class: classes,
    attrs: {
      'aria-labelledby': titleId || undefined,
      'aria-describedby': describedBy || undefined,
    },
  });

  if (title || actions.length > 0 || sub) {
    const head = el('header', { class: 'panel__head' });
    if (title) {
      const wrap = el('div');
      wrap.append(el(`h${Math.min(4, Math.max(2, titleLevel))}`, { class: 'panel__title', id: titleId }, title));
      if (sub) wrap.append(el('p', { class: 'panel__sub', text: sub }));
      head.append(wrap);
    }
    if (actions.length > 0) head.append(el('div', { class: 'cluster' }, actions));
    section.append(head);
  }

  const bodyNode = el('div', { class: flush ? 'panel__body panel__body--flush' : 'panel__body' });
  if (body) bodyNode.append(body);
  section.append(bodyNode);

  if (foot) section.append(el('div', { class: 'panel__foot' }, foot));
  return section;
}


export function detailField(label, value, { mono = false } = {}) {
  const field = el('div', { class: 'detail-field' });
  field.append(
    el('span', { class: 'detail-field__label', text: label }),
    el('span', {
      class: mono ? 'detail-field__value detail-field__value--mono' : 'detail-field__value',
      text: value === null || value === undefined || value === '' ? '—' : String(value),
    })
  );
  return field;
}

export function detailGrid(fields) {
  const grid = el('div', { class: 'detail-grid' });
  for (const field of fields) {
    if (!field) continue;
    if (field instanceof Node) grid.append(field);
    else grid.append(detailField(field.label, field.value, { mono: field.mono }));
  }
  return grid;
}

/** Local display time with the precise UTC value available as tooltip. */
export function timeNode(iso, timeZone) {
  const time = el('time', {
    text: formatDateTime(iso, timeZone),
    attrs: { datetime: iso || undefined, title: formatUTC(iso) },
  });
  return time;
}





