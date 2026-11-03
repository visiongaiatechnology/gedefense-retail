/**
 * Dense data table plus the generic record list used by timelines and case
 * lists. Both reflow into a deliberately composed mobile presentation instead
 * of shrinking the desktop table.
 */
import { el, fragment } from '../core/dom.js';
import { t } from '../i18n/index.js';
import { icon } from '../core/icons.js';

/**
 * @param {{
 *  columns: Array<{key: string, label: string, render: (row:any)=>Node|string, className?: string, numeric?: boolean}>,
 *  rows: object[],
 *  caption?: string,
 *  sort?: {key: string, direction: 'ascending'|'descending'},
 *  onSort?: (key:string)=>void,
 *  empty?: Node|null,
 * }} options
 */
export function dataTable({ columns, rows, caption = '', sort = null, onSort = null, empty = null }) {
  if (!rows || rows.length === 0) {
    return empty || el('p', { class: 'provenance', text: t('component.table.empty') });
  }

  const table = el('table', { class: 'data-table' });
  if (caption) table.append(el('caption', { text: caption }));

  const head = el('thead');
  const headRow = el('tr');
  for (const column of columns) {
    const th = el('th', { attrs: { scope: 'col' } });
    if (onSort) {
      const active = sort && sort.key === column.key;
      const ariaSort = active ? sort.direction : 'none';
      th.setAttribute('aria-sort', ariaSort);
      const button = el('button', {
        type: 'button',
        class: 'sort-btn',
        attrs: { 'aria-sort': ariaSort },
        on: { click: () => onSort(column.key) },
      });
      button.append(
        el('span', { text: column.label }),
        icon(active && sort.direction === 'descending' ? 'arrow-down' : 'arrow-up', { size: 'sm' })
      );
      th.append(button);
    } else {
      th.textContent = column.label;
    }
    headRow.append(th);
  }
  head.append(headRow);
  table.append(head);

  const body = el('tbody');
  for (const row of rows) {
    const tr = el('tr');
    for (const column of columns) {
      const td = el('td', {
        class: [column.className || '', column.numeric ? 'cell-num' : ''].filter(Boolean).join(' '),
      });
      // Mobile presentation labels every cell; desktop keeps the table header.
      td.dataset.label = column.label;
      const value = column.render(row);
      if (value instanceof Node) td.append(value);
      else td.textContent = value === null || value === undefined || value === '' ? '—' : String(value);
      tr.append(td);
    }
    body.append(tr);
  }
  table.append(body);

  return el('div', { class: 'table-wrap' }, table);
}

export function rowOpenButton(label, onClick, sub = '') {
  const wrapper = el('span');
  const button = el('button', { type: 'button', class: 'row-open', text: label, on: { click: onClick } });
  wrapper.append(button);
  if (sub) wrapper.append(el('span', { class: 'cell-sub', text: sub }));
  return wrapper;
}

/**
 * @param {{
 *  items: Array<{key: string, title: Node|string, meta?: Node[], side?: Node[], selected?: boolean, onSelect?: ()=>void}>,
 *  label?: string,
 * }} options
 */
export function recordList({ items, label = t('component.table.entries') }) {
  const list = el('ul', { class: 'record-list', attrs: { 'aria-label': label } });
  for (const item of items) {
    const li = el('li');
    const button = el('button', {
      type: 'button',
      class: 'record',
      attrs: { 'aria-current': item.selected ? 'true' : undefined },
      on: item.onSelect ? { click: item.onSelect } : undefined,
    });
    const main = el('span', { class: 'record__main' });
    const title = el('span', { class: 'record__title' });
    if (item.title instanceof Node) title.append(item.title);
    else title.append(el('span', { text: item.title }));
    main.append(title);
    if (item.meta && item.meta.length > 0) {
      const meta = el('span', { class: 'record__meta' });
      for (const entry of item.meta) {
        if (entry instanceof Node) meta.append(entry);
        else meta.append(el('span', { text: entry }));
      }
      main.append(meta);
    }
    button.append(main);
    if (item.side && item.side.length > 0) {
      const side = el('span', { class: 'record__side' });
      for (const entry of item.side) {
        if (entry instanceof Node) side.append(entry);
        else side.append(el('span', { text: entry }));
      }
      button.append(side);
    }
    li.append(button);
    list.append(li);
  }
  return list;
}

export function miniListItem({ title, meta = [], value = '', leading = null }) {
  const item = el('div', { class: 'mini-list__item' });
  if (leading) item.append(leading);
  const main = el('div', { class: 'mini-list__main' });
  const titleNode = el('div', { class: 'mini-list__title' });
  if (title instanceof Node) titleNode.append(title);
  else titleNode.append(el('span', { text: title }));
  main.append(titleNode);
  if (meta.length > 0) {
    const metaNode = el('div', { class: 'mini-list__meta' });
    for (const entry of meta) {
      if (entry instanceof Node) metaNode.append(entry);
      else metaNode.append(el('span', { text: entry }));
    }
    main.append(metaNode);
  }
  item.append(main);
  if (value) item.append(el('span', { class: 'mini-list__value', text: value }));
  return item;
}

export function miniList(children) {
  const list = el('div', { class: 'mini-list' });
  const frag = fragment();
  for (const child of children) {
    if (child) frag.append(child);
  }
  list.append(frag);
  return list;
}
