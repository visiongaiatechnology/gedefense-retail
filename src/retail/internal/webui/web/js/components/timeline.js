/**
 * Correlated threat timeline: chronological facts from events, alerts, access
 * sessions and incidents. Grouping by day keeps long windows readable.
 */
import { el, fragment } from '../core/dom.js';
import { dayKey, formatDayLabel, formatTime } from '../core/format.js';
import { categoryLabel, timelineKindLabel } from '../core/labels.js';
import { severityChip } from './chips.js';

/**
 * @param {{
 *  items: Array<{key:string, at:string, kind:string, severity?:string, title:string, category?:string, refId?:string}>,
 *  selectedKey?: string,
 *  onSelect?: (item:any)=>void,
 *  timeZone?: string,
 * }} options
 */
export function threatTimeline({ items, selectedKey = '', onSelect, timeZone = '' }) {
  const wrapper = el('div', { class: 'timeline' });
  const groups = new Map();

  for (const item of items) {
    const key = dayKey(item.at);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(item);
  }

  for (const [key, groupItems] of groups) {
    const section = el('section', { class: 'timeline__day' });
    section.append(
      el('h3', { class: 'timeline__day-label', text: formatDayLabel(groupItems[0].at, timeZone) })
    );
    const list = el('div', { class: 'timeline__list' });
    for (const item of groupItems) {
      const selected = item.key === selectedKey;
      const button = el('button', {
        type: 'button',
        class: 'timeline__item',
        dataset: { kind: item.kind, severity: item.severity || 'info' },
        attrs: {
          'aria-current': selected ? 'true' : undefined,
          'aria-label': `${timelineKindLabel(item.kind)}, ${formatTime(item.at, timeZone)}: ${item.title}`,
        },
        on: onSelect ? { click: () => onSelect(item) } : undefined,
      });
      button.append(
        el('span', { class: 'timeline__marker', attrs: { 'aria-hidden': 'true' } }),
        el('span', { class: 'timeline__time', text: formatTime(item.at, timeZone) })
      );
      const body = el('span', { class: 'timeline__body' });
      body.append(el('span', { class: 'timeline__title', text: item.title }));
      const meta = el('span', { class: 'timeline__meta' });
      const kindLabel = timelineKindLabel(item.kind);
      meta.append(el('span', { class: 'chip chip--category', text: kindLabel }));
      if (item.severity) meta.append(severityChip(item.severity));
      if (item.category && categoryText(item.category) !== kindLabel) {
        meta.append(el('span', { class: 'chip chip--category', text: categoryText(item.category) }));
      }
      body.append(meta);
      button.append(body);
      list.append(button);
    }
    section.append(list);
    wrapper.append(section);
  }

  if (items.length === 0) return null;

  const frag = fragment();
  frag.append(wrapper);
  return frag;
}

function categoryText(value) {
  return categoryLabel(value);
}

