/**
 * SVG temperature chart — no chart library, no canvas, no external assets.
 *
 * The chart answers one question per view: "where does temperature leave the
 * operator-approved band?". The band comes from the policy limit; when no limit
 * is configured the chart draws no band and the view says so explicitly.
 */
import { el, svg, uid } from '../core/dom.js';
import { formatCelsius, formatDateTime, formatTime, formatValue } from '../core/format.js';
import { qualityLabel, unitLabel } from '../core/labels.js';
import { t } from '../i18n/index.js';

const VIEW_W = 840;
const VIEW_H = 320;
const PAD = { top: 26, right: 18, bottom: 38, left: 56 };

function niceStep(range, tickCount) {
  const raw = range / Math.max(1, tickCount);
  if (!Number.isFinite(raw) || raw <= 0) return 1;
  const magnitude = 10 ** Math.floor(Math.log10(raw));
  const normalized = raw / magnitude;
  let step;
  if (normalized <= 1) step = 1;
  else if (normalized <= 2) step = 2;
  else if (normalized <= 2.5) step = 2.5;
  else if (normalized <= 5) step = 5;
  else step = 10;
  return step * magnitude;
}

function buildTicks(min, max, tickCount = 5) {
  const step = niceStep(max - min, tickCount);
  const start = Math.floor(min / step) * step;
  const end = Math.ceil(max / step) * step;
  const ticks = [];
  for (let value = start; value <= end + step / 1000; value += step) {
    ticks.push(Number(value.toFixed(8)));
  }
  return ticks.length > 2 ? ticks : [min, max];
}

function qualityGroup(quality) {
  if (quality === 'missing') return 'missing';
  if (quality === 'good' || quality === 'mixed' || !quality) return 'ok';
  return 'suspect';
}

/** Stable series colour slot: follows the sensor, not the selection order. */
function seriesColorIndex(item, fallbackIndex) {
  const explicit = Number(item.colorIndex);
  const index = Number.isFinite(explicit) && explicit > 0 ? explicit : fallbackIndex + 1;
  return String(((index - 1) % 6) + 1);
}

function seriesSegments(points) {  const segments = [];
  let current = null;
  for (const point of points) {
    const at = new Date(point.at).getTime();
    if (!Number.isFinite(at) || !Number.isFinite(Number(point.value))) continue;
    const group = qualityGroup(point.quality);
    if (group === 'missing') {
      current = null;
      continue;
    }
    if (!current || current.group !== group) {
      current = { group, points: [] };
      segments.push(current);
    }
    current.points.push({ at, value: Number(point.value) });
  }
  return segments;
}

function pathData(points, toX, toY) {
  let d = '';
  for (const point of points) {
    d += `${d ? ' L' : 'M'}${toX(point.at).toFixed(1)} ${toY(point.value).toFixed(1)}`;
  }
  return d;
}

function xLabelFormatter(spanMs, timeZone) {  if (spanMs <= 26 * 3600 * 1000) return (at) => formatTime(at, timeZone);
  if (spanMs <= 3 * 24 * 3600 * 1000) {
    return (at) => {
      const date = new Date(at);
      return `${String(date.getDate()).padStart(2, '0')}.${String(date.getMonth() + 1).padStart(2, '0')}. ${formatTime(at, timeZone)}`;
    };
  }
  return (at) => {
    const date = new Date(at);
    return `${String(date.getDate()).padStart(2, '0')}.${String(date.getMonth() + 1).padStart(2, '0')}.`;
  };
}

/**
 * @param {{
 *  series: Array<{id:string,label:string,points:Array<{at:string,value:number,quality?:string}>,unit?:string}>,
 *  limit?: {min_c?:number,max_c?:number}|null,
 *  violations?: Array<{at:string,value:number,sensor_id?:string,kind?:string}>,
 *  since: string, until: string, timeZone?: string,
 * }} options
 * @returns {HTMLElement}
 */
export function temperatureChart({ series = [], limit = null, violations = [], since, until, timeZone = '' }) {
  const width = VIEW_W;
  const height = VIEW_H;
  const plotW = width - PAD.left - PAD.right;
  const plotH = height - PAD.top - PAD.bottom;

  const from = new Date(since).getTime();
  const to = new Date(until).getTime();
  const validRange = Number.isFinite(from) && Number.isFinite(to) && to > from;
  const start = validRange ? from : Date.now() - 6 * 3600 * 1000;
  const end = validRange ? to : Date.now();
  const span = end - start;

  const values = [];
  for (const item of series) {
    for (const point of item.points || []) {
      if (Number.isFinite(Number(point.value))) values.push(Number(point.value));
    }
  }
  if (limit) {
    if (Number.isFinite(Number(limit.min_c))) values.push(Number(limit.min_c));
    if (Number.isFinite(Number(limit.max_c))) values.push(Number(limit.max_c));
  }
  if (values.length === 0) values.push(0, 10);

  let low = Math.min(...values);
  let high = Math.max(...values);
  if (low === high) {
    low -= 1;
    high += 1;
  }
  const padding = Math.max((high - low) * 0.12, 0.4);
  const ticks = buildTicks(low - padding, high + padding, 5);
  const minValue = ticks[0];
  const maxValue = ticks[ticks.length - 1];

  const toX = (at) => PAD.left + ((at - start) / span) * plotW;
  const toY = (value) => PAD.top + (1 - (value - minValue) / (maxValue - minValue)) * plotH;

  const titleId = uid('chart-title');
  const descId = uid('chart-desc');
  const clipId = uid('chart-clip');
  const root = svg('svg', {
    class: 'chart',
    viewBox: `0 0 ${width} ${height}`,
    role: 'img',
    'aria-labelledby': `${titleId} ${descId}`,
    preserveAspectRatio: 'xMidYMid meet',
  });
  const defs = svg('defs');
  const clipPath = svg('clipPath', { id: clipId });
  clipPath.append(svg('rect', { x: PAD.left, y: PAD.top, width: plotW, height: plotH }));
  defs.append(clipPath);
  root.append(defs);
  const titleNode = svg('title', { id: titleId });
  titleNode.textContent = t('component.chart.title');
  const descParts = [
    t('component.chart.desc_range', { from: formatDateTime(since, timeZone), to: formatDateTime(until, timeZone) }),
    series.length === 1 ? t('component.chart.desc_series_one') : t('component.chart.desc_series_many', { count: series.length }),
  ];
  if (limit && (Number.isFinite(Number(limit.min_c)) || Number.isFinite(Number(limit.max_c)))) {
    descParts.push(
      t('component.chart.desc_limits', {
        min: Number.isFinite(Number(limit.min_c)) ? t('component.chart.minimum_value', { value: formatCelsius(limit.min_c) }) : t('component.chart.no_minimum'),
        max: Number.isFinite(Number(limit.max_c)) ? t('component.chart.maximum_value', { value: formatCelsius(limit.max_c) }) : t('component.chart.no_maximum'),
      })
    );
  } else {
    descParts.push(t('component.chart.desc_no_limits'));
  }
  if (violations.length > 0) descParts.push(t('component.chart.desc_violations', { count: violations.length }));
  const descNode = svg('desc', { id: descId });
  descNode.textContent = descParts.join(' ');
  root.append(titleNode, descNode);

  // Limit band first so the data always reads on top of it.
  if (limit && Number.isFinite(Number(limit.min_c)) && Number.isFinite(Number(limit.max_c))) {
    const yMax = toY(Number(limit.max_c));
    const yMin = toY(Number(limit.min_c));
    root.append(
      svg('rect', {
        class: 'limit-band',
        x: PAD.left,
        y: Math.min(yMax, yMin),
        width: plotW,
        height: Math.max(1, Math.abs(yMin - yMax)),
      })
    );
  }

  // Horizontal grid + Y labels.
  for (const tick of ticks) {
    const y = toY(tick);
    root.append(svg('line', { class: 'grid-line', x1: PAD.left, y1: y, x2: PAD.left + plotW, y2: y }));
    const label = svg('text', { x: PAD.left - 8, y: y + 3.5, 'text-anchor': 'end' });
    label.textContent = formatValue(tick, '°C', Math.abs(tick) < 10 ? 1 : 0);
    root.append(label);
  }

  // Axes.
  root.append(
    svg('line', {
      class: 'axis-line',
      x1: PAD.left,
      y1: PAD.top + plotH,
      x2: PAD.left + plotW,
      y2: PAD.top + plotH,
    })
  );
  root.append(
    svg('line', { class: 'axis-line', x1: PAD.left, y1: PAD.top, x2: PAD.left, y2: PAD.top + plotH })
  );

  // X labels.
  const formatX = xLabelFormatter(span, timeZone);
  const tickCount = 5;
  for (let index = 0; index < tickCount; index += 1) {
    const at = start + ((end - start) * index) / (tickCount - 1);
    const x = toX(at);
    const label = svg('text', { x, y: PAD.top + plotH + 18, 'text-anchor': 'middle' });
    label.textContent = formatX(at);
    root.append(label);
  }

  // Policy rails.
  if (limit) {
    const rails = [
      { value: limit.max_c, text: `max ${formatCelsius(limit.max_c)}` },
      { value: limit.min_c, text: `min ${formatCelsius(limit.min_c)}` },
    ];
    for (const rail of rails) {
      if (!Number.isFinite(Number(rail.value))) continue;
      const y = toY(Number(rail.value));
      root.append(
        svg('line', {
          class: 'limit-rail',
          x1: PAD.left,
          y1: y,
          x2: PAD.left + plotW,
          y2: y,
        })
      );
      const text = svg('text', {
        class: 'limit-label',
        x: PAD.left + plotW - 4,
        y: y - 4,
        'text-anchor': 'end',
      });
      text.textContent = rail.text;
      root.append(text);
    }
  }

  // Series.
  for (const [seriesIndex, item] of series.entries()) {
    const group = svg('g', {
      dataset: { series: String(seriesColorIndex(item, seriesIndex)) },
      'clip-path': `url(#${clipId})`,
    });
    const segments = seriesSegments(item.points || []);
    for (const segment of segments) {
      if (segment.points.length === 1) {
        group.append(
          svg('circle', {
            class: 'chart-point',
            cx: toX(segment.points[0].at),
            cy: toY(segment.points[0].value),
            r: 2.4,
          })
        );
        continue;
      }
      group.append(
        svg('path', {
          class: segment.group === 'ok' ? 'chart-line' : 'chart-line chart-line--suspect',
          d: pathData(segment.points, toX, toY),
        })
      );
    }
    // Current value marker on the right edge of the last known point.
    const last = (item.points || []).filter((point) => Number.isFinite(Number(point.value))).at(-1);
    if (last) {
      const at = new Date(last.at).getTime();
      if (Number.isFinite(at)) {
        group.append(
          svg('circle', {
            class: 'chart-point',
            cx: toX(at),
            cy: toY(Number(last.value)),
            r: 3,
          })
        );
      }
    }
    const groupTitle = svg('title');
    groupTitle.textContent = item.label || item.id || 'Messreihe';
    group.append(groupTitle);
    root.append(group);
  }

  // Limit violations as factual vertical markers.
  for (const violation of violations) {
    const at = new Date(violation.at).getTime();
    if (!Number.isFinite(at) || at < start || at > end) continue;
    const x = toX(at);
    const marker = svg('line', {
      class: 'chart-violation',
      x1: x,
      y1: PAD.top,
      x2: x,
      y2: PAD.top + plotH,
    });
    const markerTitle = svg('title');
    markerTitle.textContent = t('component.chart.violation_marker', { time: formatDateTime(violation.at, timeZone), value: formatCelsius(violation.value) });
    marker.append(markerTitle);
    root.append(marker);
  }

  const figure = el('figure', { class: 'chart-figure' });
  const figCaption = [
    t('component.chart.caption_range', { from: formatDateTime(since, timeZone), to: formatDateTime(until, timeZone) }),
    series.length === 1 ? t('component.chart.caption_series_one') : t('component.chart.caption_series_many', { count: series.length }),
    limit && (Number.isFinite(Number(limit.min_c)) || Number.isFinite(Number(limit.max_c)))
      ? t('component.chart.caption_band')
      : t('component.chart.caption_no_limits'),
  ].join(' · ');
  figure.append(root, el('figcaption', { text: figCaption }));
  return figure;
}

/**
 * Text/table alternative for the chart (accessibility + audit copy).
 * Points are downsampled for display; the API series is already server-bounded.
 */
export function seriestable(series, timeZone = '') {
  const details = el('details', { class: 'chart-details' });
  details.append(el('summary', { text: t('component.chart.table_toggle') }));
  const body = el('div', { class: 'chart-details__body' });
  const table = el('table', { class: 'data-table' });
  const head = el('thead');
  const headRow = el('tr');
  for (const label of [t('component.chart.col_sensor'), t('component.chart.col_time'), t('component.chart.col_value'), t('component.chart.col_quality')]) {
    headRow.append(el('th', { attrs: { scope: 'col' }, text: label }));
  }
  head.append(headRow);
  table.append(head);
  const tbody = el('tbody');
  for (const item of series) {
    const points = (item.points || []).filter((point) => Number.isFinite(Number(point.value)));
    const step = Math.max(1, Math.ceil(points.length / 150));
    const unit = item.unit || 'celsius';
    for (let index = 0; index < points.length; index += step) {
      const point = points[index];
      const row = el('tr');
      row.append(
        el('td', { attrs: { 'data-label': t('component.chart.col_sensor') }, text: item.label || item.id }),
        el('td', { attrs: { 'data-label': t('component.chart.col_time') }, text: formatDateTime(point.at, timeZone) }),
        el('td', { attrs: { 'data-label': t('component.chart.col_value') }, text: formatValue(point.value, unitLabel(unit), 1) }),
        el('td', { attrs: { 'data-label': t('component.chart.col_quality') }, text: qualityLabel(point.quality) })
      );
      tbody.append(row);
    }
  }
  table.append(tbody);
  body.append(table);
  details.append(body);
  return details;
}
