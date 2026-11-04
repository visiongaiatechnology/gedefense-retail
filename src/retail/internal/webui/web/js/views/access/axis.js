/**
 * Access view — SVG maintenance timeline. Extracted from access.js so the view
 * container stays within the file-size budget. Pure rendering, no API access.
 */
import { el, svg } from '../../core/dom.js';
import { formatClock, formatDateTime } from '../../core/format.js';
import { windowStatusLabel } from '../../core/labels.js';
import { t } from '../../i18n/index.js';

/* ----------------------------------------------------------------- axis */

export function buildAxis({ windows, sessions, anomalies, since, until, timeZone }) {
  const width = 860;
  const height = 200;
  const pad = { left: 96, right: 20, top: 22, bottom: 30 };
  const plotW = width - pad.left - pad.right;
  const start = new Date(since).getTime();
  const end = new Date(until).getTime();
  const span = Math.max(1, end - start);

  const root = svg('svg', {
    class: 'access-axis__svg',
    viewBox: `0 0 ${width} ${height}`,
    role: 'img',
    'aria-label': t('view.access.timeline_of_maintenance_windows_sessions_and_ano'),
  });
  const title = svg('title');
  title.textContent = t('view.access.maintenance_access_timeline');
  const desc = svg('desc');
  desc.textContent = `${windows.length} Wartungsfenster, ${sessions.length} Sitzungen, ${anomalies.length} Anomalien zwischen ${formatDateTime(
    since,
    timeZone
  )} und ${formatDateTime(until, timeZone)}.`;
  root.append(title, desc);

  const toX = (iso) => pad.left + ((new Date(iso).getTime() - start) / span) * plotW;
  const clampX = (value) => Math.min(pad.left + plotW, Math.max(pad.left, value));
  const lanes = [
    { key: 'windows', label: t('view.access.windows'), y: pad.top, height: 14 },
    { key: 'sessions', label: t('view.access.sessions'), y: pad.top + 44, height: 12 },
    { key: 'anomalies', label: t('view.access.anomalies'), y: pad.top + 88, height: 14 },
  ];

  for (const lane of lanes) {
    root.append(
      svg('text', { x: pad.left - 10, y: lane.y + 11, 'text-anchor': 'end', class: 'row-label' }, lane.label)
    );
    root.append(
      svg('line', {
        x1: pad.left,
        y1: lane.y + lane.height + 8,
        x2: pad.left + plotW,
        y2: lane.y + lane.height + 8,
        class: 'grid-line',
        stroke: 'var(--line)',
      })
    );
  }

  // Time grid + labels.
  const ticks = 6;
  for (let index = 0; index < ticks; index += 1) {
    const at = start + (span * index) / (ticks - 1);
    const x = pad.left + (plotW * index) / (ticks - 1);
    root.append(svg('line', { x1: x, y1: pad.top - 8, x2: x, y2: height - pad.bottom + 4, class: 'grid-line' }));
    root.append(svg('text', { x, y: height - pad.bottom + 18, 'text-anchor': 'middle' }, formatClock(at, timeZone)));
  }

  // Windows lane.
  for (const windowEntry of windows) {
    const x1 = toX(windowEntry.starts_at);
    const x2 = toX(windowEntry.ends_at);
    const left = clampX(Math.min(x1, x2));
    const right = clampX(Math.max(x1, x2));
    const bar = svg('rect', {
      x: left,
      y: lanes[0].y,
      width: Math.max(4, right - left),
      height: lanes[0].height,
      class: windowEntry.status === 'closed' || windowEntry.status === 'cancelled' ? 'window-bar window-bar--closed' : 'window-bar',
    });
    const barTitle = svg('title');
    barTitle.textContent = `${windowEntry.vendor || t('view.access.maintenance')} · ${windowStatusLabel(windowEntry.status)} · ${formatDateTime(
      windowEntry.starts_at,
      timeZone
    )} – ${formatDateTime(windowEntry.ends_at, timeZone)}`;
    bar.append(barTitle);
    root.append(bar);
  }

  // Session lane.
  for (const session of sessions) {
    const x = clampX(toX(session.started_at));
    const startedAt = new Date(session.started_at).getTime();
    const endedAt = session.ended_at ? new Date(session.ended_at).getTime() : startedAt + 20 * 60 * 1000;
    const width = Math.max(4, clampX(toX(new Date(endedAt).toISOString())) - x);
    const bar = svg('rect', {
      x,
      y: lanes[1].y,
      width,
      height: lanes[1].height,
      class: session.in_window === false ? 'session-bar session-bar--anomaly' : 'session-bar',
    });
    const sessionTitle = svg('title');
    sessionTitle.textContent = `${session.vendor || session.user || t('view.access.session')} · ${session.in_window === false ? t('view.access.outside_window_2') : t('view.access.within_window')} · ${formatClock(
      session.started_at,
      timeZone
    )}`;
    bar.append(sessionTitle);
    root.append(bar);
  }

  // Anomaly lane (diamonds).
  for (const anomaly of anomalies) {
    const x = clampX(toX(anomaly.first_seen_at || anomaly.last_seen_at));
    const y = lanes[2].y + 7;
    const diamond = svg('path', {
      d: `M${x} ${y - 6} L${x + 6} ${y} L${x} ${y + 6} L${x - 6} ${y} Z`,
      class: 'session-bar session-bar--anomaly',
    });
    const anomalyTitle = svg('title');
    anomalyTitle.textContent = `${anomaly.title || 'Anomalie'} · ${formatDateTime(anomaly.first_seen_at, timeZone)}`;
    diamond.append(anomalyTitle);
    root.append(diamond);
  }

  // "Now" marker.
  const nowX = clampX(toX(until));
  root.append(svg('line', { x1: nowX, y1: pad.top - 6, x2: nowX, y2: height - pad.bottom + 4, class: 'now-line' }));

  const figure = el('figure', { class: 'chart-figure' });
  figure.append(
    root,
    el('figcaption', {
      text: t('view.access.p1_p2_windows_sessions_and_anomalies_details_in', { p1: formatDateTime(since, timeZone), p2: formatDateTime(until, timeZone) }),
    })
  );
  return figure;
}
