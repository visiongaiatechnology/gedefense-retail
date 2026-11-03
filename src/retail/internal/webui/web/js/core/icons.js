/**
 * Local icon set. One consistent stroke system, drawn as inline SVG elements at
 * runtime (no icon CDN, no font). Icons are decorative by default; pass a label
 * when the icon alone carries meaning.
 */
const S = 'http://www.w3.org/2000/svg';

/** @typedef {Array<[string, object]>} IconDef */
/** @type {Record<string, IconDef>} */
const ICONS = {
  dashboard: [
    ['rect', { x: 3, y: 3, width: 7, height: 8, rx: 1.6 }],
    ['rect', { x: 14, y: 3, width: 7, height: 5, rx: 1.6 }],
    ['rect', { x: 14, y: 12, width: 7, height: 9, rx: 1.6 }],
    ['rect', { x: 3, y: 15, width: 7, height: 6, rx: 1.6 }],
  ],
  store: [
    ['path', { d: 'M3.5 9.5 5 4h14l1.5 5.5' }],
    ['path', { d: 'M4.5 9.5V20h15V9.5' }],
    ['path', { d: 'M9.5 20v-6h5v6' }],
  ],
  layers: [
    ['path', { d: 'm12 3 9 5-9 5-9-5 9-5Z' }],
    ['path', { d: 'm3 13 9 5 9-5' }],
    ['path', { d: 'm3 17 9 5 9-5' }],
  ],
  thermometer: [
    ['path', { d: 'M10 13.6V5a2 2 0 1 1 4 0v8.6a4.5 4.5 0 1 1-4 0Z' }],
    ['path', { d: 'M12 9v5' }],
  ],
  key: [
    ['circle', { cx: 8, cy: 15, r: 4 }],
    ['path', { d: 'm11 12 8-8' }],
    ['path', { d: 'm15 8 2.5 2.5' }],
    ['path', { d: 'm17.5 5.5 2 2' }],
  ],
  gate: [
    ['path', { d: 'M4 20h16' }],
    ['path', { d: 'M7 20V5h10v15' }],
    ['path', { d: 'M10 12h4' }],
    ['path', { d: 'm12 10 2 2-2 2' }],
  ],
  radar: [
    ['circle', { cx: 12, cy: 12, r: 9 }],
    ['circle', { cx: 12, cy: 12, r: 5 }],
    ['path', { d: 'M12 12V3' }],
    ['circle', { cx: 12, cy: 12, r: 1.2, fill: 'currentColor', stroke: 'none' }],
  ],
  shield: [
    ['path', { d: 'M12 3l7 3v6c0 4.4-2.9 7.6-7 9-4.1-1.4-7-4.6-7-9V6l7-3Z' }],
    ['path', { d: 'm9 12 2 2 4-4' }],
  ],
  case: [
    ['rect', { x: 3, y: 7, width: 18, height: 13, rx: 2 }],
    ['path', { d: 'M8.5 7V5.5A1.5 1.5 0 0 1 10 4h4a1.5 1.5 0 0 1 1.5 1.5V7' }],
    ['path', { d: 'M3 12h18' }],
    ['path', { d: 'M10 12v2h4v-2' }],
  ],
  search: [
    ['circle', { cx: 11, cy: 11, r: 7 }],
    ['path', { d: 'm20 20-4.2-4.2' }],
  ],
  refresh: [
    ['path', { d: 'M20 12a8 8 0 1 1-2.4-5.7' }],
    ['path', { d: 'M20 4v5h-5' }],
  ],
  close: [
    ['path', { d: 'm6 6 12 12' }],
    ['path', { d: 'm18 6-12 12' }],
  ],
  'chevron-down': [['path', { d: 'm6 9 6 6 6-6' }]],
  'chevron-right': [['path', { d: 'm9 6 6 6-6 6' }]],
  'chevron-left': [['path', { d: 'm15 6-6 6 6 6' }]],
  download: [
    ['path', { d: 'M12 3v12' }],
    ['path', { d: 'm7 10 5 5 5-5' }],
    ['path', { d: 'M4 21h16' }],
  ],
  logout: [
    ['path', { d: 'M9 5H5a1 1 0 0 0-1 1v12a1 1 0 0 0 1 1h4' }],
    ['path', { d: 'm16 8 4 4-4 4' }],
    ['path', { d: 'M20 12H9' }],
  ],
  help: [
    ['circle', { cx: 12, cy: 12, r: 9 }],
    ['path', { d: 'M9.6 9.2A2.5 2.5 0 1 1 12.4 12c-.7.3-1 .9-1 1.7' }],
    ['path', { d: 'M12 17h.01' }],
  ],
  info: [
    ['circle', { cx: 12, cy: 12, r: 9 }],
    ['path', { d: 'M12 11v6' }],
    ['path', { d: 'M12 7h.01' }],
  ],
  warning: [
    ['path', { d: 'M12 3.5 21 20H3L12 3.5Z' }],
    ['path', { d: 'M12 9v5' }],
    ['path', { d: 'M12 17h.01' }],
  ],
  alert: [
    ['circle', { cx: 12, cy: 12, r: 9 }],
    ['path', { d: 'M12 7.5v5' }],
    ['path', { d: 'M12 16.5h.01' }],
  ],
  check: [['path', { d: 'm5 12.5 4.5 4.5L19 7' }]],
  clock: [
    ['circle', { cx: 12, cy: 12, r: 9 }],
    ['path', { d: 'M12 7v5.2l3.2 2' }],
  ],
  user: [
    ['circle', { cx: 12, cy: 8.5, r: 4 }],
    ['path', { d: 'M4.5 20.5c0-4 3.4-6 7.5-6s7.5 2 7.5 6' }],
  ],
  pin: [
    ['path', { d: 'M5 21V4' }],
    ['path', { d: 'M5 4h11l-1.8 4L16 12H5' }],
  ],
  note: [
    ['path', { d: 'M5 3.5h10l4 4v13H5v-17Z' }],
    ['path', { d: 'M15 3.5v4h4' }],
    ['path', { d: 'M8.5 13h7' }],
    ['path', { d: 'M8.5 17h5' }],
  ],
  database: [
    ['ellipse', { cx: 12, cy: 6, rx: 8, ry: 3 }],
    ['path', { d: 'M4 6v6c0 1.7 3.6 3 8 3s8-1.3 8-3V6' }],
    ['path', { d: 'M4 12v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6' }],
  ],
  more: [
    ['circle', { cx: 5, cy: 12, r: 1.3, fill: 'currentColor', stroke: 'none' }],
    ['circle', { cx: 12, cy: 12, r: 1.3, fill: 'currentColor', stroke: 'none' }],
    ['circle', { cx: 19, cy: 12, r: 1.3, fill: 'currentColor', stroke: 'none' }],
  ],
  menu: [
    ['path', { d: 'M4 7h16' }],
    ['path', { d: 'M4 12h16' }],
    ['path', { d: 'M4 17h16' }],
  ],
  'arrow-left': [
    ['path', { d: 'M19 12H5' }],
    ['path', { d: 'm11 6-6 6 6 6' }],
  ],
  'arrow-right': [
    ['path', { d: 'M5 12h14' }],
    ['path', { d: 'm13 6 6 6-6 6' }],
  ],
  'arrow-up': [
    ['path', { d: 'M12 19V5' }],
    ['path', { d: 'm6 11 6-6 6 6' }],
  ],
  'arrow-down': [
    ['path', { d: 'M12 5v14' }],
    ['path', { d: 'm6 13 6 6 6-6' }],
  ],
  filter: [['path', { d: 'M4 5h16l-6.2 7.2V19l-3.6 2v-8.8L4 5Z' }]],
  copy: [
    ['rect', { x: 9, y: 9, width: 11, height: 11, rx: 2 }],
    ['path', { d: 'M5 15V5a1 1 0 0 1 1-1h9' }],
  ],
  signal: [
    ['path', { d: 'M3.5 20h.01' }],
    ['path', { d: 'M7 16.5a6.5 6.5 0 0 1 10 0' }],
    ['path', { d: 'M4 12.5a11 11 0 0 1 16 0' }],
  ],
  send: [
    ['path', { d: 'M4 12 20 4l-6.5 16-2.3-6.2L4 12Z' }],
    ['path', { d: 'm11.2 13.8 3.3-3.3' }],
  ],
  calendar: [
    ['rect', { x: 4, y: 5, width: 16, height: 16, rx: 2 }],
    ['path', { d: 'M8 3v4' }],
    ['path', { d: 'M16 3v4' }],
    ['path', { d: 'M4 10h16' }],
  ],
  boundary: [
    ['path', { d: 'M4 5h16' }],
    ['path', { d: 'M4 12h16' }],
    ['path', { d: 'M4 19h16' }],
    ['path', { d: 'M8 3v18' }],
  ],
};

/**
 * Build an icon element.
 * @param {string} name
 * @param {{label?: string, size?: 'sm'|'lg'|'', className?: string}} [options]
 * @returns {SVGElement}
 */
export function icon(name, options = {}) {
  const def = ICONS[name] || ICONS.info;
  const classes = ['icon'];
  if (options.size === 'sm') classes.push('icon--sm');
  if (options.size === 'lg') classes.push('icon--lg');
  if (options.className) classes.push(options.className);

  const node = document.createElementNS(S, 'svg');
  node.setAttribute('class', classes.join(' '));
  node.setAttribute('viewBox', '0 0 24 24');
  node.setAttribute('focusable', 'false');
  if (options.label) {
    node.setAttribute('role', 'img');
    const title = document.createElementNS(S, 'title');
    title.textContent = options.label;
    node.append(title);
  } else {
    node.setAttribute('aria-hidden', 'true');
  }
  for (const [tag, attrs] of def) {
    const shape = document.createElementNS(S, tag);
    for (const [key, value] of Object.entries(attrs)) shape.setAttribute(key, String(value));
    node.append(shape);
  }
  return node;
}

