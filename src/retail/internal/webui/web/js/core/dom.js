/**
 * DOM construction helpers.
 *
 * Product rule: dynamic data is only ever written with textContent or as
 * attribute values — never through innerHTML. These helpers make that the
 * path of least resistance.
 */
const BOOLEAN_PROPS = new Set(['disabled', 'checked', 'selected', 'hidden', 'multiple', 'required', 'readOnly']);

/**
 * Create an HTML element.
 *
 * @param {string} tag
 * @param {object} [opts] class, text, attrs, props, dataset, on, role
 * @param {...(Node|string|null|false|undefined)} children
 */
export function el(tag, opts, ...children) {
  const node = document.createElement(tag);
  applyOpts(node, opts);
  appendChildren(node, children);
  return node;
}

/** Create an SVG element in the SVG namespace. */
export function svg(tag, attrs, ...children) {
  const node = document.createElementNS('http://www.w3.org/2000/svg', tag);
  if (attrs) {
    for (const [key, value] of Object.entries(attrs)) {
      if (value === undefined || value === null || value === false) continue;
      node.setAttribute(key, String(value));
    }
  }
  if (children.length > 0) {
    const fragmentNode = document.createDocumentFragment();
    for (const child of children.flat()) {
      if (child === null || child === undefined || child === false) continue;
      fragmentNode.append(typeof child === 'string' ? document.createTextNode(child) : child);
    }
    node.append(fragmentNode);
  }
  return node;
}

function applyOpts(node, opts) {
  if (!opts) return;
  for (const [key, value] of Object.entries(opts)) {
    if (value === undefined || value === null || value === false) continue;
    switch (key) {
      case 'class':
      case 'className':
        node.className = Array.isArray(value) ? value.filter(Boolean).join(' ') : String(value);
        break;
      case 'text':
        node.textContent = String(value);
        break;
      case 'attrs':
        for (const [name, attrValue] of Object.entries(value)) {
          if (attrValue === undefined || attrValue === null || attrValue === false) continue;
          node.setAttribute(name, attrValue === true ? '' : String(attrValue));
        }
        break;
      case 'props':
        for (const [name, propValue] of Object.entries(value)) {
          if (BOOLEAN_PROPS.has(name)) node[name] = Boolean(propValue);
          else if (propValue !== undefined) node[name] = propValue;
        }
        break;
      case 'dataset':
        for (const [name, dataValue] of Object.entries(value)) {
          if (dataValue === undefined || dataValue === null) continue;
          node.dataset[name] = String(dataValue);
        }
        break;
      case 'on':
        for (const [type, handler] of Object.entries(value)) {
          if (typeof handler === 'function') node.addEventListener(type, handler);
        }
        break;
      case 'role':
        node.setAttribute('role', String(value));
        break;
      default:
        // Remaining top-level keys are treated as attributes (e.g. href, id).
        node.setAttribute(key, value === true ? '' : String(value));
    }
  }
}

function appendChildren(node, children) {
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    if (Array.isArray(child)) {
      appendChildren(node, child);
      continue;
    }
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
}

/** Replace all children of a node. */
export function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
  return node;
}

/** Replace a container's content with new nodes (clears first). */
export function render(container, ...children) {
  clear(container);
  appendChildren(container, children);
  return container;
}

/** Shorthand for a text node. */
export function txt(value) {
  return document.createTextNode(value === null || value === undefined ? '—' : String(value));
}

export function fragment(...children) {
  const frag = document.createDocumentFragment();
  appendChildren(frag, children);
  return frag;
}

/** Add an event listener and return the unsubscribe function. */
export function on(target, type, handler, options) {
  target.addEventListener(type, handler, options);
  return () => target.removeEventListener(type, handler, options);
}

/** Monotonic counter used for aria id relations. */
let uidCounter = 0;
export function uid(prefix = 'ui') {
  uidCounter += 1;
  return `${prefix}-${uidCounter}`;
}

export function debounce(fn, delayMs = 200) {
  let timer = 0;
  function debounced(...args) {
    window.clearTimeout(timer);
    timer = window.setTimeout(() => fn(...args), delayMs);
  }
  debounced.cancel = () => window.clearTimeout(timer);
  return debounced;
}

export function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

/** Platform-safe focus call (does not throw on detached nodes). */
export function focusNode(node) {
  if (node && typeof node.focus === 'function') {
    try {
      // Focus for keyboard/screen-reader context must never scroll the page
      // underneath the sticky command bar.
      node.focus({ preventScroll: true });
    } catch {
      node.focus();
    }
  }
}

/** Simple keyboard activation for non-button surfaces. */
export function onActivate(node, handler) {
  node.addEventListener('click', handler);
  node.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      handler(event);
    }
  });
}
