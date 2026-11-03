/**
 * Loading, empty, partial and error states. Every state says what is missing,
 * why it is missing and what the operator can do next — no decorative empties.
 */
import { el } from '../core/dom.js';
import { icon } from '../core/icons.js';
import { formatAgeMs } from '../core/format.js';
import { t } from '../i18n/index.js';

export function announce(message) {
  const region = document.getElementById('live-region');
  if (!region) return;
  region.textContent = '';
  // Re-insert so repeated identical announcements are still spoken.
  window.setTimeout(() => {
    region.textContent = message;
  }, 30);
}

/** Visually hidden loading announcement plus a skeleton for the layout. */
export function skeletonPage(label = t('component.states.loading_default')) {
  const wrapper = el('div', { class: 'stack', attrs: { 'aria-busy': 'true' } });
  wrapper.append(
    el('div', { class: 'skeleton skeleton--title' }),
    el('div', { class: 'skeleton-stack' }, [
      el('div', { class: 'skeleton skeleton--row' }),
      el('div', { class: 'skeleton skeleton--row' }),
      el('div', { class: 'skeleton skeleton--row' }),
      el('div', { class: 'skeleton skeleton--row' }),
      el('div', { class: 'skeleton skeleton--row' }),
    ]),
    el('span', { class: 'sr-only', text: label })
  );
  return wrapper;
}

export function skeletonTable(rows = 8) {
  const wrapper = el('div', { class: 'stack', attrs: { 'aria-busy': 'true' } });
  const head = el('div', { class: 'skeleton skeleton--line' });
  wrapper.append(head);
  for (let index = 0; index < rows; index += 1) {
    wrapper.append(el('div', { class: 'skeleton skeleton--row' }));
  }
  wrapper.append(el('span', { class: 'sr-only', text: t('component.states.loading_table') }));
  return wrapper;
}

export function skeletonChart() {
  const wrapper = el('div', { class: 'stack', attrs: { 'aria-busy': 'true' } });
  wrapper.append(
    el('div', { class: 'skeleton skeleton--block' }),
    el('div', { class: 'cluster' }, [
      el('div', { class: 'skeleton skeleton--text' }),
      el('div', { class: 'skeleton skeleton--text' }),
      el('div', { class: 'skeleton skeleton--text' }),
    ]),
    el('span', { class: 'sr-only', text: t('component.states.loading_chart') })
  );
  return wrapper;
}


/**
 * @param {{icon?: string, title: string, text: string, actions?: Node[], detail?: string}} options
 */
export function emptyState({ icon: iconName = 'info', title, text, actions = [], detail = '' }) {
  const container = el('div', { class: 'state' });
  container.append(
    el('div', { class: 'state__icon' }, icon(iconName, { size: 'lg' })),
    el('h3', { class: 'state__title', text: title }),
    el('p', { class: 'state__text', text })
  );
  if (detail) container.append(el('p', { class: 'state__detail', text: detail }));
  if (actions.length > 0) {
    container.append(el('div', { class: 'state__actions' }, actions));
  }
  return container;
}

/**
 * Concrete, actionable error. Shows the API error code and request id so a
 * support case can be opened without guessing.
 */
export function errorState({ title = t('component.states.error_title'), text = '', error, actions = [] } = {}) {
  const container = el('div', { class: 'state state--error', attrs: { role: 'alert' } });
  container.append(
    el('div', { class: 'state__icon' }, icon('alert', { size: 'lg' })),
    el('h3', { class: 'state__title', text: title })
  );
  const message = text || (error && error.message) || t('component.states.error_unknown');
  container.append(el('p', { class: 'state__text', text: message }));

  if (error && (error.diagnostic || error.code)) {
    const parts = [];
    if (error.status) parts.push(`HTTP ${error.status}`);
    if (error.code) parts.push(t('component.states.error_code', { code: error.code }));
    if (error.requestId) parts.push(t('component.states.error_request_id', { id: error.requestId }));
    if (error.serverMessage) parts.push(t('component.states.error_gateway', { message: error.serverMessage }));
    if (parts.length > 0) container.append(el('p', { class: 'state__detail', text: parts.join(' · ') }));
  }

  if (error && error.status === 401) {
    container.append(
      el('p', {
        class: 'state__text',
        text: t('component.states.error_401'),
      })
    );
  } else if (error && error.status === 403) {
    container.append(
      el('p', {
        class: 'state__text',
        text: t('component.states.error_403'),
      })
    );
  }

  if (actions.length > 0) container.append(el('div', { class: 'state__actions' }, actions));
  return container;
}

/** Inline error for forms and dialogs: compact, concrete, non-blaming. */
export function inlineError(message) {
  return el(
    'p',
    { class: 'field__error', attrs: { role: 'alert' } },
    icon('alert', { size: 'sm' }),
    el('span', { text: message })
  );
}

/**
 * @param {{variant?: 'info'|'warn'|'critical'|'accent', title: string, text?: string, action?: Node}} options
 */
export function banner({ variant = 'info', title, text = '', action = null, iconName = '' } = {}) {
  const iconForVariant = iconName || {
    info: 'info',
    warn: 'warning',
    critical: 'alert',
    accent: 'signal',
  }[variant] || 'info';

  const node = el('div', { class: `banner banner--${variant}`, attrs: { role: variant === 'critical' ? 'alert' : 'status' } });
  node.append(icon(iconForVariant, { size: 'sm' }));
  const body = el('div', { class: 'banner__body' });
  body.append(el('span', { class: 'banner__title', text: title }));
  if (text) body.append(el('span', { class: 'banner__text', text }));
  node.append(body);
  if (action) node.append(action);
  return node;
}

/** Stale data is explicitly marked, never silently rendered as current. */
export function staleBanner(lastDataAt, { connection = 'live' } = {}) {
  if (!lastDataAt) return null;
  const age = Date.now() - lastDataAt;
  if (age < 90_000 && connection !== 'offline' && connection !== 'degraded') return null;
  const reason =
    connection === 'offline'
      ? t('component.states.stale_offline')
      : connection === 'degraded'
        ? t('component.states.stale_degraded')
        : t('component.states.stale_old');
  return banner({
    variant: connection === 'offline' ? 'critical' : 'warn',
    title: t('component.states.stale_title', { age: formatAgeMs(age) }),
    text: reason,
  });
}

/** Partial data: one source failed while the primary view is still useful. */
export function partialBanner({ title = t('component.states.partial_title'), text, action = null }) {
  return banner({ variant: 'warn', title, text, action });
}

