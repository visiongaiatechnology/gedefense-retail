/**
 * Non-blocking operator feedback for live events and completed actions.
 * Toasts are announced politely, auto-dismiss and never steal focus.
 */
import { el } from '../core/dom.js';
import { t } from '../i18n/index.js';
import { icon } from '../core/icons.js';
import { subscribe } from '../core/store.js';
import { announce } from './states.js';

const MAX_TOASTS = 4;

export function initToasts() {
  const root = document.getElementById('toast-root');
  if (!root) return () => {};

  const remove = (node) => {
    if (node && node.parentNode) node.remove();
  };

  return subscribe('toast', ({ variant = 'info', title = '', text = '', timeout = 6000, severity = '' }) => {
    while (root.children.length >= MAX_TOASTS) root.firstElementChild?.remove();

    const toast = el('div', {
      class: `toast${variant === 'alert' ? ' toast--alert' : ''}`,
      dataset: severity ? { severity } : {},
      attrs: { role: variant === 'alert' ? 'alert' : 'status' },
    });
    const iconName = { alert: 'alert', warn: 'warning', success: 'check', info: 'info' }[variant] || 'info';
    toast.append(icon(iconName, { size: 'sm' }));

    const body = el('div', { class: 'toast__body' });
    if (title) body.append(el('span', { class: 'toast__title', text: title }));
    if (text) body.append(el('span', { class: 'toast__text', text }));
    toast.append(body);

    const close = el('button', {
      type: 'button',
      class: 'btn btn--ghost btn--icon btn--sm',
      attrs: { 'aria-label': t('component.toast.close_aria'), title: t('common.close') },
      on: { click: () => remove(toast) },
    });
    close.append(icon('close', { size: 'sm' }));
    toast.append(close);

    root.append(toast);
    announce(`${title}${text ? `. ${text}` : ''}`);

    if (timeout > 0) {
      window.setTimeout(() => remove(toast), timeout);
    }
  });
}
