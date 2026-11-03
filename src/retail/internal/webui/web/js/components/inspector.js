/**
 * Right-hand inspector built on the native <dialog> element. It is the floating
 * glass layer (Z3): detail context for a table row or timeline entry without
 * leaving the current working plane.
 */
import { el, focusNode } from '../core/dom.js';
import { t } from '../i18n/index.js';
import { icon } from '../core/icons.js';

let current = null;

/**
 * @param {{
 *  title: string,
 *  eyebrow?: string,
 *  content: Node,
 *  foot?: Node|null,
 *  onClose?: ()=>void,
 * }} options
 */
export function openInspector({ title, eyebrow = '', content, foot = null, onClose = null }) {
  if (current) current.close();

  const dialogEl = el('dialog', { class: 'inspector', attrs: { 'aria-label': title } });

  const head = el('div', { class: 'inspector__head' });
  const heading = el('div', { class: 'inspector__heading' });
  if (eyebrow) heading.append(el('span', { class: 'inspector__eyebrow', text: eyebrow }));
  heading.append(el('h2', { class: 'inspector__title', text: title }));
  head.append(heading);

  const closeButton = el('button', {
    type: 'button',
    class: 'btn btn--ghost btn--icon',
    attrs: { 'aria-label': t('component.inspector.close_aria'), title: t('common.close') },
    on: { click: () => controller.close() },
  });
  closeButton.append(icon('close'));
  head.append(closeButton);
  dialogEl.append(head);

  const body = el('div', { class: 'inspector__body' });
  body.append(content);
  dialogEl.append(body);

  if (foot) dialogEl.append(el('div', { class: 'inspector__foot' }, foot));

  const controller = {
    element: dialogEl,
    body,
    setTitle(text) {
      const titleNode = dialogEl.querySelector('.inspector__title');
      if (titleNode) titleNode.textContent = text;
    },
    close() {
      if (dialogEl.open) dialogEl.close();
    },
  };

  dialogEl.addEventListener('cancel', (event) => {
    event.preventDefault();
    controller.close();
  });
  dialogEl.addEventListener('click', (event) => {
    if (event.target === dialogEl) {
      const rect = dialogEl.getBoundingClientRect();
      const inside =
        event.clientX >= rect.left &&
        event.clientX <= rect.right &&
        event.clientY >= rect.top &&
        event.clientY <= rect.bottom;
      if (!inside) controller.close();
    }
  });
  dialogEl.addEventListener('close', () => {
    dialogEl.remove();
    if (current === controller) current = null;
    onClose?.();
  });

  const host = document.getElementById('overlay-root') || document.body;
  host.append(dialogEl);
  dialogEl.showModal();
  focusNode(dialogEl.querySelector('button'));
  current = controller;
  return controller;
}

export function closeInspector() {
  if (current) current.close();
}
