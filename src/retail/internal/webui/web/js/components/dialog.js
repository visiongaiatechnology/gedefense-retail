/**
 * Modal dialogs built on the native <dialog> element: the platform provides
 * focus trapping, Escape handling and the top layer. Used for operator actions
 * and confirmations, never for decorative overlays.
 */
import { el, focusNode } from '../core/dom.js';
import { t } from '../i18n/index.js';
import { icon } from '../core/icons.js';
import { inlineError } from './states.js';
import { actionErrorMessage } from '../core/actions.js';

let openDialogCount = 0;

/**
 * @param {{
 *  title: string,
 *  eyebrow?: string,
 *  description?: string,
 *  content?: Node|null,
 *  actions?: Array<{label: string, variant?: string, primary?: boolean, keepOpen?: boolean, onClick?: (ctx: any)=>Promise<unknown>|unknown}>,
 *  size?: 'wide'|'',
 *  sheet?: boolean,
 *  dismissible?: boolean,
 *  onClose?: ()=>void,
 *  initialFocus?: string,
 * }} options
 */
export function openDialog({
  title,
  eyebrow = '',
  description = '',
  content = null,
  actions = [],
  size = '',
  sheet = false,
  dismissible = true,
  onClose = null,
  initialFocus = '',
}) {
  const root = document.getElementById('overlay-root') || document.body;
  const dialogEl = el('dialog', {
    class: ['dialog', size === 'wide' ? 'dialog--wide' : '', sheet ? 'dialog--sheet' : ''].filter(Boolean).join(' '),
  });

  const head = el('div', { class: 'dialog__head' });
  const heading = el('div', { class: 'dialog__heading' });
  if (eyebrow) heading.append(el('span', { class: 'dialog__eyebrow', text: eyebrow }));
  heading.append(el('h2', { class: 'dialog__title', text: title }));
  head.append(heading);
  const closeButton = el('button', {
    type: 'button',
    class: 'btn btn--ghost btn--icon dialog__close',
    attrs: { 'aria-label': t('component.dialog.close_aria'), title: t('common.close') },
    on: { click: () => controller.close() },
  });
  closeButton.append(icon('close'));
  head.append(closeButton);
  dialogEl.append(head);

  const body = el('div', { class: 'dialog__body' });
  if (description) body.append(el('p', { text: description }));
  if (content) body.append(content);
  dialogEl.append(body);

  let errorNode = null;
  function showError(message) {
    if (errorNode) errorNode.remove();
    errorNode = inlineError(message);
    body.append(errorNode);
  }
  function clearError() {
    if (errorNode) errorNode.remove();
    errorNode = null;
  }

  const foot = el('div', { class: 'dialog__foot' });
  const actionButtons = [];
  function setBusy(busy) {
    dialogEl.setAttribute('aria-busy', busy ? 'true' : 'false');
    for (const button of actionButtons) {
      button.disabled = busy;
      button.toggleAttribute('aria-busy', busy);
    }
  }

  const controller = {
    element: dialogEl,
    close() {
      if (dialogEl.open) dialogEl.close();
    },
    setBusy,
    showError,
    clearError,
  };

  for (const action of actions) {
    const button = el('button', {
      type: 'button',
      class: ['btn', action.primary ? 'btn--primary' : action.variant || 'btn--ghost'].join(' '),
      text: action.label,
    });
    button.addEventListener('click', async () => {
      if (!action.onClick) {
        controller.close();
        return;
      }
      clearError();
      setBusy(true);
      try {
        const result = await action.onClick(controller);
        if (result !== false && !action.keepOpen) controller.close();
      } catch (error) {
        showError(actionErrorMessage(error));
      } finally {
        setBusy(false);
      }
    });
    actionButtons.push(button);
    foot.append(button);
  }
  if (actions.length > 0) dialogEl.append(foot);

  dialogEl.addEventListener('cancel', (event) => {
    if (!dismissible) {
      event.preventDefault();
      return;
    }
    controller.close();
  });

  // Backdrop click closes dismissible dialogs (target is the dialog element).
  dialogEl.addEventListener('click', (event) => {
    if (!dismissible) return;
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
    openDialogCount = Math.max(0, openDialogCount - 1);
    dialogEl.remove();
    onClose?.();
  });

  root.append(dialogEl);
  openDialogCount += 1;
  dialogEl.showModal();

  const focusTarget = initialFocus
    ? dialogEl.querySelector(initialFocus)
    : dialogEl.querySelector('input, select, textarea, button.btn--primary') ||
      dialogEl.querySelector('button');
  focusNode(focusTarget);

  return controller;
}

/** Small confirmation dialog with an explicit destructive action label. */
export function confirmDialog({ title, description, confirmLabel = t('common.confirm'), onConfirm, danger = false, eyebrow = '' }) {
  return openDialog({
    title,
    eyebrow,
    description,
    actions: [
      { label: t('common.cancel'), variant: 'btn--ghost' },
      {
        label: confirmLabel,
        primary: !danger,
        variant: danger ? 'btn--danger' : '',
        onClick: async () => {
          await onConfirm();
        },
      },
    ],
    initialFocus: 'button',
  });
}

export function hasOpenDialog() {
  return openDialogCount > 0;
}
