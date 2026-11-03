/**
 * Shell overlays: account/session dialog, keyboard help, mobile navigation sheet
 * and the blocking token gate. Kept beside the shell so each module stays small
 * and the gate state has exactly one owner.
 */
import { el, clear, focusNode } from '../core/dom.js';
import { t } from '../i18n/index.js';
import { icon } from '../core/icons.js';
import { NAV } from '../core/config.js';
import { languageSelector } from './language-selector.js';
import { clearToken, setToken, tokenHint } from '../core/auth.js';
import { hrefFor } from '../core/router.js';
import { openDialog } from './dialog.js';
import { banner } from './states.js';

let gateDialog = null;

/**
 * DOM identifiers of the token gate. They are referenced by aria-describedby
 * and by browser autofill and must never be translated: a localised identifier
 * would break the field/hint association. They are ids, not UI text.
 */
const TOKEN_INPUT_ID = 'gate-token';
const TOKEN_HINT_ID = 'gate-token-hint';

/* ---------------------------------------------------------------- overlays */

export function openAccountMenu(onLogout) {
  const hint = tokenHint();
  const content = el('div', { class: 'stack' });
  const facts = el('div', { class: 'detail-grid' });
  facts.append(
    el('div', { class: 'detail-field' }, [
      el('span', { class: 'detail-field__label', text: t('component.shell_overlay.field_session') }),
      el('span', { class: 'detail-field__value', text: t('shell.token.storage') }),
    ]),
    el('div', { class: 'detail-field' }, [
      el('span', { class: 'detail-field__label', text: t('component.shell_overlay.field_token') }),
      el('span', { class: 'detail-field__value detail-field__value--mono', text: hint || t('component.shell_overlay.not_signed_in') }),
    ]),
    el('div', { class: 'detail-field' }, [
      el('span', { class: 'detail-field__label', text: t('component.shell_overlay.field_roles') }),
      el('span', { class: 'detail-field__value', text: t('component.shell_overlay.roles_summary') }),
    ])
  );
  content.append(
    facts,
    el('p', {
      class: 'provenance',
      text: t('shell.account.role_note'),
    })
  );

  openDialog({
    title: t('component.shell_overlay.account_title'),
    eyebrow: t('shell.help.security'),
    content,
    actions: [
      { label: t('component.shell_overlay.keyboard_help'), variant: 'btn--ghost', keepOpen: true, onClick: () => { openHelp(); return false; } },
      {
        label: t('nav.logout'),
        variant: 'btn--danger',
        onClick: async () => {
          clearToken();
          onLogout?.();
        },
      },
    ],
  });
}

export function openHelp() {
  const content = el('div', { class: 'stack' });
  const list = el('dl', { class: 'shortcut-list' });
  const shortcuts = [
    ['?', t('shell.help.open')],
    ['Alt + 1 … 8', t('shell.help.direct_view')],
    ['/', t('shell.help.focus_search')],
    ['Alt + R', t('shell.help.reload')],
    ['Esc', t('shell.help.close_dialog')],
    ['Tab / Shift+Tab', t('shell.help.focus')],
  ];
  for (const [keys, description] of shortcuts) {
    const dt = el('dt');
    for (const key of keys.split(' + ')) {
      if (key.includes('…')) {
        dt.append(el('span', { text: key }));
      } else {
        dt.append(el('kbd', { text: key }));
      }
    }
    list.append(dt, el('dd', { text: description }));
  }
  content.append(
    el('p', {
      text: t('component.shell_overlay.help_a11y_note'),
    }),
    list,
    banner({
      variant: 'accent',
      title: t('component.shell_overlay.passive_monitoring'),
      text: t('shell.help.observation'),
    })
  );

  openDialog({ title: t('component.shell_overlay.help_title'), eyebrow: t('component.shell_overlay.help_eyebrow'), content, size: 'wide', actions: [{ label: t('common.close'), primary: true }] });
}

export function openNavSheet(refs) {
  const content = el('div', { class: 'stack' });

  const grid = el('nav', { class: 'sheet-nav', attrs: { 'aria-label': t('shell.nav.all_views') } });
  for (const item of NAV) {
    if (item.hidden) continue;
    const link = el('a', {
      class: 'sheet-nav__link',
      href: hrefFor(item.id),
      dataset: { view: item.id },
      on: {
        click: () => {
          const dialog = link.closest('dialog');
          if (dialog) dialog.close();
        },
      },
    });
    if (refs && refs.activeView === item.id) link.setAttribute('aria-current', 'page');
    link.append(icon(item.icon), el('span', { text: item.title }));
    grid.append(link);
  }
  content.append(grid);

  const actions = el('div', { class: 'sheet-actions' });
  const helpButton = el('button', { type: 'button', class: 'btn btn--secondary', text: t('shell.help.title') });
  helpButton.addEventListener('click', () => openHelp());
  const logoutButton = el('button', { type: 'button', class: 'btn btn--danger', text: t('nav.logout') });
  logoutButton.addEventListener('click', () => {
    clearToken();
    refs?.onLogout?.();
    const dialog = logoutButton.closest('dialog');
    if (dialog) dialog.close();
  });
  actions.append(helpButton, logoutButton);
  content.append(actions);

  openDialog({ title: t('shell.nav.more_title'), eyebrow: t('shell.nav.eyebrow'), content, sheet: true, actions: [] });
}

/* -------------------------------------------------------------- token gate */

function buildTokenGate({ message = '', onSubmit, onSuccess }) {
  const dialogEl = el('dialog', { class: 'gate', attrs: { 'aria-label': t('login.title') } });

  const head = el('div', { class: 'gate__head' });
  head.append(
    el('img', { class: 'gate__brand', attrs: { src: '/assets/gedefense-logo.png', alt: '', width: '38', height: '38' } }),
    el('div', { class: 'stack stack--tight' }, [
      el('span', { class: 'gate__kicker', text: 'GeDefense Retail' }),
      el('h2', { class: 'gate__title', text: t('login.headline') }),
    ])
  );
  dialogEl.append(head);

  const body = el('div', { class: 'gate__body' });
  if (message) {
    body.append(
      banner({
        // The caller passes a free-form message string. The locale-aware equality check is the
        // primary classifier; the German fragments below are a non-rendered legacy fallback for
        // callers that still build their text in German and must not be treated as UI strings.
        variant: message === t('login.invalid') || message.includes('abgelaufen') || message.includes('ungültig') ? 'warn' : 'info',
        title: t('login.title'),
        text: message,
      })
    );
  }
  body.append(languageSelector({ compact: true, showLabel: true }));
  body.append(
    el('p', {
      class: 'gate__text',
      text: t('login.text_long'),
    })
  );

  const field = el('div', { class: 'field' });
  const inputId = TOKEN_INPUT_ID;
  field.append(el('label', { class: 'field__label', text: t('login.label'), attrs: { for: inputId } }));
  const input = el('input', {
    id: inputId,
    class: 'input',
    type: 'password',
    attrs: { autocomplete: 'off', spellcheck: 'false', placeholder: t('login.placeholder'), 'aria-describedby': TOKEN_HINT_ID },
  });
  field.append(input);
  field.append(
    el('p', {
      id: TOKEN_HINT_ID,
      class: 'field__hint',
      text: t('login.no_persist'),
    })
  );
  body.append(field);

  const errorSlot = el('div');
  body.append(errorSlot);

  const actions = el('div', { class: 'gate__actions' });
  const button = el('button', { type: 'button', class: 'btn btn--primary btn__label', text: t('login.submit') });
  actions.append(button);
  body.append(actions);

  body.append(
    el('p', { class: 'gate__note' }, [
      icon('shield', { size: 'sm' }),
      el('span', {
        text: t('login.sha_note'),
      }),
    ])
  );

  dialogEl.append(body);

  dialogEl.addEventListener('cancel', (event) => event.preventDefault());

  let busy = false;
  async function submit() {
    if (busy) return;
    const token = input.value.trim();
    if (!token) {
      showGateError(t('login.empty'));
      return;
    }
    busy = true;
    button.disabled = true;
    button.setAttribute('aria-busy', 'true');
    clear(errorSlot);
    try {
      const result = await onSubmit(token);
      if (result === false) {
        showGateError(t('login.rejected'));
        return;
      }
      setToken(token);
      if (gateDialog === dialogEl) gateDialog = null;
      dialogEl.close();
      onSuccess?.();
    } catch (error) {
      const status = error && error.status;
      if (status === 401) showGateError(t('login.rejected_401'));
      else if (status === 429) showGateError(t('login.rate_limited'));
      else if (status === 0) showGateError(t('login.offline'));
      else showGateError(error?.message || t('component.shell_overlay.login_failed'));
    } finally {
      busy = false;
      button.disabled = false;
      button.removeAttribute('aria-busy');
      focusNode(input);
    }
  }

  function showGateError(text) {
    clear(errorSlot);
    errorSlot.append(banner({ variant: 'warn', title: t('login.failed_title'), text }));
  }

  button.addEventListener('click', submit);
  input.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') submit();
  });

  document.getElementById('overlay-root')?.append(dialogEl) || document.body.append(dialogEl);
  dialogEl.showModal();
  focusNode(input);
  return dialogEl;
}

/** Open the blocking token gate; replaces any previous gate. */
export function showTokenGate(options) {
  closeGate();
  const dialogEl = buildTokenGate(options);
  gateDialog = dialogEl;
  return dialogEl;
}

export function closeGate() {
  if (gateDialog) {
    gateDialog.close();
    gateDialog = null;
  }
}

export function gateIsOpen() {
  return Boolean(gateDialog);
}
