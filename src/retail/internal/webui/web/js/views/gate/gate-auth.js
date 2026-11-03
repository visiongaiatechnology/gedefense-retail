/**
 * Access-Gate authentication UI. The gate session is separate from the
 * monitoring token: it is obtained via POST /gate/auth/login (password + TOTP),
 * kept in sessionStorage and never placed in the URL or a cookie.
 */
import { el, clear, focusNode } from '../../core/dom.js';
import { gateApi } from '../../core/api.js';
import { clearGateToken, setGateToken, gateTokenHint } from '../../core/auth.js';
import { formatDateTime } from '../../core/format.js';
import { gateRoleChip } from '../../components/chips.js';
import { banner, inlineError } from '../../components/states.js';
import { icon } from '../../core/icons.js';
import { gateErrorMessage } from './gate-dialogs.js';
import { t } from '../../i18n/index.js';

function field({ id, label, type = 'text', autocomplete = 'off', hint = '', inputmode = '' }) {
  const wrapper = el('div', { class: 'field' });
  wrapper.append(el('label', { class: 'field__label', text: label, attrs: { for: id } }));
  wrapper.append(
    el('input', {
      id,
      class: 'input',
      type,
      attrs: {
        autocomplete,
        inputmode: inputmode || undefined,
        spellcheck: 'false',
        'aria-describedby': hint ? `${id}-hint` : undefined,
      },
    })
  );
  if (hint) wrapper.append(el('p', { id: `${id}-hint`, class: 'field__hint', text: hint }));
  return wrapper;
}

/**
 * Render the blocking gate login panel. The surrounding view must call
 * loadGateCore() again after onLoggedIn.
 */
export function renderGateLogin(host, { message = '', health = null, onLoggedIn } = {}) {
  clear(host);
  const section = el('section', { class: 'gate-auth', attrs: { 'aria-labelledby': 'gate-auth-title' } });
  const card = el('div', { class: 'gate-auth__card plane plane--focus' });
  card.append(
    el('img', { class: 'gate-auth__logo', attrs: { src: '/assets/gedefense-logo.png', alt: '', width: '56', height: '56' } }),
    el('div', { class: 'gate-auth__kicker' }, [
      el('span', { class: 'badge badge--accent', text: t('gate.auth.kicker_badge') }),
      el('span', { text: t('gate.auth.kicker') }),
    ]),
    el('h2', { id: 'gate-auth-title', class: 'gate-auth__title', text: t('gate.auth.title') }),
    el('p', {
      class: 'gate-auth__text',
      text: t('gate.auth.text'),
    })
  );

  if (message) {
    card.append(banner({ variant: 'warn', title: t('gate.auth.required_title'), text: message }));
  }
  if (health) {
    card.append(
      el('div', { class: 'gate-auth__health' }, [
        el('span', { class: 'chip chip--status', dataset: { status: health.status === 'ok' ? 'resolved' : 'investigating' }, text: health.status === 'ok' ? t('gate.status.reachable') : t('gate.status.degraded') }),
        el('span', { class: 'provenance', text: t('gate.common.version_value', { version: health.version || '—' }) }),
        el('span', { class: 'provenance', text: t('gate.auth.audit_chain', { state: health.audit_chain_ok ? t('gate.common.verified') : t('gate.common.not_verified') }) }),
        health.failsafe && health.failsafe.active
          ? el('span', { class: 'chip chip--sev', dataset: { severity: 'critical' }, text: t('gate.status.failsafe_active') })
          : el('span', { class: 'provenance', text: t('gate.status.failsafe_inactive') }),
      ])
    );
  }

  const form = el('form', { class: 'gate-auth__form', attrs: { autocomplete: 'on' } });
  form.append(
    field({ id: 'gate-user-id', label: t('gate.auth.user_id'), autocomplete: 'username' }),
    field({ id: 'gate-password', label: t('gate.auth.password'), type: 'password', autocomplete: 'current-password' }),
    field({
      id: 'gate-totp',
      label: t('gate.auth.mfa'),
      type: 'password',
      autocomplete: 'one-time-code',
      inputmode: 'numeric',
      hint: t('gate.auth.mfa_hint'),
    })
  );
  const errorSlot = el('div');
  form.append(errorSlot);
  const submit = el('button', { type: 'submit', class: 'btn btn--primary gate-auth__submit' });
  submit.append(icon('gate', { size: 'sm' }), el('span', { text: t('gate.auth.submit') }));
  form.append(submit);
  card.append(form);

  card.append(
    el('p', { class: 'gate-auth__note' }, [
      icon('shield', { size: 'sm' }),
      el('span', {
        text: t('gate.auth.note'),
      }),
    ])
  );
  section.append(card);
  host.append(section);
  focusNode(document.getElementById('gate-user-id'));

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    clear(errorSlot);
    const userId = String(document.getElementById('gate-user-id')?.value || '').trim();
    const password = String(document.getElementById('gate-password')?.value || '');
    const totp = String(document.getElementById('gate-totp')?.value || '').trim();
    if (!userId || !password) {
      errorSlot.append(inlineError(t('gate.auth.error_credentials')));
      return;
    }
    if (!/^\d{6}$/.test(totp)) {
      errorSlot.append(inlineError(t('gate.auth.error_totp')));
      focusNode(document.getElementById('gate-totp'));
      return;
    }
    submit.disabled = true;
    submit.setAttribute('aria-busy', 'true');
    try {
      const response = await gateApi.login({ user_id: userId, password, totp });
      if (!response || !response.session_token) {
        throw new Error(t('gate.auth.error_no_session'));
      }
      if (!setGateToken(response.session_token)) {
        errorSlot.append(inlineError(t('gate.auth.error_storage')));
        return;
      }
      // Clear the password field immediately; the token stays in memory only.
      const passwordField = document.getElementById('gate-password');
      if (passwordField) passwordField.value = '';
      const totpField = document.getElementById('gate-totp');
      if (totpField) totpField.value = '';
      onLoggedIn?.(response);
    } catch (error) {
      errorSlot.append(inlineError(gateErrorMessage(error)));
    } finally {
      submit.disabled = false;
      submit.removeAttribute('aria-busy');
    }
  });
}

/** Session strip shown above the Gate tabs. */
export function gateSessionBar(me, { onLogout } = {}) {
  const bar = el('div', { class: 'gate-sessionbar glass', attrs: { role: 'status', 'aria-label': t('gate.auth.session_aria') } });
  const user = me?.user || {};
  const identity = el('div', { class: 'gate-sessionbar__identity' });
  identity.append(
    el('span', { class: 'gate-sessionbar__name', text: user.name || user.user_id || t('gate.auth.identity_fallback') }),
    el('span', { class: 'gate-sessionbar__meta' }, [
      el('span', { class: 'mono', text: user.user_id || '' }),
      gatewayKindLabel(user.kind),
      me?.mfa_ok ? el('span', { class: 'chip chip--status', dataset: { status: 'resolved' }, text: t('gate.auth.mfa_active') }) : el('span', { class: 'chip chip--sev', dataset: { severity: 'medium' }, text: t('gate.auth.mfa_missing') }),
    ])
  );
  const roles = el('div', { class: 'gate-sessionbar__roles' });
  for (const role of user.roles || []) roles.append(gateRoleChip(role));
  const meta = el('div', { class: 'gate-sessionbar__meta' });
  meta.append(
    el('span', { text: t('gate.auth.session_until', { time: formatDateTime(me?.expires_at) }) }),
    el('span', { class: 'mono', text: gateTokenHint() })
  );
  const logout = el('button', {
    type: 'button',
    class: 'btn btn--ghost btn--sm',
    attrs: { 'aria-label': t('gate.auth.logout') },
  });
  logout.append(icon('logout', { size: 'sm' }), el('span', { text: t('gate.common.logout') }));
  logout.addEventListener('click', async () => {
    try {
      await gateApi.logout();
    } catch {
      /* best effort: the local token is cleared regardless */
    }
    clearGateToken();
    onLogout?.();
  });
  bar.append(identity, roles, meta, logout);
  return bar;
}

function gatewayKindLabel(kind) {
  const key = kind === 'vendor' ? 'enum.gate_user_kind.vendor' : kind === 'operator' ? 'enum.gate_user_kind.operator' : kind === 'admin' ? 'enum.gate_user_kind.admin' : '';
  return el('span', { class: 'chip chip--category', text: key ? t(key) : String(kind || '—') });
}

/** Local logout without a session (e.g. after 401). */
export function forgetGateSession() {
  clearGateToken();
}
