/**
 * Access-Gate workflow dialogs: approve (MFA), reject, cancel, session revoke and
 * the one-time token reveal. All mutations are server-authorised; the dialogs
 * only collect the required evidence and never store secrets.
 */
import { el } from '../../core/dom.js';
import { gateApi } from '../../core/api.js';
import { NOTE_MAX_LENGTH } from '../../core/config.js';
import { formatDateTime } from '../../core/format.js';
import { planStateLabel, protocolLabel, unitLabel } from '../../core/labels.js';
import { openDialog } from '../../components/dialog.js';
import { banner } from '../../components/states.js';
import { icon } from '../../core/icons.js';
import { t } from '../../i18n/index.js';

/** German, concrete error text for gate API error codes. */
export function gateErrorMessage(error) {
  const code = error && error.code ? String(error.code) : 'network';
  const map = {
    mfa_required: t('gate.errors.mfa_required'),
    self_approval: t('gate.errors.self_approval'),
    plan_already_decided: t('gate.errors.plan_already_decided'),
    plan_hash_mismatch: t('gate.errors.plan_hash_mismatch'),
    window_expired: t('gate.errors.window_expired'),
    role_required: t('gate.errors.role_required'),
    device_not_bound: t('gate.errors.device_not_bound'),
    user_disabled: t('gate.errors.user_disabled'),
    invalid_credentials: t('gate.errors.invalid_credentials'),
    token_invalid: t('gate.errors.token_invalid'),
    token_expired: t('gate.errors.token_expired'),
    token_used: t('gate.errors.token_used'),
    wrong_source: t('gate.errors.wrong_source'),
    not_approved: t('gate.errors.not_approved'),
    outside_window: t('gate.errors.outside_window'),
    failsafe_active: t('gate.errors.failsafe_active'),
  };
  if (error && error.status === 401) return t('gate.errors.session_expired');
  if (error && error.status === 403 && map[code]) return map[code];
  if (error && error.status === 403) return t('gate.errors.role_required_generic');
  if (error && error.status === 429) return t('gate.errors.rate_limited');
  if (error && error.status === 0) return t('gate.errors.offline');
  return map[code] || (error && error.message) || t('gate.errors.generic');
}

function mfaField(prefix) {
  const id = `${prefix}-mfa`;
  const field = el('div', { class: 'field' });
  field.append(
    el('label', { class: 'field__label', text: t('gate.dialogs.mfa_label'), attrs: { for: id } }),
    el('input', {
      id,
      class: 'input mono',
      type: 'password',
      attrs: {
        inputmode: 'numeric',
        autocomplete: 'one-time-code',
        maxlength: '6',
        pattern: '[0-9]{6}',
        placeholder: '123456',
        'aria-describedby': `${id}-hint`,
      },
    }),
    el('p', {
      id: `${id}-hint`,
      class: 'field__hint',
      text: t('gate.dialogs.mfa_hint'),
    })
  );
  return field;
}

function commentField(prefix, label, placeholder, required = false) {
  const id = `${prefix}-comment`;
  const field = el('div', { class: 'field' });
  field.append(
    el('label', { class: 'field__label', text: label, attrs: { for: id } }),
    el('textarea', {
      id,
      class: 'textarea',
      attrs: { rows: '3', maxlength: String(NOTE_MAX_LENGTH), placeholder, required: required ? 'required' : undefined },
    })
  );
  field.append(el('p', { class: 'field__hint', text: t('gate.dialogs.comment_hint') }));
  return field;
}

function readValue(id) {
  const input = document.getElementById(id);
  return input ? String(input.value || '').trim() : '';
}

/** Approve dialog: MFA is mandatory; four-eyes state is shown before approval. */
export function openApproveDialog(plan, { onApproved } = {}) {
  const content = el('div', { class: 'stack' });
  content.append(
    el('p', {
      class: 'evidence-block__text',
      text: `Plan ${plan.plan_id} · ${plan.target_id || '—'} · ${protocolLabel(plan.protocol)}`,
    }),
    banner({
      variant: 'accent',
      title: t('gate.dialogs.approve_banner_title'),
      text: t('gate.dialogs.approve_banner_text'),
    }),
    mfaField('gate-approve'),
    commentField('gate-approve', t('gate.dialogs.comment_optional'), t('gate.dialogs.comment_placeholder_approve'))
  );
  if (plan.critical || plan.four_eyes) {
    content.append(
      banner({
        variant: 'warn',
        title: t('gate.dialogs.four_eyes_title'),
        text: t('gate.dialogs.four_eyes_text'),
      })
    );
  }

  let succeeded = false;
  let result = null;
  const dialog = openDialog({
    title: t('gate.dialogs.approve_title'),
    eyebrow: t('gate.dialogs.eyebrow_approval'),
    content,
    size: 'wide',
    initialFocus: '#gate-approve-mfa',
    actions: [
      { label: t('gate.common.cancel'), variant: 'btn--ghost' },
      {
        label: t('gate.dialogs.approve_submit'),
        primary: true,
        onClick: async (controller) => {
          const mfa = readValue('gate-approve-mfa');
          if (!/^\d{6}$/.test(mfa)) {
            controller.showError(t('gate.dialogs.mfa_error'));
            return false;
          }
          try {
            result = await gateApi.approvePlan(
              plan.plan_id,
              mfa,
              readValue('gate-approve-comment')
            );
            succeeded = true;
            return true;
          } catch (error) {
            controller.showError(gateErrorMessage(error));
            return false;
          }
        },
      },
    ],
    onClose: () => {
      if (succeeded) onApproved?.(result);
    },
  });
  return dialog;
}

/** Reject dialog: a reason is mandatory evidence. */
export function openRejectDialog(plan, { onRejected } = {}) {
  const content = el('div', { class: 'stack' });
  content.append(
    el('p', {
      class: 'evidence-block__text',
      text: `Plan ${plan.plan_id} · ${plan.target_id || '—'} · ${protocolLabel(plan.protocol)}`,
    }),
    banner({
      variant: 'warn',
      title: t('gate.dialogs.reject_banner_title'),
      text: t('gate.dialogs.reject_banner_text'),
    }),
    commentField('gate-reject', t('gate.dialogs.reject_reason_label'), t('gate.dialogs.reject_reason_placeholder'), true)
  );
  let succeeded = false;
  let result = null;
  return openDialog({
    title: t('gate.dialogs.reject_title'),
    eyebrow: t('gate.dialogs.eyebrow_approval'),
    content,
    size: 'wide',
    actions: [
      { label: 'Abbrechen', variant: 'btn--ghost' },
      {
        label: t('gate.inbox.reject'),
        variant: 'btn--danger',
        onClick: async (controller) => {
          const reason = readValue('gate-reject-comment');
          if (!reason) {
            controller.showError(t('gate.dialogs.reject_reason_error'));
            return false;
          }
          try {
            result = await gateApi.rejectPlan(plan.plan_id, reason);
            succeeded = true;
            return true;
          } catch (error) {
            controller.showError(gateErrorMessage(error));
            return false;
          }
        },
      },
    ],
    onClose: () => {
      if (succeeded) onRejected?.(result);
    },
  });
}

/** Cancel an own pending plan (vendor requesters only). */
export function openCancelDialog(plan, { onCancelled } = {}) {
  let succeeded = false;
  let result = null;
  return openDialog({
    title: t('gate.dialogs.cancel_title'),
    eyebrow: t('gate.dialogs.eyebrow'),
    description: t('gate.dialogs.cancel_description', { id: plan.plan_id }),
    actions: [
      { label: 'Abbrechen', variant: 'btn--ghost' },
      {
        label: t('gate.dialogs.cancel_submit'),
        variant: 'btn--danger',
        onClick: async (controller) => {
          try {
            result = await gateApi.cancelPlan(plan.plan_id);
            succeeded = true;
            return true;
          } catch (error) {
            controller.showError(gateErrorMessage(error));
            return false;
          }
        },
      },
    ],
    onClose: () => {
      if (succeeded) onCancelled?.(result);
    },
  });
}

export function openRevokeSessionDialog(session, { onRevoked } = {}) {
  let succeeded = false;
  let result = null;
  return openDialog({
    title: t('gate.dialogs.revoke_title'),
    eyebrow: t('gate.dialogs.eyebrow'),
    description: t('gate.dialogs.revoke_description'),
    content: el('div', { class: 'stack stack--tight' }, [
      el('p', { class: 'evidence-block__text', text: t('gate.denies.session_ref', { id: session.session_id }) }),
      el('p', { class: 'provenance', text: t('gate.dialogs.revoke_meta', { target: session.target_id || '—', source: session.source_ip || '—', user: session.user_id || '—' }) }),
      el('p', { class: 'provenance', text: t('gate.dialogs.revoke_usage', { time: formatDateTime(session.expires_at), uses: session.uses ?? 0, max: session.max_uses ?? 1 }) }),
    ]),
    actions: [
      { label: 'Abbrechen', variant: 'btn--ghost' },
      {
        label: t('gate.dialogs.revoke_submit'),
        variant: 'btn--danger',
        onClick: async (controller) => {
          try {
            result = await gateApi.revokeSession(session.session_id);
            succeeded = true;
            return true;
          } catch (error) {
            controller.showError(gateErrorMessage(error));
            return false;
          }
        },
      },
    ],
    onClose: () => {
      if (succeeded) onRevoked?.(result);
    },
  });
}

/**
 * One-time token reveal. The plaintext token exists only in this dialog (and in
 * the approval response memory); no clipboard automation, no URL, no logging,
 * no re-fetch. Closing the dialog discards it.
 */
export function openTokenRevealDialog({ token, expiresAt, plan }) {
  const content = el('div', { class: 'gate-token-reveal' });
  content.append(
    banner({
      variant: 'critical',
      title: t('gate.dialogs.token_banner_title'),
      text: t('gate.dialogs.token_banner_text'),
    }),
    el('code', { class: 'gate-token-reveal__value', text: token }),
    el('p', {
      class: 'provenance',
      text: t('gate.dialogs.token_validity', { time: formatDateTime(expiresAt) }),
    }),
    el('p', {
      class: 'provenance',
      text: t('gate.dialogs.token_warning'),
    })
  );
  if (plan && Array.isArray(plan.operations) && plan.operations.length > 0) {
    const list = el('ul', { class: 'gate-token-reveal__ops' });
    for (const op of plan.operations) {
      list.append(
        el('li', {
          text: `${op.function || '—'} · ${op.address || '—'} · ${op.current_value || '—'} → ${op.new_value || '—'}${
            op.unit ? ` ${unitLabel(op.unit) || op.unit}` : ''
          }`,
        })
      );
    }
    content.append(el('p', { class: 'provenance', text: t('gate.dialogs.token_operations', { count: plan.operations.length }) }), list);
  }
  content.append(
    el('p', { class: 'gate-token-reveal__plan' }, [
      icon('shield', { size: 'sm' }),
      el('span', { text: t('gate.dialogs.token_plan', { id: plan?.plan_id || '—', state: planStateLabel(plan?.state) }) }),
    ])
  );

  openDialog({
    title: t('gate.dialogs.token_title'),
    eyebrow: t('gate.dialogs.eyebrow_approval'),
    content,
    size: 'wide',
    actions: [{ label: t('gate.dialogs.token_discard'), primary: true }],
    initialFocus: 'button',
  });
}
