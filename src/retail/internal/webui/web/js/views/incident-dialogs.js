/**
 * Operator workflow dialogs for one alert: acknowledge, assign, close. Each
 * dialog documents a workflow step; none of them changes plant behaviour.
 */
import { el } from '../core/dom.js';
import { NOTE_MAX_LENGTH } from '../core/config.js';
import { toast } from '../core/store.js';
import { openDialog } from '../components/dialog.js';
import { acknowledgeAlert, assignAlert, closeAlert } from '../core/actions.js';

import { t, ruleTitle } from '../i18n/index.js';
export function openAckDialog(alert, onChanged) {
  const content = el('div', { class: 'field' });
  content.append(
    el('label', { class: 'field__label', text: t('view.incident.note_optional'), attrs: { for: 'ack-note' } }),
    el('textarea', {
      id: 'ack-note',
      class: 'textarea',
      attrs: { rows: '3', maxlength: String(NOTE_MAX_LENGTH), placeholder: t('view.incident_dialogs.e_g_operator_informed') },
    }),
    el('p', { class: 'field__hint', text: t('view.incident_dialogs.audited_as_alert_ack_no_plant_effect') })
  );
  openDialog({
    title: t('view.incident_dialogs.acknowledge_alert'),
    eyebrow: t('view.incident_dialogs.alert_workflow'),
    description: t('view.incident_dialogs.alert_p1', { p1: ruleTitle(alert.rule_id, alert.title) || alert.alert_id }),
    content,
    actions: [
      { label: t('common.cancel'), variant: 'btn--ghost' },
      {
        label: t('view.incident.acknowledge'),
        primary: true,
        onClick: async () => {
          const note = document.getElementById('ack-note')?.value || '';
          await acknowledgeAlert(alert.alert_id, note);
          toast({ variant: 'success', title: t('view.incident_dialogs.alert_acknowledged'), text: ruleTitle(alert.rule_id, alert.title) || alert.alert_id });
          await onChanged();
        },
      },
    ],
  });
}

export function openAssignDialog(alert, onChanged) {
  const content = el('div', { class: 'field' });
  content.append(
    el('label', { class: 'field__label', text: t('view.incident_dialogs.responsible_user_id'), attrs: { for: 'assign-user' } }),
    el('input', {
      id: 'assign-user',
      class: 'input',
      attrs: { placeholder: t('view.incident_dialogs.user_id_from_the_gateway_configuration'), autocomplete: 'off' },
    }),
    el('p', { class: 'field__hint', text: t('view.incident_dialogs.the_user_must_be_active_in_the_gateway_unknown_i') }),
    el('label', { class: 'field__label', text: t('view.incident.note_optional'), attrs: { for: 'assign-note' } }),
    el('textarea', { id: 'assign-note', class: 'textarea', attrs: { rows: '2', maxlength: String(NOTE_MAX_LENGTH) } })
  );
  openDialog({
    title: t('view.incident_dialogs.assign_alert'),
    eyebrow: t('view.incident_dialogs.alert_workflow'),
    description: t('view.incident_dialogs.alert_p1', { p1: ruleTitle(alert.rule_id, alert.title) || alert.alert_id }),
    content,
    actions: [
      { label: t('common.cancel'), variant: 'btn--ghost' },
      {
        label: t('view.incident_dialogs.assign'),
        primary: true,
        onClick: async () => {
          const assignee = document.getElementById('assign-user')?.value.trim() || '';
          if (!assignee) throw new Error(t('view.incident_dialogs.please_enter_a_user_id'));
          const note = document.getElementById('assign-note')?.value || '';
          await assignAlert(alert.alert_id, assignee, note);
          toast({ variant: 'success', title: t('view.incident_dialogs.alert_assigned'), text: t('view.incident_dialogs.responsible_p1', { p1: assignee }) });
          await onChanged();
        },
      },
    ],
  });
}

export function openCloseDialog(alert, onChanged) {
  const content = el('div', { class: 'stack' });
  const select = el('select', { class: 'select', attrs: { 'aria-label': t('view.incident_dialogs.closing_status') } });
  for (const option of [
    { value: 'resolved', label: t('enum.alert_status.resolved') },
    { value: 'closed', label: t('enum.alert_status.closed') },
    { value: 'false_positive', label: t('view.incident_dialogs.false_positive') },
  ]) {
    select.append(el('option', { text: option.label, attrs: { value: option.value } }));
  }
  const noteField = el('div', { class: 'field' });
  noteField.append(
    el('label', { class: 'field__label', text: t('view.incident_dialogs.reason_note'), attrs: { for: 'close-note' } }),
    el('textarea', {
      id: 'close-note',
      class: 'textarea',
      attrs: { rows: '3', maxlength: String(NOTE_MAX_LENGTH), placeholder: t('view.incident_dialogs.e_g_vendor_misoperation_verified') },
    })
  );
  content.append(
    el('p', {
      class: 'provenance',
      text: t('view.incident_dialogs.closing_is_documentation_gedefense_does_not_trig'),
    }),
    select,
    noteField
  );
  openDialog({
    title: t('view.incident_dialogs.close_alert'),
    eyebrow: t('view.incident_dialogs.alert_workflow'),
    description: t('view.incident_dialogs.alert_p1', { p1: ruleTitle(alert.rule_id, alert.title) || alert.alert_id }),
    content,
    actions: [
      { label: t('common.cancel'), variant: 'btn--ghost' },
      {
        label: t('view.incident.close_case'),
        primary: true,
        onClick: async () => {
          const note = document.getElementById('close-note')?.value || '';
          if (!note.trim()) throw new Error(t('view.incident_dialogs.please_provide_a_reason'));
          const statusLabel = select.options[select.selectedIndex]?.text || select.value;
          await closeAlert(alert.alert_id, select.value, note);
          toast({ variant: 'success', title: t('view.incident_dialogs.alert_closed'), text: t('view.incident.status_p1', { p1: statusLabel }) });
          await onChanged();
        },
      },
    ],
  });
}
