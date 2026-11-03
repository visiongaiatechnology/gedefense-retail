/**
 * Operator actions. Each function is a thin, honest wrapper around an API
 * endpoint; callers own the dialog state and inline error presentation.
 */
import { api } from './api.js';
import { t } from '../i18n/index.js';

/** Download the authenticated incident evidence package. */
export async function downloadIncidentExport(incidentId) {
  const { blob, filename } = await api.exportIncident(incidentId);
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.rel = 'noopener';
  anchor.hidden = true;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 15_000);
  return filename;
}

export async function acknowledgeAlert(alertId, note = '') {
  const response = await api.ackAlert(alertId, note);
  return response && response.alert ? response.alert : null;
}

export async function assignAlert(alertId, assignee, note = '') {
  const response = await api.assignAlert(alertId, assignee, note);
  return response && response.alert ? response.alert : null;
}

export async function closeAlert(alertId, status, note = '') {
  const response = await api.closeAlert(alertId, status, note);
  return response && response.alert ? response.alert : null;
}

export async function addIncidentNote(incidentId, note) {
  const response = await api.addIncidentNote(incidentId, note);
  return response && response.incident ? response.incident : null;
}

/** German, actionable message for a failed operator action. */
export function actionErrorMessage(error) {
  if (!error) return 'Aktion fehlgeschlagen.';
  if (error.status === 401) return t('api.error.401');
  if (error.status === 403) return t('core.action.forbidden');
  if (error.status === 429) {
    return error.retryAfter > 0
      ? `Zu viele Anfragen. Erneut in ${error.retryAfter} s versuchen.`
      : 'Zu viele Anfragen. Bitte kurz warten.';
  }
  if (error.status === 404) return 'Das Objekt existiert nicht mehr. Ansicht wird neu geladen.';
  if (error.status === 0) return t('core.action.offline');
  return error.message || 'Aktion fehlgeschlagen.';
}
