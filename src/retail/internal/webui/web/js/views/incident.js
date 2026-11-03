/**
 * Incident workspace — the case file. Status, evidence, notes and the export
 * bundle are operator documentation. Every action is audited by the gateway and
 * never changes plant behaviour; the UI states this explicitly.
 */
import { api } from '../core/api.js';
import { el, clear, render } from '../core/dom.js';
import { getSiteId, getSiteTimezone, toast } from '../core/store.js';
import { NOTE_MAX_LENGTH } from '../core/config.js';
import { formatCount, formatDateTime, formatValue } from '../core/format.js';
import { INCIDENT_STATUS_OPTIONS, eventKindLabel, isOpenIncident, unitLabel } from '../core/labels.js';
import { hrefFor } from '../core/router.js';
import { detailGrid, pageHeader, panel } from '../components/panel.js';
import { dataTable } from '../components/table.js';
import { emptyState, errorState, inlineError, skeletonPage } from '../components/states.js';
import {
  alertStatusChip,
  confidenceMeter,
  incidentStatusChip,
  qualityChip,
  readOnlyBadge,
  severityChip,
} from '../components/chips.js';
import { correlationBlocks } from '../components/evidence.js';
import { openAckDialog, openAssignDialog, openCloseDialog } from './incident-dialogs.js';
import { actionErrorMessage, addIncidentNote, downloadIncidentExport } from '../core/actions.js';
import { icon } from '../core/icons.js';

import { t, ruleTitle } from '../i18n/index.js';
export async function mount({ root, query }) {
  const siteId = getSiteId();
  if (!siteId) {
    render(root, buildNoSite());
    return;
  }

  const timeZone = getSiteTimezone();
  const state = {
    statusFilter: '',
    selectedId: query.get('id') || '',
  };
  let incidents = [];
  let listRequest = 0;
  let detailRequest = 0;

  const listHost = el('div');
  const detailHost = el('div');
  const countLabel = el('span', { class: 'filterbar__result', text: '' });

  const statusSelect = el('select', { class: 'select', attrs: { 'aria-label': t('view.incident.filter_incidents_by_status') } });
  statusSelect.append(el('option', { text: t('view.incident.all_statuses'), attrs: { value: '' } }));
  for (const option of INCIDENT_STATUS_OPTIONS) {
    statusSelect.append(el('option', { text: option.label, attrs: { value: option.value } }));
  }
  statusSelect.addEventListener('change', () => {
    state.statusFilter = statusSelect.value;
    void loadList();
  });

  const header = pageHeader({
    eyebrow: [t('nav.incidents'), readOnlyBadge()],
    title: t('nav.incidents'),
    subtitle:
      t('view.incident.case_files_from_correlated_chains_status_evidenc'),
    actions: [el('a', { class: 'btn btn--ghost', href: hrefFor('threat'), text: t('view.threat.threat_timeline') })],
  });

  const listPanel = panel({
    title: t('view.incident.case_files'),
    sub: t('view.incident.correlated_chains_with_at_least_three_independen'),
    actions: [statusSelect, countLabel],
    body: listHost,
    flush: true,
  });

  const detailPanel = panel({
    title: t('view.threat.case_file'),
    sub: t('view.incident.status_evidence_notes_and_export'),
    body: detailHost,
  });

  const workspace = el('div', { class: 'incident-workspace' });
  workspace.append(listPanel, detailPanel);

  const view = el('div', { class: 'view view--incident' });
  view.append(header, workspace);
  render(root, view);

  await loadList();

  async function loadList() {
    const sequence = ++listRequest;
    clear(listHost);
    listHost.append(el('div', { class: 'panel__body' }, skeletonPage(t('view.incident.loading_incidents'))));
    try {
      const response = await api.getIncidents({ site_id: siteId, status: state.statusFilter || undefined, limit: 200 });
      if (sequence !== listRequest) return;
      incidents = Array.isArray(response.items) ? response.items : [];
      countLabel.textContent = t('view.incident.case_count', { p1: formatCount(incidents.length), p2: incidents.length === 1 ? t('view.incident.case_singular') : t('view.incident.case_plural') });
      renderList();

      const selectionExists = state.selectedId && incidents.some((incident) => incident.incident_id === state.selectedId);
      if (selectionExists) {
        await loadDetail(state.selectedId);
      } else if (incidents.length > 0) {
        const firstOpen = incidents.find((incident) => isOpenIncident(incident.status)) || incidents[0];
        state.selectedId = firstOpen.incident_id;
        renderList();
        await loadDetail(state.selectedId);
      } else {
        state.selectedId = '';
        clear(detailHost);
        detailHost.append(
          emptyState({
            icon: 'case',
            title: t('view.incident.no_incidents'),
            text: t('view.incident.incidents_arise_exclusively_from_correlated_chai'),
            actions: [el('a', { class: 'btn btn--secondary', href: hrefFor('threat'), text: t('view.incident.check_threat_timeline') })],
          })
        );
      }
    } catch (error) {
      if (sequence !== listRequest) return;
      clear(listHost);
      listHost.append(
        el('div', { class: 'panel__body' }, [
          errorState({
            title: t('view.incident.incidents_could_not_be_loaded'),
            error,
            actions: [el('button', { type: 'button', class: 'btn btn--primary', text: t('view.assets.reload'), on: { click: () => void loadList() } })],
          }),
        ])
      );
    }
  }

  function renderList() {
    clear(listHost);
    if (incidents.length === 0) {
      listHost.append(
        el('div', { class: 'panel__body' }, el('p', { class: 'provenance', text: t('view.incident.no_incidents_for_this_filter') }))
      );
      return;
    }
    const sorted = [...incidents].sort((a, b) => {
      const openDelta = Number(isOpenIncident(b.status)) - Number(isOpenIncident(a.status));
      if (openDelta !== 0) return openDelta;
      return new Date(b.last_seen_at || 0).getTime() - new Date(a.last_seen_at || 0).getTime();
    });
    for (const incident of sorted) {
      const selected = incident.incident_id === state.selectedId;
      const button = el('button', {
        type: 'button',
        class: 'incident-item',
        attrs: {
          'aria-current': selected ? 'true' : undefined,
          'aria-label': t('view.incident.open_case_file_p1', { p1: incident.title || incident.incident_id }),
        },
        on: {
          click: () => {
            state.selectedId = incident.incident_id;
            renderList();
            void loadDetail(incident.incident_id);
          },
        },
      });
      button.append(
        el('span', { class: 'incident-item__head' }, [severityChip(incident.severity), incidentStatusChip(incident.status)]),
        el('span', { class: 'incident-item__title', text: incident.title || t('view.incident.incident_without_title') }),
        el('span', { class: 'incident-item__meta' }, [
          el('span', { text: incident.incident_id }),
          el('span', { text: t('view.incident.last_p1_2', { p1: formatDateTime(incident.last_seen_at, timeZone) }) }),
          incident.assignee
            ? el('span', { text: t('view.incident_dialogs.responsible_p1', { p1: incident.assignee }) })
            : el('span', { text: t('view.incident.unassigned') }),
        ])
      );
      listHost.append(button);
    }
  }

  async function loadDetail(incidentId) {
    const sequence = ++detailRequest;
    clear(detailHost);
    detailHost.append(skeletonPage(t('view.incident.loading_case_file')));
    try {
      const data = await api.getIncident(incidentId);
      if (sequence !== detailRequest) return;
      renderDetail(data);
    } catch (error) {
      if (sequence !== detailRequest) return;
      clear(detailHost);
      detailHost.append(
        errorState({
          title: t('view.incident.case_file_could_not_be_loaded'),
          error,
          actions: [
            el('button', {
              type: 'button',
              class: 'btn btn--primary',
              text: t('view.assets.reload'),
              on: { click: () => void loadDetail(incidentId) },
            }),
          ],
        })
      );
    }
  }

  function renderDetail(data) {
    const incident = data.incident || {};
    const alerts = Array.isArray(data.alerts) ? data.alerts : [];
    const events = Array.isArray(data.events) ? data.events : [];
    clear(detailHost);

    const head = el('div', { class: 'incident-detail__head' });
    const headMain = el('div', { class: 'stack stack--tight' });
    headMain.append(
      el('div', { class: 'cluster' }, [
        severityChip(incident.severity),
        incidentStatusChip(incident.status),
        el('span', { class: 'mono provenance', text: incident.incident_id || '' }),
      ]),
      el('h3', { class: 'incident-detail__title', text: incident.title || t('view.incident.incident') }),
      el('div', { class: 'incident-detail__meta' }, [
        el('span', { text: t('view.incident.first_seen_p1', { p1: formatDateTime(incident.first_seen_at, timeZone) }) }),
        el('span', { text: t('view.incident.last_seen_p1', { p1: formatDateTime(incident.last_seen_at, timeZone) }) }),
        el('span', { text: incident.assignee ? t('view.incident_dialogs.responsible_p1', { p1: incident.assignee }) : t('view.incident.unassigned') }),
        el('span', { text: t('view.incident.store_p1', { p1: incident.site_id || siteId }) }),
      ])
    );
    head.append(headMain);

    const exportButton = el('button', {
      type: 'button',
      class: 'btn btn--primary',
      attrs: { 'aria-label': t('view.incident.export_incident_package_as_json') },
    });
    exportButton.append(icon('download', { size: 'sm' }), el('span', { text: t('view.incident.export_incident_package') }));
    exportButton.addEventListener('click', () => void handleExport(incident.incident_id, exportButton));
    head.append(exportButton);
    detailHost.append(head);

    detailHost.append(summaryBlock(incident));

    const alertsSection = el('section', { class: 'plane' });
    alertsSection.append(
      el('header', { class: 'panel__head' }, [
        el('div', {}, [
          el('h4', { class: 'panel__title', text: t('view.threat.linked_alerts') }),
          el('p', {
            class: 'panel__sub',
            text: t('view.incident.p1_alerts_workflow_documents_acknowledgement_no', { p1: formatCount(alerts.length) }),
          }),
        ]),
      ])
    );
    const alertsBody = el('div', { class: 'incident-alert-list' });
    if (alerts.length === 0) {
      alertsBody.append(el('div', { class: 'panel__body' }, el('p', { class: 'provenance', text: t('view.incident.no_alerts_linked') })));
    } else {
      for (const alert of alerts) alertsBody.append(buildAlertRow(alert, () => void loadList()));
    }
    alertsSection.append(alertsBody);
    detailHost.append(alertsSection);

    detailHost.append(notesBlock(incident));
    detailHost.append(eventsBlock(events));
    detailHost.append(
      el('p', {
        class: 'provenance',
        text: t('view.incident.the_export_contains_the_case_file_alerts_events'),
      })
    );
  }

  function summaryBlock(incident) {
    const section = el('section', { class: 'plane' });
    section.append(
      el('header', { class: 'panel__head' }, [
        el('div', {}, [
          el('h4', { class: 'panel__title', text: t('view.incident.summary_and_evidence') }),
          el('p', { class: 'panel__sub', text: t('view.incident.facts_hypothesis_and_recommended_check_strictly') }),
        ]),
      ])
    );
    const body = el('div', { class: 'panel__body stack' });
    body.append(el('p', { text: incident.summary || t('view.incident.no_summary_stored') }));
    const correlation = correlationBlocks(incident);
    if (correlation) body.append(correlation);
    if (Array.isArray(incident.alert_ids) && incident.alert_ids.length > 0) {
      body.append(
        detailGrid([
          { label: t('view.incident.alert_ids'), value: incident.alert_ids.join(', '), mono: true },
          {
            label: t('view.incident.zones'),
            value: Array.isArray(incident.zone_ids) && incident.zone_ids.length > 0 ? incident.zone_ids.join(', ') : '—',
            mono: true,
          },
          {
            label: t('view.overview.systems'),
            value: Array.isArray(incident.asset_ids) && incident.asset_ids.length > 0 ? incident.asset_ids.join(', ') : '—',
            mono: true,
          },
        ])
      );
    }
    section.append(body);
    return section;
  }

  function buildAlertRow(alert, onChanged) {
    const row = el('div', { class: 'incident-alert' });
    const main = el('div', { class: 'incident-alert__main' });
    main.append(
      el('div', { class: 'cluster' }, [
        severityChip(alert.severity),
        alertStatusChip(alert.status),
        confidenceMeter(alert.confidence, { label: t('view.threat.alert_confidence') }),
      ]),
      el('div', { class: 'incident-alert__title', text: ruleTitle(alert.rule_id, alert.title) || t('enum.timeline_kind.alert') }),
      el('div', { class: 'incident-alert__meta' }, [
        el('span', { class: 'mono', text: alert.alert_id || '' }),
        el('span', { text: alert.rule_id || '' }),
        el('span', { text: formatDateTime(alert.last_seen_at, timeZone) }),
        alert.assignee ? el('span', { text: t('view.incident_dialogs.responsible_p1', { p1: alert.assignee }) }) : null,
      ].filter(Boolean))
    );

    const actions = el('div', { class: 'incident-alert__actions' });
    actions.append(
      el('button', { type: 'button', class: 'btn btn--ghost btn--sm', text: t('view.incident.acknowledge'), on: { click: () => openAckDialog(alert, onChanged) } }),
      el('button', { type: 'button', class: 'btn btn--ghost btn--sm', text: t('view.incident_dialogs.assign'), on: { click: () => openAssignDialog(alert, onChanged) } }),
      el('button', { type: 'button', class: 'btn btn--ghost btn--sm', text: t('view.incident.close_case'), on: { click: () => openCloseDialog(alert, onChanged) } })
    );
    row.append(main, actions);
    return row;
  }

  function notesBlock(incident) {
    const section = el('section', { class: 'plane' });
    section.append(
      el('header', { class: 'panel__head' }, [
        el('div', {}, [
          el('h4', { class: 'panel__title', text: t('view.incident.notes') }),
          el('p', { class: 'panel__sub', text: t('view.incident.documentation_within_the_case_every_note_is_assi') }),
        ]),
      ])
    );
    const notes = Array.isArray(incident.notes) ? [...incident.notes] : [];
    const notesHost = el('div');
    if (notes.length === 0) {
      notesHost.append(el('div', { class: 'panel__body' }, el('p', { class: 'provenance', text: t('view.incident.no_notes_yet') })));
    } else {
      notes
        .sort((a, b) => Number(b.pinned) - Number(a.pinned) || new Date(b.at || 0) - new Date(a.at || 0))
        .forEach((note) => notesHost.append(buildNote(note)));
    }
    section.append(notesHost);

    const form = el('form', { class: 'incident-note-form', attrs: { 'aria-label': t('view.incident.add_note') } });
    const fieldId = `incident-note-${incident.incident_id || 'x'}`;
    form.append(el('label', { class: 'field__label', text: t('view.incident.new_note'), attrs: { for: fieldId } }));
    const textarea = el('textarea', {
      id: fieldId,
      class: 'textarea',
      attrs: { maxlength: String(NOTE_MAX_LENGTH), rows: '3', placeholder: t('view.incident.document_observation_check_step_or_feedback') },
    });
    const counter = el('span', { class: 'incident-note-form__count', text: `0 / ${NOTE_MAX_LENGTH}` });
    textarea.addEventListener('input', () => {
      counter.textContent = `${textarea.value.length} / ${NOTE_MAX_LENGTH}`;
    });
    const errorSlot = el('div');
    const row = el('div', { class: 'incident-note-form__row' });
    const submit = el('button', { type: 'submit', class: 'btn btn--primary btn--sm' });
    submit.append(icon('send', { size: 'sm' }), el('span', { text: t('view.incident.save_note') }));
    row.append(counter, submit);
    form.append(textarea, row, errorSlot);
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      clear(errorSlot);
      const note = textarea.value.trim();
      if (!note) {
        errorSlot.append(inlineError(t('view.incident.please_enter_a_note')));
        textarea.focus();
        return;
      }
      submit.disabled = true;
      submit.setAttribute('aria-busy', 'true');
      try {
        await addIncidentNote(incident.incident_id, note);
        toast({ variant: 'success', title: t('view.incident.note_saved'), text: t('view.incident.the_case_file_was_updated') });
        await loadDetail(incident.incident_id);
      } catch (error) {
        errorSlot.append(inlineError(actionErrorMessage(error)));
      } finally {
        submit.disabled = false;
        submit.removeAttribute('aria-busy');
      }
    });
    section.append(form);
    return section;
  }

  function buildNote(note) {
    const node = el('div', { class: note.pinned ? 'note note--pinned' : 'note' });
    const meta = el('div', { class: 'note__meta' });
    meta.append(
      el('span', { text: note.actor || t('view.site.unknown') }),
      note.role ? el('span', { class: 'chip chip--category', text: note.role }) : null,
      el('span', { text: formatDateTime(note.at, timeZone) }),
      note.pinned ? el('span', { class: 'badge badge--accent', text: 'angeheftet' }) : null
    );
    node.append(meta, el('p', { class: 'note__text', text: note.note || '' }));
    return node;
  }

  function eventsBlock(events) {
    const section = el('section', { class: 'plane' });
    section.append(
      el('header', { class: 'panel__head' }, [
        el('div', {}, [
          el('h4', { class: 'panel__title', text: t('view.incident.events_in_the_case_period') }),
          el('p', { class: 'panel__sub', text: t('view.incident.p1_of_at_most_200_events', { p1: formatCount(events.length) }) }),
        ]),
      ])
    );
    if (events.length === 0) {
      section.append(el('div', { class: 'panel__body' }, el('p', { class: 'provenance', text: t('view.incident.no_events_in_the_case_period') })));
      return section;
    }
    const columns = [
      {
        key: 'observed_at',
        label: t('view.threat.timestamp'),
        render: (event) => el('span', { class: 'cell-num', text: formatDateTime(event.observed_at, timeZone) }),
      },
      { key: 'kind', label: t('view.assets.type'), render: (event) => eventKindLabel(event.kind) },
      {
        key: 'asset_id',
        label: t('gate.inbox.field_asset'),
        render: (event) => el('span', { class: 'mono', text: event.asset_id || event.sensor_id || '—' }),
      },
      {
        key: 'measurement',
        label: t('view.incident.measured_value'),
        render: (event) =>
          event.measurement ? formatValue(event.measurement.value, unitLabel(event.measurement.unit), 1) : '—',
      },
      { key: 'quality', label: t('view.incident.quality'), render: (event) => (event.quality ? qualityChip(event.quality) : '—') },
      {
        key: 'source',
        label: t('view.incident.source'),
        render: (event) => el('span', { class: 'mono', text: event.source || '—' }),
      },
    ];
    section.append(dataTable({ columns, rows: events, caption: t('view.incident.events_of_the_case_period_data_minimisation_no_p') }));
    return section;
  }

  async function handleExport(incidentId, button) {
    button.disabled = true;
    button.setAttribute('aria-busy', 'true');
    try {
      const filename = await downloadIncidentExport(incidentId);
      toast({ variant: 'success', title: t('view.incident.export_created'), text: t('view.incident.file_p1', { p1: filename }) });
    } catch (error) {
      toast({ variant: 'warn', title: t('view.incident.export_failed'), text: actionErrorMessage(error) });
    } finally {
      button.disabled = false;
      button.removeAttribute('aria-busy');
    }
  }
}

function buildNoSite() {
  const view = el('div', { class: 'view' });
  view.append(
    el('h1', { class: 'view__title', text: t('nav.incidents') }),
    emptyState({
      icon: 'case',
      title: t('view.site.no_store_selected'),
      text: t('view.incident.select_a_store_above_to_see_case_files'),
      actions: [el('a', { class: 'btn btn--primary', href: hrefFor('overview'), text: t('notfound.action') })],
    })
  );
  return view;
}
