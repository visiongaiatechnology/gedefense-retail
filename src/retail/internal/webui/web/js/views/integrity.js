/**
 * Integrity view — configuration and firmware states with change and approval
 * status. GeDefense compares hashes/versions; it never writes configuration
 * back to a controller and never claims an approved state it cannot prove.
 */
import { api } from '../core/api.js';
import { el, clear, render } from '../core/dom.js';
import { getSiteId, getSiteTimezone } from '../core/store.js';
import { formatCount, formatDateTime, formatHash, formatRelative } from '../core/format.js';
import { integritySubjectLabel } from '../core/labels.js';
import { hrefFor } from '../core/router.js';
import { pageHeader, panel } from '../components/panel.js';
import { dataTable } from '../components/table.js';
import { emptyState } from '../components/states.js';
import { readOnlyBadge, severityChip } from '../components/chips.js';

import { t } from '../i18n/index.js';
export async function mount({ root }) {
  const siteId = getSiteId();
  if (!siteId) {
    render(root, buildNoSite());
    return;
  }

  const timeZone = getSiteTimezone();
  const [integrity, assetsResponse] = await Promise.all([
    api.getIntegrity({ site_id: siteId }),
    api.getAssets({ site_id: siteId, limit: 200 }).catch(() => null),
  ]);
  const items = Array.isArray(integrity.items) ? integrity.items : [];
  const changes = Array.isArray(integrity.changes) ? integrity.changes : [];
  const assetNames = new Map(
    (Array.isArray(assetsResponse?.items) ? assetsResponse.items : []).map((asset) => [asset.asset_id, asset.name || asset.asset_id])
  );

  const changed = items.filter((item) => item.changed);
  const unapproved = items.filter((item) => !item.approved);
  const changedUnapproved = items.filter((item) => item.changed && !item.approved);
  const lastChange = changes.reduce((latest, change) => {
    const at = new Date(change.at || 0).getTime();
    return at > latest ? at : latest;
  }, 0);

  const view = el('div', { class: 'view view--integrity' });

  const header = pageHeader({
    eyebrow: [t('nav.integrity'), readOnlyBadge()],
    title: t('nav.integrity'),
    subtitle:
      t('view.integrity.configuration_and_firmware_versions_with_change'),
    actions: [el('a', { class: 'btn btn--ghost', href: hrefFor('assets'), text: t('view.site.equipment_inventory') })],
  });

  const summary = el('section', { class: 'integrity-summary', attrs: { 'aria-label': t('view.integrity.integrity_metrics') } });
  summary.append(
    summaryItem(t('view.integrity.observed_subjects'), formatCount(items.length), ''),
    summaryItem(t('view.integrity.changed'), formatCount(changed.length), changed.length > 0 ? 'warning' : ''),
    summaryItem(
      t('view.integrity.unverified_approval'),
      formatCount(unapproved.length),
      unapproved.length > 0 ? 'critical' : 'success'
    ),
    summaryItem(t('view.integrity.changed_unverified'), formatCount(changedUnapproved.length), changedUnapproved.length > 0 ? 'critical' : 'success'),
    summaryItem(t('view.integrity.last_change'), lastChange > 0 ? formatRelative(new Date(lastChange).toISOString()) : '—', '')
  );

  const tableHost = el('div');
  const tablePanel = panel({
    title: t('view.integrity.integrity_versions'),
    sub: t('view.integrity.a_change_is_a_finding_approval_is_an_operator_de'),
    body: tableHost,
    flush: true,
  });

  const changesHost = el('div');
  const changesPanel = panel({
    title: t('view.integrity.change_history'),
    sub: t('view.integrity.chronological_with_reference_to_alerts'),
    body: changesHost,
    flush: true,
  });

  const safetyPanel = panel({
    title: t('view.integrity.boundaries'),
    body: el('div', { class: 'stack stack--tight' }, [
      el('p', {
        class: 'provenance',
        text: t('view.integrity.an_unapproved_status_does_not_automatically_mean'),
      }),
      el('p', {
        class: 'provenance',
        text: t('view.integrity.gedefense_does_not_write_configuration_back_and'),
      }),
      el('p', {
        class: 'provenance',
        text: t('view.integrity.firmware_details_appear_only_with_source_and_con'),
      }),
    ]),
  });

  const main = el('div', { class: 'view__main' });
  main.append(summary, tablePanel, changesPanel);
  const rail = el('aside', { class: 'view__rail view__rail--sticky', attrs: { 'aria-label': t('view.integrity.integrity_notices') } });
  rail.append(safetyPanel);

  const grid = el('div', { class: 'view__grid' });
  grid.append(main, rail);
  view.append(header, grid);
  render(root, view);

  renderTable();
  renderChanges();

  function renderTable() {
    clear(tableHost);
    if (items.length === 0) {
      tableHost.append(
        el('div', { class: 'panel__body' }, [
          emptyState({
            icon: 'shield',
            title: t('view.integrity.no_integrity_data_recorded'),
            text: t('view.integrity.integrity_versions_are_created_from_approved_rea'),
            actions: [
              el('a', { class: 'btn btn--ghost', href: hrefFor('assets'), text: t('view.integrity.check_asset_inventory') }),
              el('a', { class: 'btn btn--ghost', href: hrefFor('site'), text: t('view.assets.check_store_context') }),
            ],
          }),
        ])
      );
      return;
    }

    const columns = [
      {
        key: 'subject',
        label: t('view.integrity.subject'),
        render: (item) => {
          const wrapper = el('div');
          wrapper.append(
            el('span', { class: 'cell-primary', text: integritySubjectLabel(item.subject) }),
            el('span', { class: 'cell-sub mono', text: item.subject || '' })
          );
          return wrapper;
        },
      },
      {
        key: 'asset_id',
        label: t('gate.inbox.field_asset'),
        render: (item) => {
          const wrapper = el('div');
          wrapper.append(
            el('span', { text: assetNames.get(item.asset_id) || item.asset_id || '—' }),
            el('span', { class: 'cell-sub mono', text: item.asset_id || '' })
          );
          return wrapper;
        },
      },
      { key: 'zone_id', label: t('view.assets.zone'), render: (item) => item.zone_id || '—' },
      { key: 'version', label: t('view.integrity.version'), render: (item) => el('span', { class: 'mono', text: item.version || '—' }) },
      {
        key: 'sha256',
        label: t('view.integrity.sha_256'),
        render: (item) =>
          el('span', {
            class: 'hash',
            text: formatHash(item.sha256),
            attrs: item.sha256 ? { title: item.sha256 } : {},
          }),
      },
      {
        key: 'changed',
        label: t('view.integrity.changed'),
        render: (item) =>
          item.changed
            ? el('span', { class: 'chip chip--sev', dataset: { severity: 'high' }, text: t('view.integrity.changed_2') })
            : el('span', { class: 'chip chip--category', text: t('view.integrity.unchanged') }),
      },
      {
        key: 'approved',
        label: t('view.integrity.approval'),
        render: (item) =>
          item.approved
            ? el('span', { class: 'chip chip--sev', dataset: { severity: 'low' }, text: t('view.integrity.approved') })
            : el('span', { class: 'chip chip--sev', dataset: { severity: 'medium' }, text: t('view.integrity.unverified') }),
      },
      {
        key: 'last_seen_at',
        label: t('view.site.last_seen'),
        render: (item) =>
          el('span', {
            class: 'cell-num',
            text: item.last_seen_at ? formatRelative(item.last_seen_at) : '—',
            attrs: item.last_seen_at ? { title: formatDateTime(item.last_seen_at, timeZone) } : {},
          }),
      },
    ];

    tableHost.append(
      dataTable({
        columns,
        rows: items,
        caption: t('view.integrity.integrity_versions_of_the_store_unverified_is_an'),
      })
    );
  }

  function renderChanges() {
    clear(changesHost);
    if (changes.length === 0) {
      changesHost.append(el('div', { class: 'panel__body' }, el('p', { class: 'provenance', text: t('view.integrity.no_changes_in_the_observation_period') })));
      return;
    }
    const list = el('div');
    for (const change of [...changes].sort((a, b) => new Date(b.at || 0) - new Date(a.at || 0))) {
      const row = el('div', { class: 'change-row' });
      const main = el('div', { class: 'change-row__main' });
      main.append(
        el('div', { class: 'mini-list__title' }, [
          severityChip(change.approved ? 'low' : 'medium'),
          el('span', { text: integritySubjectLabel(change.subject) }),
          el('span', { class: 'mono provenance', text: change.subject || '' }),
        ]),
        el('div', { class: 'mini-list__meta' }, [
          el('span', { text: assetNames.get(change.asset_id) || change.asset_id || '—' }),
          el('span', { text: formatDateTime(change.at, timeZone) }),
          el('span', { text: change.approved ? t('view.integrity.approved') : t('view.integrity.not_approved') }),
        ])
      );
      row.append(main);
      if (change.alert_id) {
        row.append(
          el('a', {
            class: 'btn btn--ghost btn--sm',
            href: hrefFor('threat', { alert: change.alert_id }),
            text: t('view.integrity.open_alert'),
          })
        );
      }
      list.append(row);
    }
    changesHost.append(list);
  }
}

function summaryItem(label, value, tone) {
  const item = el('div', { class: 'integrity-summary__item' });
  item.append(
    el('span', { class: 'integrity-summary__label', text: label }),
    el('span', { class: 'integrity-summary__value', dataset: tone ? { tone } : {}, text: value })
  );
  return item;
}

function buildNoSite() {
  const view = el('div', { class: 'view' });
  view.append(
    el('h1', { class: 'view__title', text: t('nav.integrity') }),
    emptyState({
      icon: 'shield',
      title: t('view.site.no_store_selected'),
      text: t('view.integrity.select_a_store_above_to_see_integrity_versions'),
      actions: [el('a', { class: 'btn btn--primary', href: hrefFor('overview'), text: t('notfound.action') })],
    })
  );
  return view;
}
