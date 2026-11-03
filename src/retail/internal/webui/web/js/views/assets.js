/**
 * Asset inventory — dense, filterable table of passively discovered OT devices.
 * Confidence and provenance stay visible per row; the row opens the detail
 * inspector instead of navigating away from the filter context.
 */
import { api } from '../core/api.js';
import { el, clear, render } from '../core/dom.js';
import { LIST_LIMIT } from '../core/config.js';
import { getSiteId, getSiteTimezone } from '../core/store.js';
import { formatDateTime, formatRelative } from '../core/format.js';
import {
  ASSET_TYPE_OPTIONS,
  CRITICALITY_OPTIONS,
  assetTypeLabel,
  criticalityLabel,
} from '../core/labels.js';
import { hrefFor } from '../core/router.js';
import { pageHeader, panel } from '../components/panel.js';
import { filterBar } from '../components/filters.js';
import { dataTable, rowOpenButton } from '../components/table.js';
import { emptyState, errorState, skeletonTable } from '../components/states.js';
import { assetTypeChip, confidenceMeter, criticalityChip, protocolChips, readOnlyBadge } from '../components/chips.js';
import { openAssetInspector } from '../components/asset-inspector.js';
import { icon } from '../core/icons.js';

import { t } from '../i18n/index.js';
const CRITICALITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

export async function mount({ root, query }) {
  const siteId = getSiteId();
  const timeZone = getSiteTimezone();

  if (!siteId) {
    render(
      root,
      el('div', { class: 'view' }, [
        el('h1', { class: 'view__title', text: t('view.overview.systems') }),
        emptyState({
          icon: 'layers',
          title: t('view.site.no_store_selected'),
          text: t('view.assets.select_a_store_above_without_a_store_context_the'),
          actions: [el('a', { class: 'btn btn--secondary', href: hrefFor('overview'), text: t('notfound.action') })],
        }),
      ])
    );
    return;
  }

  const state = {
    q: '',
    type: '',
    criticality: '',
    showRetired: false,
    sort: { key: 'last_seen_at', direction: 'descending' },
  };
  let lastItems = [];
  let zoneNames = new Map();
  let requestSeq = 0;

  const tableHost = el('div');
  const view = el('div', { class: 'view view--assets' });

  const filter = filterBar({
    fields: [
      { type: 'search', key: 'q', label: t('view.assets.search_systems'), placeholder: t('view.assets.name_vendor_or_model') },
      { type: 'select', key: 'type', label: t('view.assets.type'), value: '', options: [{ value: '', label: t('view.assets.all_types') }, ...ASSET_TYPE_OPTIONS] },
      {
        type: 'select',
        key: 'criticality',
        label: t('gate.inbox.risk_label'),
        value: '',
        options: [{ value: '', label: t('view.assets.all_levels') }, ...CRITICALITY_OPTIONS],
      },
      { type: 'checkbox', key: 'showRetired', label: t('view.assets.show_retired'), value: false },
    ],
    summary: t('view.assets.loading'),
    onChange: (key, value) => {
      if (key === 'showRetired') state.showRetired = value === '1';
      else state[key] = value;
      void loadTable();
    },
    actions: [
      el('button', {
        type: 'button',
        class: 'btn btn--ghost btn--sm',
        text: t('gate.denies.reset_filters'),
        on: { click: () => resetFilters() },
      }),
    ],
  });

  const panelNode = panel({
    title: t('view.assets.found_systems'),
    sub: t('view.assets.passive_discovery_classification_only_where_data'),
    actions: [
      el('button', {
        type: 'button',
        class: 'btn btn--ghost btn--sm',
        attrs: { 'aria-label': t('view.assets.reload_equipment') },
        on: { click: () => void loadTable() },
      }, icon('refresh', { size: 'sm' }), el('span', { text: t('nav.refresh') })),
    ],
    body: tableHost,
    flush: true,
  });

  view.append(
    pageHeader({
      eyebrow: [t('view.site.equipment_inventory'), readOnlyBadge(), el('span', { class: 'mono', text: siteId })],
      title: t('view.overview.systems'),
      subtitle:
        t('view.assets.passively_discovered_ot_inventory_with_confidenc'),
      actions: [
        el('a', { class: 'btn btn--ghost', href: hrefFor('site'), text: t('view.overview.open_store') }),
        el('a', { class: 'btn btn--primary', href: hrefFor('coldchain'), text: t('view.overview.check_cold_chain') }),
      ],
    }),
    filter.element,
    panelNode
  );

  render(root, view);
  await loadTable(query.get('asset') || '');

  function resetFilters() {
    state.q = '';
    state.type = '';
    state.criticality = '';
    state.showRetired = false;
    filter.setValue('q', '');
    filter.setValue('type', '');
    filter.setValue('criticality', '');
    filter.setValue('showRetired', false);
    void loadTable();
  }

  function sorted(items) {
    const direction = state.sort.direction === 'ascending' ? 1 : -1;
    const key = state.sort.key;
    const compare = (a, b) => {
      switch (key) {
        case 'name':
          return String(a.name || a.asset_id || '').localeCompare(String(b.name || b.asset_id || ''), 'de');
        case 'asset_type':
          return assetTypeLabel(a.asset_type).localeCompare(assetTypeLabel(b.asset_type), 'de');
        case 'criticality':
          return (CRITICALITY_RANK[a.criticality] || 0) - (CRITICALITY_RANK[b.criticality] || 0);
        case 'confidence':
          return Number(a.confidence || 0) - Number(b.confidence || 0);
        case 'zone_id':
          return String(zoneNames.get(a.zone_id) || a.zone_id || '').localeCompare(String(zoneNames.get(b.zone_id) || b.zone_id || ''), 'de');
        case 'last_seen_at':
        default:
          return new Date(a.last_seen_at || 0).getTime() - new Date(b.last_seen_at || 0).getTime();
      }
    };
    return [...items].sort((a, b) => compare(a, b) * direction);
  }

  function columns() {
    return [
      {
        key: 'name',
        label: t('gate.inbox.field_asset'),
        render: (asset) => {
          const wrapper = el('div');
          wrapper.append(
            rowOpenButton(
              asset.name || asset.asset_id,
              () => void openAssetInspector(asset.asset_id),
              [asset.vendor, asset.model].filter(Boolean).join(' · ') || asset.asset_id
            )
          );
          if (asset.retired) wrapper.append(el('span', { class: 'badge badge--muted', text: 'ausgemustert' }));
          return wrapper;
        },
      },
      { key: 'asset_type', label: t('view.assets.type'), render: (asset) => assetTypeChip(asset.asset_type) },
      {
        key: 'zone_id',
        label: t('view.assets.zone'),
        render: (asset) => el('span', { text: zoneNames.get(asset.zone_id) || asset.zone_id || '—' }),
      },
      { key: 'criticality', label: t('gate.inbox.risk_label'), render: (asset) => criticalityChip(asset.criticality) },
      {
        key: 'confidence',
        label: t('view.assets.confidence'),
        render: (asset) => confidenceMeter(asset.confidence, { label: t('view.assets.classification_confidence') }),
      },
      {
        key: 'protocols',
        label: t('view.assets.protocols'),
        render: (asset) => protocolChips((asset.protocols || []).slice(0, 2)),
      },
      {
        key: 'last_seen_at',
        label: t('view.site.last_seen'),
        render: (asset) =>
          el('span', {
            class: 'cell-num',
            text: asset.last_seen_at ? formatRelative(asset.last_seen_at) : '—',
            attrs: asset.last_seen_at ? { title: formatDateTime(asset.last_seen_at, timeZone) } : {},
          }),
      },
    ];
  }

  function onSort(key) {
    if (state.sort.key === key) {
      state.sort.direction = state.sort.direction === 'ascending' ? 'descending' : 'ascending';
    } else {
      state.sort = { key, direction: key === 'name' ? 'ascending' : 'descending' };
    }
    if (lastItems.length > 0) renderTable(sorted(lastItems));
  }

  function renderTable(items) {
    clear(tableHost);
    if (items.length === 0) {
      tableHost.append(emptyStateForCurrentState());
      return;
    }
    tableHost.append(
      dataTable({
        columns: columns(),
        rows: items,
        caption: t('view.assets.equipment_of_the_selected_store_details_via_the'),
        sort: state.sort,
        onSort,
      })
    );
  }

  function emptyStateForCurrentState() {
    const filtered = Boolean(state.q || state.type || state.criticality);
    if (filtered) {
      return el('div', { class: 'panel__body' }, [
        emptyState({
          icon: 'search',
          title: t('view.assets.no_results_for_these_filters'),
          text: t('view.assets.adjust_the_search_or_filters_the_search_applies'),
          actions: [
            el('button', { type: 'button', class: 'btn btn--primary', text: t('gate.denies.reset_filters'), on: { click: resetFilters } }),
          ],
        }),
      ]);
    }
    return el('div', { class: 'panel__body' }, [
      emptyState({
        icon: 'layers',
        title: t('view.assets.no_equipment_recorded_yet'),
        text: t('view.assets.the_inventory_is_built_from_passively_observed_f'),
        actions: [
          el('button', { type: 'button', class: 'btn btn--primary', text: t('view.overview.check_again'), on: { click: () => void loadTable() } }),
          el('a', { class: 'btn btn--ghost', href: hrefFor('site'), text: t('view.assets.check_store_context') }),
        ],
      }),
    ]);
  }

  async function loadTable(openAssetId = '') {
    const sequence = ++requestSeq;
    clear(tableHost);
    tableHost.append(el('div', { class: 'panel__body' }, skeletonTable(6)));
    filter.setSummary(t('view.assets.loading'));
    try {
      const [assetsResponse, siteResponse] = await Promise.all([
        api.getAssets({ site_id: siteId, q: state.q, type: state.type, limit: LIST_LIMIT }),
        api.getSite(siteId).catch(() => null),
      ]);
      if (sequence !== requestSeq) return;
      const zones = siteResponse?.zones || siteResponse?.site?.zones || [];
      zoneNames = new Map(zones.map((zone) => [zone.zone_id, zone.name]));
      let items = Array.isArray(assetsResponse.items) ? assetsResponse.items : [];
      if (!state.showRetired) items = items.filter((asset) => !asset.retired);
      if (state.criticality) items = items.filter((asset) => asset.criticality === state.criticality);
      lastItems = items;
      renderTable(sorted(items));
      filter.setSummary(t('view.assets.p1_of_p2_systems', { p1: items.length, p2: Number(assetsResponse.total ?? items.length) }));
      if (openAssetId) void openAssetInspector(openAssetId);
    } catch (error) {
      if (sequence !== requestSeq) return;
      clear(tableHost);
      tableHost.append(
        el('div', { class: 'panel__body' }, [
          errorState({
            title: t('view.assets.equipment_could_not_be_loaded'),
            error,
            actions: [
              el('button', { type: 'button', class: 'btn btn--primary', text: t('view.assets.reload'), on: { click: () => void loadTable() } }),
            ],
          }),
        ])
      );
      filter.setSummary(t('gate.common.error'));
    }
  }

  void criticalityLabel;
}
