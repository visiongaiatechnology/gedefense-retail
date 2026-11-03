/**
 * Site view — one store as a trust-boundary ladder. Zones are ordered from the
 * externally reachable maintenance path down to the OT process, because that
 * order is the operator's mental model for access risk.
 */
import { api } from '../core/api.js';
import { el, clear, render } from '../core/dom.js';
import { getSiteId, getSiteTimezone } from '../core/store.js';
import { formatDateTime, formatRelative, formatCount } from '../core/format.js';
import { ZONE_KIND_ORDER, zoneKindLabel } from '../core/labels.js';
import { hrefFor } from '../core/router.js';
import { detailGrid, pageHeader, panel } from '../components/panel.js';
import { emptyState } from '../components/states.js';
import {
  assetTypeChip,
  collectorStateChip,
  confidenceMeter,
  criticalityChip,
  readOnlyBadge,
  siteStatusChip,
} from '../components/chips.js';
import { openAssetInspector } from '../components/asset-inspector.js';
import { icon } from '../core/icons.js';

import { t } from '../i18n/index.js';
export async function mount({ root }) {
  const siteId = getSiteId();
  if (!siteId) {
    render(root, buildNoSite());
    return;
  }

  const timeZone = getSiteTimezone();
  const [detail, assetsResponse] = await Promise.all([
    api.getSite(siteId),
    api.getAssets({ site_id: siteId, limit: 200 }).catch(() => null),
  ]);
  const assets = Array.isArray(assetsResponse?.items) ? assetsResponse.items : [];
  const assetsUnavailable = assetsResponse === null;
  const site = detail?.site || {};
  const zones = Array.isArray(detail?.zones) ? detail.zones : Array.isArray(site.zones) ? site.zones : [];
  const counts = detail?.counts || {};
  const collectors = Array.isArray(detail?.collectors) ? detail.collectors : [];
  const orderedZones = orderZones(zones);

  let selectedZoneId = '';

  const view = el('div', { class: 'view view--site' });
  const ladderHost = el('div');
  const assetHost = el('div');

  const header = pageHeader({
    eyebrow: [
      siteStatusChip(site.status || 'unknown'),
      readOnlyBadge(),
      site.country ? el('span', { text: site.country }) : null,
      site.timezone ? el('span', { class: 'mono', text: site.timezone }) : null,
    ].filter(Boolean),
    title: site.name || siteId,
    subtitle:
      t('view.site.zones_as_trust_boundaries_from_external_maintena'),
    actions: [
      el('a', { class: 'btn btn--ghost', href: hrefFor('assets'), text: t('view.site.equipment_inventory') }),
      el('a', { class: 'btn btn--primary', href: hrefFor('coldchain'), text: t('view.overview.check_cold_chain') }),
    ],
  });

  const context = el('div', { class: 'site-context' });
  context.append(
    contextItem(t('view.overview.systems'), formatCount(counts.assets ?? assets.length)),
    contextItem(t('view.site.sensors'), formatCount(counts.sensors)),
    contextItem(t('view.overview.open_alerts'), formatCount(counts.open_alerts)),
    contextItem(t('view.site.policy_version'), detail?.policy_version != null ? String(detail.policy_version) : '—'),
    site.gateway_asset_id ? contextItem(t('view.site.gateway'), site.gateway_asset_id) : null,
    site.last_seen_at ? contextItem(t('view.site.last_seen'), formatRelative(site.last_seen_at)) : null
  );

  const ladderPanel = panel({
    title: t('view.site.zones_and_trust_boundaries'),
    sub: t('view.site.the_selection_filters_the_equipment_list_zones_a'),
    actions: [
      el('button', {
        type: 'button',
        class: 'btn btn--ghost btn--sm',
        text: t('view.site.all_zones'),
        on: { click: () => selectZone('') },
      }),
    ],
    body: ladderHost,
    flush: true,
  });

  const rail = el('aside', { class: 'view__rail view__rail--sticky', attrs: { 'aria-label': t('view.site.store_context') } });
  rail.append(
    panel({
      title: t('view.site.store_context'),
      body: detailGrid([
        { label: t('nav.site'), value: site.site_id || siteId, mono: true },
        { label: t('view.site.tenant'), value: site.tenant_id || '—', mono: true },
        { label: t('view.site.country'), value: site.country || '—' },
        { label: t('view.site.time_zone'), value: site.timezone || t('view.site.local_browser'), mono: true },
        { label: t('view.site.status'), value: site.status || t('view.site.unknown') },
        { label: t('view.site.gateway'), value: site.gateway_asset_id || '—', mono: true },
        { label: t('view.site.created'), value: formatDateTime(site.created_at, timeZone) },
        { label: t('view.site.updated'), value: formatDateTime(site.updated_at, timeZone) },
      ]),
    }),
    panel({
      title: t('view.overview.collectors'),
      sub: t('view.site.runtime_per_read_only_adapter'),
      body:
        collectors.length === 0
          ? el('p', { class: 'provenance', text: t('view.site.no_collectors_reported_for_this_store') })
          : buildCollectors(collectors, timeZone),
      flush: true,
    }),
    panel({
      title: 'Policy',
      body: el('div', { class: 'stack stack--tight' }, [
        el('p', { class: 'evidence-block__text', text: t('view.site.active_policy_version_p1', { p1: detail?.policy_version ?? '—' }) }),
        el('p', {
          class: 'provenance',
          text: t('view.site.limits_maintenance_rules_and_escalation_come_exc'),
        }),
      ]),
    })
  );

  const main = el('div', { class: 'view__main' });
  if (assetsUnavailable) {
    main.append(
      el('div', { class: 'banner banner--warn', attrs: { role: 'status' } }, [
        icon('warning', { size: 'sm' }),
        el('div', { class: 'banner__body' }, [
          el('span', { class: 'banner__title', text: t('view.site.equipment_list_unavailable') }),
          el('span', { class: 'banner__text', text: t('view.site.zone_counts_and_the_equipment_list_are_incomplet') }),
        ]),
      ])
    );
  }
  main.append(ladderPanel, assetHost);

  const grid = el('div', { class: 'view__grid' });
  grid.append(main, rail);
  view.append(header, context, grid);
  render(root, view);

  renderLadder();
  renderAssetPanel();

  function selectZone(zoneId) {
    selectedZoneId = zoneId;
    renderLadder();
    renderAssetPanel();
  }

  function renderLadder() {
    clear(ladderHost);
    ladderHost.append(
      orderedZones.length === 0
        ? el('div', { class: 'panel__body' }, [
            emptyState({
              icon: 'boundary',
              title: t('view.site.no_zones_configured'),
              text: t('view.site.zones_are_configured_in_the_gateway_under_site_z'),
            }),
          ])
        : buildLadder()
    );
  }

  function buildLadder() {
    const ladder = el('div', { class: 'zone-ladder', attrs: { role: 'group', 'aria-label': t('view.site.zones_by_trust_boundary') } });
    orderedZones.forEach((zone, index) => {
      const zoneAssets = assets.filter((asset) => asset.zone_id === zone.zone_id);
      const criticalAssets = zoneAssets.filter((asset) => asset.criticality === 'critical' || asset.criticality === 'high');
      const selected = zone.zone_id === selectedZoneId;
      const layer = el('button', {
        type: 'button',
        class: 'zone-layer',
        attrs: {
          'aria-pressed': selected ? 'true' : 'false',
          'aria-label': t('view.site.select_p1', { p1: zone.name || zone.zone_id }),
        },
        on: { click: () => selectZone(selected ? '' : zone.zone_id) },
      });

      const kind = el('span', { class: 'zone-layer__kind' });
      kind.append(
        el('span', { class: 'zone-layer__kind-label', text: `${index + 1}. ${zoneKindLabel(zone.kind)}` }),
        el('span', { class: 'zone-layer__name', text: zone.name || zone.zone_id })
      );

      const detail = el('span', { class: 'stack stack--tight' });
      if (zone.purpose) detail.append(el('span', { class: 'zone-layer__purpose', text: zone.purpose }));
      if (zone.operator_id) detail.append(el('span', { class: 'zone-layer__purpose', text: t('view.site.responsible_p1', { p1: zone.operator_id }) }));
      if (zone.kind === 'unknown') {
        detail.append(el('span', { class: 'zone-layer__flag', text: t('view.site.zone_unknown_operator_assignment_pending') }));
      }

      const countsNode = el('span', { class: 'zone-layer__counts' });
      const countParts = [
        el('span', {
          text: t('view.site.zone_asset_count', { p1: formatCount(zoneAssets.length), p2: zoneAssets.length === 1 ? t('view.site.asset_singular') : t('view.site.asset_plural') }),
        }),
      ];
      if (criticalAssets.length > 0) {
        countParts.push(
          el('span', { class: 'zone-layer__flag', text: t('view.site.p1_critical_high', { p1: formatCount(criticalAssets.length) }) })
        );
      }
      if (zone.critical) countParts.push(el('span', { class: 'zone-layer__flag', text: t('view.site.critical_zone') }));
      countsNode.append(...countParts);

      layer.append(kind, detail, countsNode);
      ladder.append(layer);
    });
    return ladder;
  }

  function renderAssetPanel() {
    const zone = orderedZones.find((entry) => entry.zone_id === selectedZoneId) || null;
    const list = zone ? assets.filter((asset) => asset.zone_id === zone.zone_id) : assets;
    const body =
      assetsUnavailable
        ? el('p', { class: 'panel__body', text: t('view.site.the_equipment_list_could_not_be_loaded') })
        : list.length === 0
          ? el('div', { class: 'panel__body' }, [
              emptyState({
                icon: 'layers',
                title: zone ? t('view.site.no_equipment_in_this_zone') : t('view.site.no_equipment_recorded'),
                text: zone
                  ? t('view.site.passive_discovery_has_not_yet_assigned_any_devic')
                  : t('view.site.the_inventory_is_built_from_passively_observed_f'),
                actions: [el('a', { class: 'btn btn--secondary', href: hrefFor('assets'), text: t('view.site.open_asset_inventory') })],
              }),
            ])
          : buildAssetRows(list, timeZone);

    const panelNode = panel({
      title: zone ? t('view.site.systems_in_p1', { p1: zone.name || zone.zone_id }) : t('view.site.all_equipment_of_the_store'),
      sub: t('view.site.asset_list_summary', { p1: formatCount(list.length), p2: assetsUnavailable ? t('view.site.incomplete_marker') : '' }),
      body,
      flush: true,
    });
    clear(assetHost);
    assetHost.append(panelNode);
  }
}

function buildAssetRows(assets, timeZone) {
  const list = el('div', { class: 'zone-assets' });
  for (const asset of assets) {
    const row = el('div', { class: 'zone-asset' });
    const main = el('div', { class: 'zone-asset__main' });
    const open = el('button', {
      type: 'button',
      class: 'row-open',
      text: asset.name || asset.asset_id,
      on: { click: () => void openAssetInspector(asset.asset_id) },
    });
    main.append(open);
    const meta = el('div', { class: 'zone-asset__meta' });
    meta.append(
      assetTypeChip(asset.asset_type),
      criticalityChip(asset.criticality),
      asset.vendor ? el('span', { text: asset.vendor }) : null,
      asset.last_seen_at
        ? el('span', { text: t('view.incident.last_p1_2', { p1: formatRelative(asset.last_seen_at) }), attrs: { title: formatDateTime(asset.last_seen_at, timeZone) } })
        : null
    );
    main.append(meta);
    const side = el('span', { class: 'cluster' });
    side.append(confidenceMeter(asset.confidence));
    row.append(main, side);
    list.append(row);
  }
  return list;
}

function buildCollectors(collectors, timeZone) {
  const list = el('div', { class: 'collector-list' });
  for (const collector of collectors) {
    const row = el('div', { class: 'collector-row' });
    const main = el('div', { class: 'collector-row__main' });
    main.append(
      el('span', { class: 'collector-row__id', text: collector.adapter_id || '—' }),
      el('span', {
        class: 'collector-row__counters',
        text: t('view.overview.events_p1_errors_p2_parser_p3', { p1: formatCount(collector.events), p2: formatCount(collector.errors), p3: formatCount(collector.parser_errors) }),
      }),
      el('span', {
        class: 'collector-row__counters',
        text: collector.last_event_at ? formatRelative(collector.last_event_at) : t('view.site.no_event_yet'),
        attrs: collector.last_event_at ? { title: formatDateTime(collector.last_event_at, timeZone) } : {},
      })
    );
    row.append(main, collectorStateChip(collector.state));
    list.append(row);
  }
  return list;
}

function contextItem(label, value) {
  const item = el('span', { class: 'site-context__item' });
  item.append(el('span', { text: `${label}: ` }), el('strong', { text: value }));
  return item;
}

function orderZones(zones) {
  const rank = new Map(ZONE_KIND_ORDER.map((kind, index) => [kind, index]));
  return [...zones].sort((a, b) => {
    const rankA = rank.has(a.kind) ? rank.get(a.kind) : ZONE_KIND_ORDER.length;
    const rankB = rank.has(b.kind) ? rank.get(b.kind) : ZONE_KIND_ORDER.length;
    if (rankA !== rankB) return rankA - rankB;
    return String(a.name || a.zone_id).localeCompare(String(b.name || b.zone_id), 'de');
  });
}

function buildNoSite() {
  const view = el('div', { class: 'view' });
  view.append(
    el('h1', { class: 'view__title', text: t('nav.site') }),
    emptyState({
      icon: 'store',
      title: t('view.site.no_store_selected'),
      text: t('view.site.select_a_store_above_the_gateway_provides_store'),
      actions: [el('a', { class: 'btn btn--primary', href: hrefFor('overview'), text: t('notfound.action') })],
    })
  );
  return view;
}
