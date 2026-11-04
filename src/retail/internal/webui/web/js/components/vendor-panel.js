/**
 * "Herstellerwissen" panel for the asset inspector. Read-only manufacturer
 * knowledge from the optional catalog API: vendor, family, lifecycle, documented
 * management interfaces and write surfaces with evidence/source. It never
 * grants permissions and never edits anything; missing catalog degrades cleanly.
 */
import { api } from '../core/api.js';
import { el, clear } from '../core/dom.js';
import { t } from '../i18n/index.js';
import {
  evidenceLevel,
  lifecycleInfo,
  matchVendorFamily,
  normalizeRegulatoryContext,
  normalizeVendorCatalog,
  normalizeVendorFamily,
} from '../core/vendor-knowledge.js';
import { banner, skeletonPage } from './states.js';
import { detailGrid } from './panel.js';

const EVIDENCE_LABELS = {
  high: 'vendor.evidence.high',
  medium: 'vendor.evidence.medium',
  low: 'vendor.evidence.low',
  unknown: 'vendor.evidence.unknown',
};


function categoryLabel(category) {
  const value = String(category || '');
  if (!value) return t('vendor.unknown');
  return t(`vendor.category.${value}`, null, value.replace(/_/g, ' '));
}

const LIFECYCLE_LABELS = {
  current: 'vendor.lifecycle.current',
  legacy: 'vendor.lifecycle.legacy',
  eol: 'vendor.lifecycle.eol',
  unknown: 'vendor.lifecycle.unknown',
};

export function createVendorKnowledgePanel(asset) {
  const section = el('section', { class: 'vendor-panel', attrs: { 'aria-labelledby': 'vendor-panel-title' } });
  const heading = el('div', { class: 'vendor-panel__head' });
  heading.append(
    el('h3', { id: 'vendor-panel-title', class: 'vendor-panel__title', text: t('vendor.panel.title') }),
    el('span', { class: 'badge badge--muted', text: t('vendor.panel.readonly') })
  );
  section.append(heading, el('p', { class: 'provenance', text: t('vendor.panel.subtitle') }));
  const body = el('div', { class: 'vendor-panel__body', attrs: { 'aria-live': 'polite' } });
  section.append(body);
  void loadPanel(asset, body);
  return section;
}

async function loadPanel(asset, body) {
  renderLoading(body);
  const [catalogResult, regulatoryResult] = await Promise.allSettled([
    api.getVendors(),
    api.getRegulatoryContext(),
  ]);
  const catalog = catalogResult.status === 'fulfilled' ? normalizeVendorCatalog(catalogResult.value) : null;
  const regulatory = regulatoryResult.status === 'fulfilled' ? normalizeRegulatoryContext(regulatoryResult.value) : null;

  if (!catalog || !catalog.enabled) {
    renderDegraded(body, catalogResult, catalog, asset);
    return;
  }
  const family = matchVendorFamily(catalog, asset);
  if (!family) {
    renderNoFamily(body, asset, catalog);
    return;
  }
  renderLoading(body, t('vendor.panel.loading_detail', { family: family.name || family.id }));
  try {
    const detailRaw = await api.getVendorFamily(family.id);
    const detail = normalizeVendorFamily(detailRaw, catalog);
    clear(body);
    body.append(buildKnowledge(detail, catalog, regulatory));
  } catch {
    clear(body);
    body.append(
      banner({
        variant: 'warn',
        title: t('vendor.detail.error_title'),
        text: t('vendor.detail.error_text', { family: family.name || family.id }),
      })
    );
    body.append(
      el('button', {
        type: 'button',
        class: 'btn btn--secondary btn--sm',
        text: t('common.retry'),
        on: { click: () => void loadPanel(asset, body) },
      })
    );
  }
}

function renderLoading(body, message = null) {
  clear(body);
  body.append(skeletonPage(message || t('vendor.panel.loading'), { rows: 3 }));
}

function renderDegraded(body, result, catalog, asset) {
  clear(body);
  const reason = result.status === 'rejected'
    ? t('vendor.unavailable.network')
    : catalog && catalog.disabledReason
      ? catalog.disabledReason
      : t('vendor.unavailable.disabled');
  body.append(
    banner({
      variant: 'info',
      title: t('vendor.unavailable.title'),
      text: t('vendor.unavailable.text', { reason }),
    })
  );
  body.append(
    el('p', {
      class: 'provenance',
      text: t('vendor.empty.asset_hint', {
        vendor: asset.vendor || t('vendor.unknown'),
        model: asset.model || t('vendor.unknown'),
      }),
    })
  );
  if (result.status === 'rejected') {
    body.append(
      el('button', {
        type: 'button',
        class: 'btn btn--secondary btn--sm',
        text: t('common.retry'),
        on: { click: () => void loadPanel(asset, body) },
      })
    );
  }
}

function renderNoFamily(body, asset, catalog) {
  clear(body);
  const hasVendor = Boolean(asset.vendor || asset.model);
  body.append(
    el('div', { class: 'vendor-empty' }, [
      el('p', { class: 'vendor-empty__title', text: t('vendor.empty.title') }),
      el('p', {
        class: 'provenance',
        text: hasVendor
          ? t('vendor.empty.text', { vendor: asset.vendor || t('vendor.unknown'), model: asset.model || t('vendor.unknown') })
          : t('vendor.empty.text_unknown'),
      }),
      el('p', { class: 'provenance', text: t('vendor.catalog.version', { version: catalog.schemaVersion || '—', date: catalog.lastChecked || '—' }) }),
    ])
  );
}

function buildKnowledge(detail, catalog, regulatory) {
  const wrapper = el('div', { class: 'vendor-knowledge' });
  const family = detail.family || {};
  const vendor = detail.vendor || {};
  const lifecycle = lifecycleInfo(family.lifecycle);

  const meta = detailGrid([
    { label: t('vendor.field.vendor'), value: vendor.name || family.vendorId || t('vendor.unknown') },
    { label: t('vendor.field.family'), value: family.name || family.id || t('vendor.unknown') },
    { label: t('vendor.field.category'), value: categoryLabel(family.category) },
    {
      label: t('vendor.field.lifecycle'),
      value:
        lifecycle.state === 'eol'
          ? t('vendor.lifecycle.eol_since', { date: lifecycle.date || t('vendor.unknown') })
          : t(LIFECYCLE_LABELS[lifecycle.state] || LIFECYCLE_LABELS.unknown),
    },
  ]);
  wrapper.append(meta);

  if (lifecycle.state === 'eol') {
    wrapper.append(
      banner({
        variant: 'critical',
        title: t('vendor.lifecycle.eol_title'),
        text: t('vendor.lifecycle.eol_text', { date: lifecycle.date || t('vendor.unknown') }),
      })
    );
  } else if (lifecycle.state === 'legacy') {
    wrapper.append(
      banner({
        variant: 'warn',
        title: t('vendor.lifecycle.legacy_title'),
        text: t('vendor.lifecycle.legacy_text'),
      })
    );
  }

  wrapper.append(buildManagement(detail, family));
  wrapper.append(buildWriteSurfaces(detail.surfaces));
  wrapper.append(buildRegulatory(regulatory));
  wrapper.append(
    el('p', {
      class: 'provenance',
      text: t('vendor.catalog.provenance', {
        version: catalog.schemaVersion || '—',
        date: family.lastChecked || catalog.lastChecked || '—',
        confidence: family.confidence || t('vendor.unknown'),
        verification: family.verification || t('vendor.unknown'),
      }),
    })
  );
  return wrapper;
}

function buildManagement(detail, family) {
  const section = el('section', { class: 'vendor-section' });
  section.append(el('h4', { class: 'vendor-section__title', text: t('vendor.management.title') }));
  const protocols = detail.protocols.length
    ? detail.protocols
    : family.protocols.map((protocol) => ({ id: protocol, name: protocol }));
  const protocolChips = el('div', { class: 'cluster vendor-chips' });
  if (protocols.length === 0) {
    protocolChips.append(el('span', { class: 'provenance', text: t('vendor.management.none') }));
  } else {
    for (const protocol of protocols) {
      protocolChips.append(
        el('span', { class: 'chip chip--protocol', text: protocol.name || protocol.id, attrs: { title: protocol.transport || '' } })
      );
    }
  }
  section.append(
    detailGrid([
      { label: t('vendor.management.interface'), value: family.managementInterface || t('vendor.unknown') },
      { label: t('vendor.management.firmware'), value: family.firmwareUpdate || t('vendor.unknown') },
    ]),
    protocolChips
  );
  const ports = family.ports.length ? family.ports.join(', ') : t('vendor.unknown');
  section.append(el('p', { class: 'provenance', text: t('vendor.management.ports', { ports }) }));
  return section;
}

function buildWriteSurfaces(surfaces) {
  const section = el('section', { class: 'vendor-section' });
  section.append(
    el('h4', { class: 'vendor-section__title', text: t('vendor.write.title') }),
    banner({ variant: 'info', title: t('vendor.write.readonly_title'), text: t('vendor.write.note') })
  );
  if (!surfaces.length) {
    section.append(el('p', { class: 'provenance', text: t('vendor.write.empty') }));
    return section;
  }
  const list = el('div', { class: 'vendor-surface-list' });
  for (const surface of surfaces) {
    const row = el('article', { class: 'vendor-surface' });
    const head = el('div', { class: 'vendor-surface__head' });
    const level = evidenceLevel(surface.evidenceLevel);
    head.append(
      el('span', { class: 'vendor-surface__id mono', text: surface.id || surface.protocol || '—' }),
      el('span', { class: 'chip chip--protocol', text: surface.protocol || t('vendor.unknown') }),
      el('span', {
        class: 'chip chip--sev',
        dataset: { severity: level === 'unknown' ? 'info' : level },
        text: t(EVIDENCE_LABELS[level]),
      })
    );
    if (surface.scope) head.append(el('span', { class: 'chip chip--category', text: surface.scope }));
    row.append(head);
    if (surface.operations.length) {
      const ops = el('ul', { class: 'vendor-surface__ops' });
      for (const operation of surface.operations) ops.append(el('li', { text: operation }));
      row.append(el('p', { class: 'vendor-surface__label', text: t('vendor.write.operations') }), ops);
    }
    if (surface.targetPattern) {
      row.append(el('p', { class: 'provenance mono', text: t('vendor.write.target', { pattern: surface.targetPattern }) }));
    }
    const evidenceLine = el('div', { class: 'vendor-surface__evidence' });
    evidenceLine.append(el('span', { text: t('vendor.evidence.source') }));
    if (surface.evidenceSource) {
      evidenceLine.append(
        el('a', {
          class: 'vendor-source-link',
          href: surface.evidenceSource,
          text: surface.evidenceSource,
          attrs: { target: '_blank', rel: 'noopener noreferrer' },
        })
      );
    } else {
      evidenceLine.append(el('span', { class: 'provenance', text: t('vendor.unknown') }));
    }
    if (surface.verification) evidenceLine.append(el('span', { class: 'provenance', text: surface.verification }));
    row.append(evidenceLine);
    if (surface.enforcement) row.append(el('p', { class: 'provenance', text: surface.enforcement }));
    list.append(row);
  }
  section.append(list);
  return section;
}

function buildRegulatory(regulatory) {
  const section = el('section', { class: 'vendor-section vendor-regulatory' });
  section.append(el('h4', { class: 'vendor-section__title', text: t('vendor.regulatory.title') }));
  if (!regulatory || !regulatory.enabled) {
    section.append(el('p', { class: 'provenance', text: t('vendor.regulatory.empty') }));
    return section;
  }
  section.append(
    banner({
      variant: 'warn',
      title: t('vendor.regulatory.note_title'),
      text: t('vendor.regulatory.note'),
    })
  );
  if (regulatory.boundary.length) {
    const details = el('details', { class: 'vendor-regulatory__details' });
    details.append(el('summary', { text: t('vendor.regulatory.boundary') }));
    const list = el('ul', { class: 'vendor-regulatory__list' });
    for (const line of regulatory.boundary) list.append(el('li', { text: line }));
    details.append(list);
    section.append(details);
  }
  if (regulatory.frameworks.length) {
    const list = el('ul', { class: 'vendor-regulatory__list' });
    for (const framework of regulatory.frameworks.slice(0, 4)) {
      const item = el('li', {});
      item.append(el('span', { text: framework.name || framework.id }));
      if (framework.reference) item.append(el('span', { class: 'provenance', text: framework.reference }));
      list.append(item);
    }
    section.append(el('h5', { class: 'vendor-section__subtitle', text: t('vendor.regulatory.frameworks') }), list);
  }
  section.append(
    el('p', {
      class: 'provenance',
      text: t('vendor.regulatory.provenance', { date: regulatory.lastChecked || '—' }),
    })
  );
  return section;
}

