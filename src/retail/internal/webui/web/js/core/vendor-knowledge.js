/**
 * Defensive normalization for the optional manufacturer catalog API:
 * GET /vendors, GET /vendors/{family_id}, GET /regulatory-context.
 *
 * The catalog is optional. Every function tolerates missing fields and unknown
 * wrapper shapes so the UI can degrade to an explicit "catalog unavailable"
 * state instead of throwing. No value from this module authorises a write.
 */

function list(value) {
  return Array.isArray(value) ? value : [];
}

function str(value) {
  return value === undefined || value === null ? '' : String(value);
}

function normalizeProtocol(entry) {
  if (typeof entry === 'string') return { id: entry, name: entry };
  const item = entry || {};
  return {
    id: str(item.id || item.protocol || item.name),
    name: str(item.name || item.label || item.id || item.protocol),
    ports: list(item.ports || (item.default_port !== undefined ? [item.default_port] : [])).map(Number).filter(Number.isFinite),
    transport: str(item.transport),
    encryptedNative: item.encrypted_native === true,
  };
}

function normalizeFamily(entry) {
  const item = entry || {};
  return {
    id: str(item.id || item.family_id || item.device_family_id),
    vendorId: str(item.vendor_id || item.vendorId),
    name: str(item.name || item.family_name),
    category: str(item.category),
    protocols: list(item.protocols).map((protocol) => str(protocol)),
    ports: list(item.ports).map(Number).filter(Number.isFinite),
    managementInterface: str(item.management_interface),
    firmwareUpdate: str(item.firmware_update),
    lifecycle: str(item.lifecycle || item.lifecycle_state),
    notes: str(item.notes),
    sourceUrl: str(item.source_url),
    confidence: str(item.confidence),
    verification: str(item.verification),
    lastChecked: str(item.last_checked),
  };
}

function normalizeVendor(entry) {
  const item = entry || {};
  return {
    id: str(item.id || item.vendor_id || item.name),
    name: str(item.name || item.vendor_name || item.id),
    legalName: str(item.legal_name),
    country: str(item.country),
    role: str(item.role),
    focus: str(item.focus),
    sourceUrl: str(item.source_url),
    confidence: str(item.confidence),
  };
}

export function normalizeVendorCatalog(raw) {
  const data = raw && typeof raw === 'object' ? raw.data || raw : {};
  const vendors = list(data.vendors || data.items).map(normalizeVendor).filter((vendor) => vendor.id || vendor.name);
  const families = list(data.device_families || data.families).map(normalizeFamily).filter((family) => family.id || family.name);
  const protocols = list(data.protocols).map(normalizeProtocol).filter((protocol) => protocol.id || protocol.name);
  return {
    enabled: data.enabled !== false && data.disabled !== true && vendors.length + families.length > 0,
    vendors,
    families,
    protocols,
    schemaVersion: str(data.schema_version || data.catalog_version),
    lastChecked: str(data.last_checked),
  };
}

function normalizeSurface(entry) {
  const item = entry || {};
  const evidence = item.evidence || {};
  const operations = list(item.operations).map((operation) => {
    if (typeof operation === 'string') return operation;
    const target = str(operation.target || operation.name || operation.operation || operation.id || operation.kind);
    const kind = str(operation.kind || operation.operation || '');
    if (!target) return '';
    return kind && target !== kind ? `${kind} · ${target}` : target;
  }).filter(Boolean);
  return {
    id: str(item.id),
    scope: str(item.scope),
    protocol: str(item.protocol),
    transport: str(item.transport),
    port: item.port === undefined ? '' : str(item.port),
    operations,
    targetPattern: str(item.target_pattern),
    enforcement: str(item.enforcement),
    criticalChangeClasses: list(item.critical_change_classes).map(str),
    evidenceLevel: str(evidence.confidence || item.confidence || 'unknown'),
    evidenceSource: str(evidence.source_url || item.source_url),
    verification: str(evidence.verification || item.verification),
    notes: str(item.notes),
  };
}

export function normalizeVendorFamily(raw, catalog = null) {
  const data = raw && typeof raw === 'object' ? raw.data || raw : {};
  const nestedFamily = data.family || data.device_family;
  const family = normalizeFamily(nestedFamily || data);
  const vendor = normalizeVendor(data.vendor || (data.vendor_id ? { id: data.vendor_id } : {}));
  const vendorFromCatalog = catalog && catalog.vendors.find((entry) => entry.id === family.vendorId);
  const surfaces = list(data.write_surfaces || data.surfaces).map(normalizeSurface);
  const protocols = list(data.protocols).map(normalizeProtocol);
  return {
    enabled: data.enabled !== false,
    family,
    vendor: vendor.id || vendor.name ? vendor : vendorFromCatalog || { id: family.vendorId, name: family.vendorId },
    surfaces,
    protocols,
    lastChecked: str(data.last_checked),
    disabledReason: str(data.reason),
  };
}

export function normalizeRegulatoryContext(raw) {
  const data = raw && typeof raw === 'object' ? raw.data || raw : {};
  return {
    enabled: data.enabled !== false && data.disabled !== true,
    boundary: list(data.product_boundary_summary || data.boundary_summary).map(str).filter(Boolean),
    frameworks: list(data.frameworks).map((entry) => ({
      id: str(entry.id),
      name: str(entry.name),
      reference: str(entry.reference),
      jurisdiction: str(entry.jurisdiction),
      status: str(entry.status),
      productRole: str(entry.product_role),
      productConstraints: str(entry.product_constraints),
      sourceUrl: str(entry.source_url),
      confidence: str(entry.confidence),
    })),
    lastChecked: str(data.last_checked),
    disabledReason: str(data.reason),
  };
}

function normalizedText(value) {
  return str(value).toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
}

/**
 * Resolve the catalog family for one asset. Explicit family IDs win; otherwise
 * model/name match within the vendor's families. A vendor fallback is only used
 * when the vendor has exactly one documented family (no guessing).
 */
export function matchVendorFamily(catalog, asset) {
  if (!catalog || !catalog.enabled) return null;
  const explicit = str(asset.family_id || asset.vendor_family_id || asset.device_family_id);
  if (explicit) {
    const exact = catalog.families.find((family) => family.id === explicit);
    if (exact) return exact;
  }
  const vendorName = normalizedText(asset.vendor);
  const vendor = catalog.vendors.find(
    (entry) => normalizedText(entry.id) === vendorName || normalizedText(entry.name) === vendorName
  );
  const candidates = vendor ? catalog.families.filter((family) => family.vendorId === vendor.id) : catalog.families;
  const model = normalizedText(asset.model);
  if (model) {
    const scored = candidates
      .map((family) => {
        const familyName = normalizedText(family.name);
        if (!familyName) return { family, score: 0 };
        if (familyName === model) return { family, score: 4 };
        if (familyName.includes(model) || model.includes(familyName)) return { family, score: 3 };
        const modelTokens = new Set(model.split(' ').filter((token) => token.length > 2));
        const familyTokens = familyName.split(' ').filter((token) => token.length > 2);
        const overlap = familyTokens.filter((token) => modelTokens.has(token)).length;
        return { family, score: overlap > 0 ? 1 + overlap : 0 };
      })
      .filter((entry) => entry.score > 0)
      .sort((a, b) => b.score - a.score);
    if (scored.length && scored[0].score >= 3) return scored[0].family;
  }
  if (vendor && candidates.length === 1) return candidates[0];
  return null;
}

/** Lifecycle buckets rendered as current / legacy / EOL / unknown. */
export function lifecycleInfo(lifecycle) {
  const value = normalizedText(lifecycle);
  if (!value) return { state: 'unknown', label: lifecycle || '' };
  const eolMatch = String(lifecycle).match(/eol[_-]?(\d{4})(?:[_-](\d{2}))?/i);
  if (eolMatch) {
    return {
      state: 'eol',
      date: eolMatch[2] ? `${eolMatch[2]}/${eolMatch[1]}` : eolMatch[1],
      label: String(lifecycle),
    };
  }
  if (value.includes('legacy') || value.includes('supported')) return { state: 'legacy', label: String(lifecycle) };
  if (value === 'current' || value.includes('current')) return { state: 'current', label: String(lifecycle) };
  return { state: 'unknown', label: String(lifecycle) };
}

export function evidenceLevel(value) {
  const level = str(value).toLowerCase();
  return ['high', 'medium', 'low'].includes(level) ? level : 'unknown';
}
