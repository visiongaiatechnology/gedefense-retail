/**
 * Manufacturer-catalog fixture handler for the design-QA harness. Mirrors the
 * optional read-only API (GET /vendors, /vendors/{family_id},
 * /regulatory-context). `?state=empty` simulates a missing/disabled catalog.
 */
export function createVendorApiHandler({ loadFixture, jsonResponse, errorResponse }) {
  let catalogPromise = null;
  let regulatoryPromise = null;
  let writeSurfacesPromise = null;

  function loadCatalog() {
    if (!catalogPromise) catalogPromise = loadFixture('vendors.json');
    return catalogPromise;
  }
  function loadRegulatory() {
    if (!regulatoryPromise) regulatoryPromise = loadFixture('regulatory-context.json');
    return regulatoryPromise;
  }
  function loadWriteSurfaces() {
    if (!writeSurfacesPromise) writeSurfacesPromise = loadFixture('write-surfaces.json');
    return writeSurfacesPromise;
  }

  function disabled(reason) {
    return { enabled: false, reason };
  }

  return async function handleVendorRequest(path, method, params, init, config) {
    if (method !== 'GET') return errorResponse(405, 'method_not_allowed', 'vendor catalog is read-only');
    if (config.state === 'empty' || config.vendorsDisabled) {
      if (path === '/vendors' || path.startsWith('/vendors/') || path === '/regulatory-context') {
        return jsonResponse(disabled('catalog_missing'));
      }
    }
    if (path === '/vendors') {
      const catalog = await loadCatalog();
      return jsonResponse({
        enabled: true,
        schema_version: catalog.schema_version,
        last_checked: catalog.last_checked,
        vendors: catalog.vendors || [],
        device_families: catalog.device_families || [],
        protocols: catalog.protocols || [],
      });
    }
    if (path === '/regulatory-context') {
      const regulatory = await loadRegulatory();
      return jsonResponse({ enabled: true, ...regulatory });
    }
    const match = path.match(/^\/vendors\/([^/]+)$/);
    if (match) {
      const id = decodeURIComponent(match[1]);
      const [catalog, write] = await Promise.all([loadCatalog(), loadWriteSurfaces()]);
      const family = (catalog.device_families || []).find((entry) => entry.id === id);
      if (!family) return errorResponse(404, 'family_not_found', `vendor family ${id} not found`);
      const vendor = (catalog.vendors || []).find((entry) => entry.id === family.vendor_id) || null;
      const familyProtocols = new Set(family.protocols || []);
      const surfaces = (write.write_surfaces || []).filter(
        (surface) =>
          surface.device_family_id === id ||
          (surface.scope === 'protocol_generic' && familyProtocols.has(surface.protocol))
      );
      const protocols = (catalog.protocols || []).filter((protocol) => familyProtocols.has(protocol.id));
      return jsonResponse({
        enabled: true,
        last_checked: catalog.last_checked,
        family,
        vendor,
        protocols,
        write_surfaces: surfaces,
      });
    }
    return errorResponse(404, 'not_found', `Mock-Vendor-Endpunkt ${path} ist nicht implementiert.`);
  };
}
