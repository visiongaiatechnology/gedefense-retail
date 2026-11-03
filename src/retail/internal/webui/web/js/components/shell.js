/**
 * Application shell: navigation rail, command bar, content plane and the
 * provenance footer. Also owns the blocking token gate (sessionStorage token),
 * mobile navigation sheet, keyboard help and account menu.
 */
import { el, clear, focusNode } from '../core/dom.js';
import { t } from '../i18n/index.js';
import { icon } from '../core/icons.js';
import { NAV, NAV_BY_ID, STALE_AFTER_MS } from '../core/config.js';
import { formatClock, formatDateTime, formatUTC } from '../core/format.js';
import { installSirduEgg, sirduFigure } from './sirdu.js';
import { languageSelector } from './language-selector.js';
import { subscribe, getState, setSite } from '../core/store.js';
import { announce, banner, staleBanner } from './states.js';
import { readOnlyBadge } from './chips.js';
import { navigate, hrefFor } from '../core/router.js';
import {
  showTokenGate,
  closeGate as closeTokenGate,
  openAccountMenu,
  openHelp,
  openNavSheet,
} from './shell-overlays.js';

export { gateIsOpen } from './shell-overlays.js';

const CONNECTION_LABELS = {
  live: 'Live',
  connecting: 'Verbinde',
  reconnecting: 'Verbinde neu',
  degraded: t('conn.degraded'),
  offline: 'Offline',
  unauthorized: t('shell.state.unauthenticated'),
  idle: t('shell.state.inactive'),
};

let shellRefs = null;

/**
 * @param {{app: HTMLElement, onRefresh: ()=>void, onLogout: ()=>void, onNavigate?: (viewId:string)=>void}} options
 */
export function mountShell({ app, onRefresh, onLogout }) {
  const rail = buildRail();
  const topbar = buildTopbar({ onRefresh });
  const viewRoot = el('div', { class: 'main__inner', id: 'view-root' });
  const main = el('main', { class: 'main', id: 'main', tabindex: '-1' }, viewRoot);
  const statusbar = buildStatusbar();
  const bannerHost = el('div', { class: 'shell-banner', id: 'shell-banner' });
  const body = el('div', { class: 'app__body' }, topbar.element, bannerHost, main, statusbar.element);

  app.append(rail.element, body);

  const refs = {
    app,
    rail,
    topbar,
    main,
    viewRoot,
    statusbar,
    bannerHost,
    activeView: '',
    onRefresh,
    onLogout,
  };
  shellRefs = refs;

  // Navigation updates.
  subscribe('connection', () => updateConnection(refs));
  subscribe('data', () => updateFreshness(refs));
  subscribe('state', () => {
    updateSites(refs);
    updateAlertBadge();
    updateStatusbar(refs);
  });

  updateSites(refs);
  updateConnection(refs);
  updateFreshness(refs);
  updateStatusbar(refs);
  updateAlertBadge();

  installShortcuts(refs);
  installOnlineHint(refs);

  // Keep the "Stand" label honest even without new data events.
  window.setInterval(() => updateFreshness(refs), 15_000);

  return {
    viewRoot,
    main,
    setActiveView(viewId) {
      refs.activeView = viewId;
      rail.setActive(viewId);
      topbar.setActiveView(viewId);
      const item = NAV_BY_ID.get(viewId);
      document.title = item ? `${item.title} — GeDefense Retail` : 'GeDefense Retail';
    },
    focusMain() {
      focusNode(main);
    },
    onRefresh() {
      onRefresh?.();
    },
    openGate(options) {
      return showTokenGate(options);
    },
    closeGate() {
      closeTokenGate();
    },
    openAccountMenu() {
      openAccountMenu({ onLogout });
    },
    openHelp() {
      openHelp();
    },
    openNavSheet() {
      openNavSheet(refs);
    },
    raiseAlertCount(increment = 1) {
      const state = getState();
      state.openAlerts = Math.max(0, (state.openAlerts || 0) + increment);
      updateAlertBadge();
    },
  };
}

/* ------------------------------------------------------------------ rail */

function buildRail() {
  const element = el('aside', { class: 'app__rail', attrs: { 'aria-label': t('shell.nav.main') } });

  const brand = el('a', {
    class: 'brand',
    href: hrefFor('overview'),
    attrs: { 'aria-label': t('shell.brand.aria') },
  });
  brand.append(
    el('img', { class: 'brand__mark', attrs: { src: '/assets/gedefense-logo.png', alt: '', width: '34', height: '34' } }),
    el('span', { class: 'brand__text' }, [
      el('span', { class: 'brand__product', text: 'GeDefense' }),
      el('span', { class: 'brand__edition', text: 'Retail' }),
    ])
  );
  installSirduEgg(brand);
  element.append(brand);

  element.append(el('div', { class: 'rail__section-label', text: t('nav.operation') }));

  const nav = el('nav', { class: 'rail__nav', attrs: { 'aria-label': t('nav.views') } });
  const links = new Map();
  for (const item of NAV) {
    if (item.hidden) continue;
    const link = el('a', {
      class: ['rail__link', item.primary ? '' : 'rail__link--secondary'].filter(Boolean).join(' '),
      href: hrefFor(item.id),
      dataset: { view: item.id },
      attrs: { title: item.description, 'aria-label': item.primary ? undefined : item.title },
    });
    link.append(icon(item.icon), el('span', { class: 'rail__label', text: item.title }));
    if (item.id === 'threat') {
      const badge = el('span', { class: 'nav-badge', attrs: { hidden: true, attrs: { hidden: true, 'aria-label': t('view.overview.alertes_ouvertes') } } });
      link.append(badge);
    }
    const li = el('li', { class: item.primary ? 'rail__item' : 'rail__item rail__item--secondary' }, link);
    nav.append(li);
    links.set(item.id, link);
  }

  // Phone-only "Mehr" entry: opens the navigation sheet.
  const moreLink = el('button', {
    type: 'button',
    class: 'rail__link rail__more',
    attrs: { 'aria-label': t('shell.more.aria'), 'aria-haspopup': 'dialog' },
    on: { click: () => openNavSheet(shellRefs) },
  });
  moreLink.append(icon('more'), el('span', { class: 'rail__label', text: t('nav.more') }));
  nav.append(el('li', { class: 'rail__item rail__item--more' }, moreLink));
  element.append(nav);

  const footer = el('div', { class: 'rail__footer' });
  footer.append(languageSelector({ showLabel: true, compact: true }));
  const readonly = el('div', { class: 'rail__readonly' });
  readonly.append(icon('shield', { size: 'sm' }), el('span', { text: t('nav.readonly') }));
  footer.append(readonly);
  element.append(footer);

  return {
    element,
    setActive(viewId) {
      for (const [id, link] of links) {
        if (id === viewId) link.setAttribute('aria-current', 'page');
        else link.removeAttribute('aria-current');
      }
      for (const link of element.querySelectorAll('.sheet-nav__link')) {
        if (link.dataset.view === viewId) link.setAttribute('aria-current', 'page');
        else link.removeAttribute('aria-current');
      }
    },
  };
}

/* ---------------------------------------------------------------- topbar */

function buildTopbar({ onRefresh }) {
  const element = el('header', { class: 'topbar' });

  const brand = el('a', { class: 'topbar__brand', href: hrefFor('overview'), attrs: { 'aria-label': 'GeDefense Retail' } });
  brand.append(el('img', { class: 'brand__mark', attrs: { src: '/assets/gedefense-logo.png', alt: '', width: '28', height: '28' } }));

  const context = el('div', { class: 'topbar__context' });
  const siteField = el('div', { class: 'topbar__site' });
  const siteLabel = el('label', { class: 'sr-only', text: t('shell.site.select'), attrs: { for: 'site-select' } });
  const siteSelect = el('select', {
    id: 'site-select',
    class: 'select select--compact',
    attrs: { 'aria-label': t('shell.site.select') },
  });
  siteSelect.addEventListener('change', () => {
    setSite(siteSelect.value);
    announce(t('shell.site.changed', { site: siteSelect.options[siteSelect.selectedIndex]?.text || '' }));
  });
  siteField.append(siteLabel, siteSelect);
  context.append(siteField);

  const freshness = el('span', { class: 'topbar__freshness', attrs: { role: 'status' } });
  context.append(freshness);
  installSirduEgg(brand);
  element.append(brand, context);

  const actions = el('div', { class: 'topbar__actions' });

  const conn = el('span', { class: 'conn', dataset: { state: 'connecting' } });
  conn.append(el('span', { class: 'dot dot--pulse', attrs: { 'aria-hidden': 'true' } }), el('span', { class: 'conn__text', text: 'Verbinde' }));
  actions.append(conn);

  const refresh = iconButton(t('shell.action.refresh'), 'refresh', onRefresh);
  const help = iconButton(t('shell.action.help'), 'help', () => openHelp(), 'topbar__action--secondary');
  const lang = el('div', { class: 'topbar__lang' }, languageSelector({ compact: true }));
  const account = iconButton(t('nav.account'), 'user', () => openAccountMenu(onLogout), 'topbar__action--secondary');

  actions.append(lang, refresh, help, account);
  element.append(actions);

  return {
    element,
    siteSelect,
    freshness,
    conn,
    setActiveView(viewId) {
      const item = NAV_BY_ID.get(viewId);
      brand.setAttribute('aria-label', item ? `GeDefense Retail — ${item.title}` : 'GeDefense Retail');
    },
  };
}

function iconButton(label, iconName, handler, className = '') {
  const button = el('button', {
    type: 'button',
    class: ['btn btn--ghost btn--icon', className].filter(Boolean).join(' '),
    attrs: { 'aria-label': label, title: label },
  });
  button.append(icon(iconName));
  if (typeof handler === 'function') {
    button.__handler = handler;
    button.addEventListener('click', handler);
  }
  return button;
}

/* -------------------------------------------------------------- statusbar */

function buildStatusbar() {
  const element = el('footer', { class: 'statusbar', attrs: { 'aria-label': 'Produkt- und Datenprovenienz' } });
  const readonly = el('span', { class: 'statusbar__item' });
  readonly.append(readOnlyBadge());
  const product = el('span', { class: 'statusbar__item', text: 'GeDefense Retail' });
  const version = el('span', { class: 'statusbar__item', text: t('shell.version.loading') });
  const storage = el('span', { class: 'statusbar__item', text: '' });
  const audit = el('span', { class: 'statusbar__item', text: '' });
  const gateway = el('span', { class: 'statusbar__item', text: '' });
  const spacer = el('span', { class: 'statusbar__spacer' });
  const timezone = el('span', { class: 'statusbar__item', text: t('shell.statusbar.storage') });

  element.append(readonly, product, version, storage, audit, gateway, spacer, timezone);
  return { element, readonly, product, version, storage, audit, gateway };
}

/* ---------------------------------------------------------------- updates */

function updateSites(refs) {
  const state = getState();
  const select = refs.topbar.siteSelect;
  if (!select) return;
  clear(select);
  if (state.sites.length === 0) {
    select.append(el('option', { text: t('shell.site.none'), attrs: { value: '' } }));
    select.disabled = true;
    return;
  }
  select.disabled = false;
  for (const site of state.sites) {
    const option = el('option', {
      text: `${site.name} · ${site.site_id}`,
      attrs: { value: site.site_id },
    });
    if (site.site_id === state.siteId) option.selected = true;
    select.append(option);
  }
}

function updateConnection(refs) {
  const state = getState();
  const conn = refs.topbar.conn;
  if (!conn) return;
  conn.dataset.state = state.connection;
  conn.title = state.connectionDetail || '';
  const text = conn.querySelector('.conn__text');
  if (text) text.textContent = CONNECTION_LABELS[state.connection] || state.connection;
  const hasDetail = Boolean(state.connectionDetail);
  conn.setAttribute('aria-label', `Verbindungsstatus: ${CONNECTION_LABELS[state.connection] || state.connection}${hasDetail ? `. ${state.connectionDetail}` : ''}`);
  refs.app.dataset.connection = state.connection;
  updateFreshness(refs);
}

function updateFreshness(refs) {
  const state = getState();
  const node = refs.topbar.freshness;
  if (!node) return;
  clear(node);
  if (!state.lastDataAt) {
    node.append(el('span', { class: 'topbar__freshness-label', text: t('shell.freshness.none') }));
    updateShellBanner(refs);
    return;
  }
  const age = Date.now() - state.lastDataAt;
  const stale = age > STALE_AFTER_MS;
  const label = el('span', {
    class: stale ? 'topbar__freshness-label topbar__freshness-label--stale' : 'topbar__freshness-label',
    text: `Stand: ${formatClock(state.lastDataAt)}`,
    attrs: { title: `${formatDateTime(state.lastDataAt)} · ${formatUTC(state.lastDataAt)}` },
  });
  node.append(label);
  if (stale) node.append(el('span', { class: 'badge badge--muted', text: 'veraltet' }));
  updateShellBanner(refs);
}

/**
 * Persistent, non-blocking banner for offline, degraded and stale data. The
 * freshness value itself is never silently presented as current.
 */
function updateShellBanner(refs) {
  const host = refs.bannerHost;
  if (!host) return;
  const state = getState();
  clear(host);
  const stale = staleBanner(state.lastDataAt, { connection: state.connection });
  if (stale) {
    host.append(stale);
    return;
  }
  if (state.connection === 'offline' || state.connection === 'degraded' || state.connection === 'reconnecting') {
    const notice = banner({
      variant: state.connection === 'offline' ? 'critical' : 'warn',
      title: CONNECTION_LABELS[state.connection] || t('shell.banner.connection_title'),
      text: state.connectionDetail || t('shell.banner.connection_text'),
    });
    if (state.connection === 'offline') {
      host.append(el('div', { class: 'shell-banner__offline' }, [sirduFigure('sirdu-offline'), notice]));
    } else {
      host.append(notice);
    }
  }
}

function updateAlertBadge() {
  const state = getState();
  const count = Number(state.openAlerts) || 0;
  for (const badge of document.querySelectorAll('.nav-badge')) {
    if (count > 0) {
      badge.hidden = false;
      badge.textContent = count > 99 ? '99+' : String(count);
      badge.setAttribute('aria-label', t('common.open_alerts', { count }));
      badge.title = t('common.open_alerts', { count });
    } else {
      badge.hidden = true;
      badge.textContent = '';
    }
  }
}

function updateStatusbar(refs) {
  const state = getState();
  const status = refs.statusbar;
  if (!status) return;
  const meta = state.meta;
  const health = state.health;
  if (meta) {
    status.version.textContent = `Version ${meta.version || '—'} · API ${meta.http_api || 'v1'}`;
    status.product.textContent = meta.product || 'GeDefense Retail';
  }
  if (health) {
    status.storage.textContent = `Event-Store: ${health.storage?.events ?? '—'} · Alarme: ${health.storage?.alerts ?? '—'}`;
    status.audit.textContent = `Audit-Kette: ${health.storage?.audit_chain_ok ? 'verifiziert' : 'nicht verifiziert'}`;
    const collectors = Array.isArray(health.collectors) ? health.collectors.length : 0;
    const failed = Array.isArray(health.collectors) ? health.collectors.filter((c) => c.state === 'failed').length : 0;
    status.gateway.textContent = `Kollektoren: ${collectors - failed}/${collectors} aktiv`;
  }
  const capability = meta?.capabilities;
  if (capability && capability.read_only === false && !status.readonly.querySelector('.badge')) {
    status.readonly.append(el('span', { class: 'badge', text: t('shell.readonly.disabled') }));
  }
}


/* --------------------------------------------------------------- shortcuts */

function installShortcuts(refs) {
  window.addEventListener('keydown', (event) => {
    const target = event.target;
    const typing =
      target instanceof HTMLElement &&
      (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.tagName === 'SELECT' || target.isContentEditable);

    if (event.altKey && !event.ctrlKey && !event.metaKey) {
      if (event.key.toLowerCase() === 'r') {
        event.preventDefault();
        refs.onRefresh?.();
        return;
      }
      const index = Number(event.key) - 1;
      if (Number.isInteger(index) && index >= 0 && index < NAV.length) {
        event.preventDefault();
        navigate(NAV[index].id);
        return;
      }
    }

    if (typing) return;

    if (event.key === '?') {
      event.preventDefault();
      openHelp();
      return;
    }
    if (event.key === '/') {
      event.preventDefault();
      const search = document.querySelector('[data-primary-search]');
      if (search) focusNode(search);
    }
  });
}

function installOnlineHint(refs) {
  window.addEventListener('offline', () => {
    announce(t('shell.banner.offline_text'));
  });
  window.addEventListener('online', () => {
    announce('Netzwerkverbindung wiederhergestellt.');
    refs.onRefresh?.();
  });
}

