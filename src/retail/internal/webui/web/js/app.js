/**
 * GeDefense Retail dashboard bootstrap.
 *
 * Responsibilities: token gate, initial data load, live SSE connection, hash
 * routing, view lifecycle and global failure handling. Views own their layout;
 * this module owns the frame and never renders domain data itself.
 */
import { api, setUnauthorizedHandler } from './core/api.js';
import { t, ruleTitle } from './i18n/index.js';
import { clearToken, getToken, isAuthenticated, setToken } from './core/auth.js';
import { el, clear } from './core/dom.js';
import {
  bumpData,
  getState,
  setCollectors,
  setConnection,
  setSites,
  subscribe,
  toast,
  updateState,
} from './core/store.js';
import { createStream } from './core/stream.js';
import { parseHash, startRouter } from './core/router.js';
import { closeInspector } from './components/inspector.js';
import { mountShell, gateIsOpen } from './components/shell.js';
import { initToasts } from './components/toast.js';
import { announce, errorState, skeletonChart, skeletonPage, skeletonTable } from './components/states.js';
import { sirduFigure } from './components/sirdu.js';
import { severityLabel, categoryLabel } from './core/labels.js';

import * as overviewView from './views/overview.js';
import * as siteView from './views/site.js';
import * as assetsView from './views/assets.js';
import * as coldchainView from './views/coldchain.js';
import * as accessView from './views/access.js';
import * as threatView from './views/threat.js';
import * as integrityView from './views/integrity.js';
import * as incidentsView from './views/incident.js';
import * as gateView from './views/gate/gate-view.js';
import * as setupView from './views/setup.js';

const VIEWS = {
  overview: overviewView,
  site: siteView,
  assets: assetsView,
  coldchain: coldchainView,
  access: accessView,
  gate: gateView,
  threat: threatView,
  integrity: integrityView,
  incidents: incidentsView,
  setup: setupView,
};

const appRoot = document.getElementById('app');

let shell = null;
let startupDone = false;
let routerStarted = false;
let currentCleanup = null;
let currentRoute = null;
let renderSequence = 0;
let healthTimer = 0;

initToasts();

const stream = createStream({
  onEvent: handleStreamEvent,
  onStatus: ({ status, detail }) => setConnection(status, detail),
});

const initialRoute = parseHash();
if (initialRoute.viewId === 'setup') {
  // First-run setup is a standalone shell: no dashboard chrome, no token gate.
  document.title = 'Setup — GeDefense Retail';
  appRoot.classList.add('app--setup');
  void setupView.mount({ root: appRoot, query: initialRoute.query });
} else {
  setUnauthorizedHandler(() => {
    if (gateIsOpen()) return;
    handleSessionExpired();
  });

  shell = mountShell({
    app: appRoot,
    onRefresh: () => {
      if (currentRoute) void renderRoute(currentRoute, { keepFocus: true });
    },
    onLogout: () => {
      logout();
    },
  });

  bootstrap();
}

/* --------------------------------------------------------------- bootstrap */

async function bootstrap() {
  if (!isAuthenticated()) {
    showLoginGate(t('app.login.required'));
    return;
  }
  const ok = await loadBootstrapData();
  if (!ok) {
    showLoginGate(t('app.login.stored_rejected'));
    return;
  }
  startApp();
}

/** Load meta/health/sites. Returns false when the token is not accepted. */
async function loadBootstrapData() {
  try {
    const [meta, health, sites] = await Promise.all([api.getMeta(), api.getHealth(), api.getSites()]);
    updateState({ meta, health });
    const items = Array.isArray(sites?.items) ? sites.items : [];
    setSites(items);
    setCollectors(Array.isArray(health?.collectors) ? health.collectors : []);
    return true;
  } catch (error) {
    if (error && error.status === 401) {
      clearToken();
      return false;
    }
    // Gateway unreachable (offline start): still open the shell; views will
    // show concrete errors and the connection badge stays offline.
    updateState({ error });
    setConnection(error?.status === 0 ? 'offline' : 'degraded', error?.message || '');
    return Boolean(getToken());
  }
}

function startApp() {
  if (!startupDone) {
    startupDone = true;
    stream.start();
    if (!routerStarted) {
      routerStarted = true;
      subscribe('site', () => {
        if (gateIsOpen()) return;
        void renderRoute(parseHash());
      });
      startRouter((route) => {
        void renderRoute(route);
      });
    }
    healthTimer = window.setInterval(pollHealth, 30_000);
  } else {
    stream.start();
    void renderRoute(parseHash());
  }
  shell.closeGate();
}

async function pollHealth() {
  if (!isAuthenticated() || gateIsOpen()) return;
  try {
    const health = await api.getHealth();
    updateState({ health });
    if (Array.isArray(health?.collectors)) setCollectors(health.collectors);
  } catch (error) {
    if (error && error.status === 401) {
      handleSessionExpired();
      return;
    }
    // A failed health poll does not tear down the view: the connection badge
    // and stale marker already communicate the degraded state.
  }
}

/* ------------------------------------------------------------------- gate */

function showLoginGate(message) {
  shell.openGate({
    message,
    onSubmit: async (token) => {
      setToken(token);
      try {
        const meta = await api.getMeta();
        updateState({ meta });
        return true;
      } catch (error) {
        clearToken();
        throw error;
      }
    },
    onSuccess: () => {
      void afterLogin();
    },
  });
}

async function afterLogin() {
  const ok = await loadBootstrapData();
  if (!ok) {
    showLoginGate(t('app.login.rejected_short'));
    return;
  }
  startApp();
  announce(t('app.login.success'));
}

function handleSessionExpired() {
  clearToken();
  stream.stop();
  setConnection('unauthorized', t('app.login.expired'));
  if (healthTimer) window.clearInterval(healthTimer);
  healthTimer = 0;
  startupDone = false;
  clearView();
  showLoginGate(t('app.session.expired'));
}

function logout() {
  clearToken();
  stream.stop();
  setConnection('idle', 'Abgemeldet');
  if (healthTimer) window.clearInterval(healthTimer);
  healthTimer = 0;
  startupDone = false;
  clearView();
  showLoginGate(t('app.logout.done'));
}

function clearView() {
  if (currentCleanup) {
    try {
      currentCleanup();
    } catch {
      /* view cleanup must not block logout */
    }
    currentCleanup = null;
  }
  if (shell) clear(shell.viewRoot);
}

/* ------------------------------------------------------------------ views */

function viewSkeleton(viewId) {
  if (viewId === 'assets' || viewId === 'integrity') return skeletonTable(8);
  if (viewId === 'coldchain') return skeletonChart();
  if (viewId === 'incidents' || viewId === 'threat') return skeletonPage(t('app.loading.incidents'));
  return skeletonPage();
}

async function renderRoute(route, { keepFocus = false } = {}) {
  if (route.viewId === 'setup') {
    window.location.reload();
    return;
  }
  if (!isAuthenticated() || gateIsOpen()) return;
  const view = VIEWS[route.viewId];
  currentRoute = route;

  // Close transient overlays of the previous view (never the token gate).
  closeInspector();
  for (const dialog of document.querySelectorAll('#overlay-root dialog[open]')) {
    if (!dialog.classList.contains('gate')) dialog.close();
  }

  if (currentCleanup) {
    try {
      currentCleanup();
    } catch {
      /* ignore cleanup failures */
    }
    currentCleanup = null;
  }

  const root = shell.viewRoot;
  clear(root);
  shell.setActiveView(route.viewId || '');

  if (!route.viewId) {
    root.append(
      el('div', { class: 'notfound' }, [
        sirduFigure('sirdu-404'),
        errorState({
          title: t('notfound.title'),
          text: t('app.notfound.text', { path: route.path }),
          actions: [el('a', { class: 'btn btn--primary', href: '#/overview', text: t('notfound.action') })],
        }),
      ])
    );
    return;
  }

  root.append(viewSkeleton(route.viewId));
  const sequence = ++renderSequence;

  try {
    const result = await view.mount({
      root,
      query: route.query,
      route,
      rerender: () => renderRoute(currentRoute || route),
    });
    if (sequence !== renderSequence) {
      // A newer navigation won the race; dispose this mount quietly.
      const destroy = typeof result === 'function' ? result : result && result.destroy;
      if (typeof destroy === 'function') destroy();
      return;
    }
    currentCleanup = typeof result === 'function' ? result : (result && result.destroy) || null;
    if (!keepFocus) shell.focusMain();
    bumpData();
  } catch (error) {
    if (sequence !== renderSequence) return;
    if (error && error.status === 401) {
      handleSessionExpired();
      return;
    }
    clear(root);
    root.append(
      errorState({
        title: t('app.error.view'),
        error,
        actions: [
          el('button', {
            type: 'button',
            class: 'btn btn--primary',
            text: t('common.retry'),
            on: { click: () => void renderRoute(route) },
          }),
        ],
      })
    );
  }
}

/* ----------------------------------------------------------------- stream */

function handleStreamEvent(event, data) {
  updateState({ lastStreamAt: Date.now() });

  if (event === 'alert' && data && typeof data === 'object') {
    const title = String(ruleTitle(data.rule_id, data.title) || t('app.alert.new'));
    toast({
      variant: 'alert',
      severity: data.severity || 'high',
      title: `Alarm: ${title}`,
      text: `${severityLabel(data.severity)} · ${categoryLabel(data.category)}`,
      timeout: 9000,
    });
    bumpData();
    return;
  }

  if (event === 'incident' && data && typeof data === 'object') {
    toast({
      variant: 'alert',
      severity: data.severity || 'critical',
      title: t('app.incident.title', { title: String(data.title || t('app.incident.title_fallback')) }),
      text: t('app.alert.incident_hint'),
      timeout: 9000,
    });
    bumpData();
    return;
  }

  if (event === 'health') {
    if (Array.isArray(data)) {
      setCollectors(data);
      const health = getState().health;
      if (health) updateState({ health: { ...health, collectors: data } });
    } else if (data && Array.isArray(data.collectors)) {
      setCollectors(data.collectors);
    }
    if (data && Number.isFinite(Number(data.dropped)) && Number(data.dropped) > 0) {
      toast({
        variant: 'warn',
        title: 'Live-Puffer',
        text: t('app.stream.dropped', { count: Number(data.dropped) }),
      });
    }
    updateState({ lastStreamAt: Date.now() });
    return;
  }

  if (event === 'event') {
    bumpData();
  }
}
