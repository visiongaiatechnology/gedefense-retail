/**
 * Access Gate view container. Extends the existing Glass shell with a dedicated
 * enforcement workbench (approval inbox, plan detail, sessions, deny timeline,
 * status). The gate has its own session and is strictly separate from the
 * passive monitoring UI: it documents approvals and never opens a write session.
 */
import { el, clear, render } from '../../core/dom.js';
import { gateApi, setGateUnauthorizedHandler } from '../../core/api.js';
import { clearGateToken, getGateToken } from '../../core/auth.js';
import { hrefFor } from '../../core/router.js';
import { protocolLabel } from '../../core/labels.js';
import { pageHeader } from '../../components/panel.js';
import { segmented } from '../../components/filters.js';
import { errorState, skeletonPage } from '../../components/states.js';
import { icon } from '../../core/icons.js';
import { renderGateLogin, gateSessionBar } from './gate-auth.js';
import { renderInbox } from './gate-inbox.js';
import { renderSessions } from './gate-sessions.js';
import { renderDenies } from './gate-denies.js';
import { renderStatus } from './gate-status.js';
import { t } from '../../i18n/index.js';

const TABS = [
  { value: 'inbox', label: t('gate.tab.inbox') },
  { value: 'sessions', label: t('gate.tab.sessions') },
  { value: 'denies', label: t('gate.tab.denies') },
  { value: 'status', label: t('gate.tab.status') },
];

const TAB_IDS = new Set(TABS.map((tab) => tab.value));

export async function mount({ root, query }) {
  const requestedTab = query.get('tab');
  const state = {
    tab: TAB_IDS.has(requestedTab) ? requestedTab : 'inbox',
    planId: query.get('plan') || '',
    me: null,
    health: null,
    status: null,
    authMessage: '',
    loading: true,
    error: null,
  };
  if (state.planId) state.tab = 'inbox';

  const view = el('div', { class: 'view view--gate' });
  const headerHost = el('div');
  const sessionHost = el('div');
  const tabsHost = el('div');
  const contentHost = el('div');
  view.append(headerHost, sessionHost, tabsHost, contentHost);
  render(root, view);

  setGateUnauthorizedHandler(() => {
    clearGateToken();
    state.me = null;
    state.authMessage = t('gate.auth.session_expired_mfa');
    renderAuth();
  });

  const ctx = {
    get me() {
      return state.me;
    },
    get health() {
      return state.health;
    },
    get status() {
      return state.status;
    },
    get planId() {
      return state.planId;
    },
    setPlanUrl(planId) {
      state.planId = planId || '';
      updateUrl();
    },
    setTab(tab) {
      if (!TAB_IDS.has(tab)) return;
      state.tab = tab;
      if (tab !== 'inbox') state.planId = '';
      updateUrl();
      void renderAll();
    },
    showPlan(planId) {
      state.planId = planId || '';
      state.tab = 'inbox';
      updateUrl();
      void renderAll();
    },
    targets() {
      const targets = state.status?.targets || state.health?.targets || [];
      return targets.map((target) => ({
        value: target.target_id,
        label: `${target.target_id} · ${protocolLabel(target.protocol)}`,
      }));
    },
    async reloadAll() {
      await refreshCore();
      await renderAll();
    },
    async reloadStatus() {
      try {
        state.status = await gateApi.status();
      } catch {
        /* status refresh is best effort */
      }
    },
  };

  function updateUrl() {
    const params = { tab: state.tab };
    if (state.tab === 'inbox' && state.planId) params.plan = state.planId;
    const target = hrefFor('gate', params);
    if (window.location.hash !== target) window.history.replaceState(null, '', target);
  }

  async function refreshCore() {
    const results = await Promise.allSettled([gateApi.me(), gateApi.health(), gateApi.status()]);
    const [meResult, healthResult, statusResult] = results;
    if (meResult.status === 'rejected') throw meResult.reason;
    if (healthResult.status === 'rejected') throw healthResult.reason;
    state.me = meResult.value;
    state.health = healthResult.value;
    // Status is role-dependent (approver/master_admin/auditor); a vendor session
    // may read own plans without status counters.
    state.status = statusResult.status === 'fulfilled' ? statusResult.value : null;
    state.error = null;
  }

  async function bootstrap() {
    state.loading = true;
    renderAll();
    try {
      await refreshCore();
      state.loading = false;
      await renderAll();
    } catch (error) {
      state.loading = false;
      if (error && error.status === 401) {
        clearGateToken();
        state.me = null;
        state.authMessage = t('gate.auth.session_invalid');
        renderAuth();
        return;
      }
      state.error = error;
      renderAll();
    }
  }

  function renderAuth() {
    clear(headerHost);
    headerHost.append(buildHeader(null));
    clear(sessionHost);
    clear(tabsHost);
    clear(contentHost);
    renderGateLogin(contentHost, {
      message: state.authMessage,
      health: state.health,
      onLoggedIn: () => {
        state.authMessage = '';
        void bootstrap();
      },
    });

  }

  async function renderAll() {
    if (!getGateToken()) {
      renderAuth();
      return;
    }
    clear(headerHost);
    headerHost.append(buildHeader(state.health));
    clear(sessionHost);
    if (state.me) {
      sessionHost.append(
        gateSessionBar(state.me, {
          onLogout: () => {
            state.me = null;
            state.authMessage = t('gate.auth.session_ended_relogin');
            renderAuth();
          },
        })
      );
    }
    clear(tabsHost);
    tabsHost.append(
      el('div', { class: 'gate-tabs' }, [
        segmented({
          label: t('gate.view.tabs_aria'),
          options: TABS,
          value: state.tab,
          onChange: (value) => {
            state.tab = value;
            if (value !== 'inbox') state.planId = '';
            updateUrl();
            void renderAll();
          },
        }),
      ])
    );

    clear(contentHost);
    if (state.loading) {
      contentHost.append(skeletonPage(t('gate.view.loading')));
      return;
    }
    if (state.error) {
      contentHost.append(
        errorState({
          title: t('gate.view.load_error_title'),
          error: state.error,
          actions: [
            el('button', {
              type: 'button',
              class: 'btn btn--primary',
              text: t('gate.common.reload'),
              on: { click: () => void bootstrap() },
            }),
            el('button', {
              type: 'button',
              class: 'btn btn--ghost',
              text: t('gate.auth.logout'),
              on: {
                click: () => {
                  clearGateToken();
                  state.me = null;
                  state.authMessage = t('gate.auth.session_ended');
                  renderAuth();
                },
              },
            }),
          ],
        })
      );
      return;
    }
    try {
      if (state.tab === 'inbox') await renderInbox(contentHost, ctx);
      else if (state.tab === 'sessions') await renderSessions(contentHost, ctx);
      else if (state.tab === 'denies') await renderDenies(contentHost, ctx);
      else await renderStatus(contentHost, ctx);
    } catch (error) {
      clear(contentHost);
      contentHost.append(
        errorState({
          title: t('gate.view.section_error_title'),
          error,
          actions: [
            el('button', {
              type: 'button',
              class: 'btn btn--primary',
              text: t('gate.common.reload'),
              on: { click: () => void renderAll() },
            }),
          ],
        })
      );
    }
  }

  function buildHeader(health) {
    const eyebrow = [
      el('span', { text: 'Access Gate' }),
      health
        ? el('span', {
            class: 'chip chip--status',
            dataset: { status: health.status === 'ok' ? 'resolved' : 'investigating' },
            text: health.status === 'ok' ? t('gate.status.online') : t('gate.status.degraded'),
          })
        : null,
      health ? el('span', { class: 'provenance mono', text: health.version || '' }) : null,
      el('span', { class: 'provenance', text: t('gate.view.eyebrow_default_deny') }),
    ].filter(Boolean);
    return pageHeader({
      eyebrow,
      title: 'Gate',
      subtitle: t('gate.view.subtitle'),
      actions: [
        el('button', {
          type: 'button',
          class: 'btn btn--ghost',
          attrs: { 'aria-label': t('gate.view.reload_aria') },
          on: { click: () => void bootstrap() },
        }, icon('refresh', { size: 'sm' }), el('span', { text: t('gate.common.reload') })),
      ],
    });
  }

  const cleanup = () => {
    setGateUnauthorizedHandler(() => {});
  };

  if (getGateToken()) {
    await bootstrap();
  } else {
    state.authMessage = t('gate.auth.prompt_mfa');
    renderAuth();
  }
  return cleanup;
}
