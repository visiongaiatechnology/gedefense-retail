/**
 * First-run setup wizard (#/setup). Standalone shell: no dashboard chrome, no
 * monitoring token, loopback-only server API. Six steps per
 * setup-and-whitelist-contract.md §6. Admin token is shown once in memory only.
 */
import { el, clear, focusNode } from '../core/dom.js';
import { setupApi } from '../core/setup-api.js';
import { errorState, inlineError, skeletonPage } from '../components/states.js';
import { icon } from '../core/icons.js';
import { getLanguage, hasExplicitLanguage, isLanguage, setLanguage, t } from '../i18n/index.js';
import { buildStep, errorText } from './setup/setup-steps.js';
import {
  buildHeader,
  buildStepper,
  buildFooter,
  renderCompleted,
  renderEnded,
  renderLoadError,
  openAbortDialog,
} from './setup/setup-shell.js';

const STEPS = ['language', 'site', 'whitelist', 'admin', 'collectors', 'summary'];
const FALLBACK_COLLECTORS = [
  { id: 'modbus', name: 'Modbus TCP', hint: t('setup.collector.modbus_hint') },
  { id: 'pcap', name: 'PCAP', hint: t('setup.collector.pcap_hint') },
  { id: 'mqtt', name: 'MQTT', hint: t('setup.collector.mqtt_hint') },
  { id: 'bacnet', name: 'BACnet/IP', hint: t('setup.collector.bacnet_hint') },
  { id: 'snmp', name: 'SNMP', hint: t('setup.collector.snmp_hint') },
];

const view = {
  root: null,
  step: 0,
  data: null,
  token: '',
  busy: false,
  error: '',
  abortOpen: false,
  sessionExpired: false,
};

/**
 * Shared context for the step builders. Keeping navigation and persistence in
 * the container avoids a circular import between wizard and steps.
 */
const stepContext = {
  get view() {
    return view;
  },
  render,
  goStep,
  saveStep,
  complete: completeSetup,
};

export async function mount({ root, query }) {
  view.root = root;
  view.step = clampStep(Number(query.get('step') || 0));
  clear(root);
  root.append(el('div', { class: 'setup-app', id: 'setup-app' }, skeletonPage(t('common.loading'))));
  const onHash = () => {
    if (!window.location.hash.includes('/setup')) window.location.reload();
  };
  window.addEventListener('hashchange', onHash);
  try {
    view.data = normalize(await setupApi.getState());
  } catch (error) {
    renderLoadError(view, error);
    return () => window.removeEventListener('hashchange', onHash);
  }
  if (view.data.completed) {
    renderEnded(view);
    return () => window.removeEventListener('hashchange', onHash);
  }
  if (!hasExplicitLanguage() && isLanguage(view.data.language)) setLanguage(view.data.language, { persist: false });
  render();
  return () => window.removeEventListener('hashchange', onHash);
}

function clampStep(step) {
  if (!Number.isFinite(step)) return 0;
  return Math.max(0, Math.min(STEPS.length - 1, step));
}

function normalize(data) {
  const raw = data || {};
  const site = raw.site || null;
  const whitelist = Array.isArray(raw.whitelist_cidrs)
    ? raw.whitelist_cidrs
    : Array.isArray(raw.cidrs)
      ? raw.cidrs
      : [];
  const supported = Array.isArray(raw.supported_collectors) && raw.supported_collectors.length
    ? raw.supported_collectors
    : FALLBACK_COLLECTORS;
  return {
    completed: Boolean(raw.completed),
    completedAt: raw.completed_at || '',
    language: raw.language || getLanguage(),
    remoteIp: raw.remote_ip || raw.remoteIp || '',
    loopback: raw.loopback !== false,
    site,
    whitelist,
    adminCreated: Boolean(raw.admin_created || raw.adminCreated),
    collectors: Array.isArray(raw.collectors) ? raw.collectors : [],
    supported,
    bindHint: raw.bind_hint || '',
  };
}

/* --------------------------------------------------------------- rendering */

function render() {
  if (!view.root) return;
  clear(view.root);
  const app = el('div', { class: 'setup-app', id: 'setup-app' });
  app.append(buildHeader(view, render), buildMain(), buildFooter());
  view.root.append(app);
  applyStepUrl();
}

function buildMain() {
  const main = el('main', { class: 'setup-main', id: 'setup-main', tabindex: '-1' });
  const intro = el('div', { class: 'setup-intro' });
  intro.append(
    el('p', { class: 'setup-intro__kicker', text: t('setup.product') }),
    el('h1', { class: 'setup-intro__title', text: t('setup.title') }),
    el('p', { class: 'setup-intro__text', text: t('setup.subtitle') })
  );
  main.append(intro, buildStepper(view, STEPS));

  const card = el('section', { class: 'setup-card plane plane--focus', attrs: { 'aria-labelledby': 'setup-step-title' } });
  const current = STEPS[view.step];
  const cardHead = el('div', { class: 'setup-card__head' });
  cardHead.append(
    el('div', { class: 'setup-card__titles' }, [
      el('p', { class: 'setup-card__step', text: t('setup.stepOf', { current: view.step + 1, total: STEPS.length }) }),
      el('h2', { id: 'setup-step-title', class: 'setup-card__title', text: t(`setup.step.${current}`) }),
    ]),
    el('span', { class: 'setup-card__marker' }, [
      el('span', { class: 'setup-card__marker-value', text: String(view.step + 1).padStart(2, '0') }),
      el('span', { class: 'setup-card__marker-label', text: t(`setup.step.${current}`) }),
    ])
  );
  card.append(cardHead);
  const errorSlot = el('div', { class: 'setup-card__error' });
  if (view.error) errorSlot.append(inlineError(view.error));
  if (view.sessionExpired) {
    errorSlot.append(
      el('button', {
        type: 'button',
        class: 'btn btn--secondary btn--sm',
        text: t('setup.reload', null, 'Seite neu laden'),
        on: { click: () => window.location.reload() },
      })
    );
  }
  card.append(errorSlot);

  const body = el('div', { class: 'setup-card__body' });
  const stepView = buildStep(current, body, errorSlot, stepContext);
  card.append(body);
  card.append(buildCardFooter(stepView));
  main.append(card);
  return main;
}

function buildCardFooter(stepView) {
  const footer = el('footer', { class: 'setup-card__foot' });
  const left = el('div', { class: 'setup-card__foot-left' });
  if (view.step > 0) {
    left.append(
      el('button', {
        type: 'button',
        class: 'btn btn--ghost',
        on: { click: () => goStep(view.step - 1) },
      }, icon('arrow-left', { size: 'sm' }), el('span', { text: t('common.back') }))
    );
  }
  left.append(
    el('button', {
      type: 'button',
      class: 'btn btn--ghost setup-abort',
      on: { click: () => openAbortDialog() },
    }, el('span', { text: t('setup.abort') }))
  );
  footer.append(left);

  const right = el('div', { class: 'setup-card__foot-right' });
  if (stepView.primaryLabel) {
    const primary = el('button', {
      type: 'button',
      class: 'btn btn--primary',
      attrs: { form: stepView.formId || undefined, 'aria-busy': view.busy ? 'true' : undefined },
    });
    primary.append(icon(stepView.primaryIcon || 'arrow-right', { size: 'sm' }), el('span', { text: stepView.primaryLabel }));
    if (view.busy) primary.disabled = true;
    primary.addEventListener('click', () => {
      if (!view.busy) void stepView.submit(primary);
    });
    if (stepView.submitAsForm) {
      const form = document.getElementById(stepView.formId);
      form?.addEventListener('submit', (event) => {
        event.preventDefault();
        if (!view.busy) void stepView.submit(primary);
      });
    }
    right.append(primary);
  }
  footer.append(right);
  return footer;
}

/* ------------------------------------------------------------------- steps */

/* ------------------------------------------------------------------ actions */

async function saveStep(action, nextStep, onSuccess) {
  if (view.busy) return;
  view.busy = true;
  view.error = '';
  render();
  try {
    await action();
    onSuccess?.();
    view.busy = false;
    if (nextStep !== undefined) goStep(nextStep);
    else render();
  } catch (error) {
    view.busy = false;
    view.error = errorText(error);
    render();
  }
}

async function completeSetup() {
  if (view.busy) return;
  view.busy = true;
  view.error = '';
  render();
  try {
    const response = await setupApi.complete();
    view.busy = false;
    view.data.completed = true;
    view.data.bindHint = response?.bind_hint || view.data.bindHint;
    renderCompleted(view, response, STEPS);
  } catch (error) {
    view.busy = false;
    view.error = errorText(error);
    render();
  }
}

function goStep(step) {
  view.step = clampStep(step);
  view.error = '';
  render();
  focusNode(document.getElementById('setup-step-title'));
}

function applyStepUrl() {
  const params = new URLSearchParams();
  params.set('step', String(view.step));
  params.set('lang', getLanguage());
  const target = `#/setup?${params.toString()}`;
  if (window.location.hash !== target) window.history.replaceState(null, '', target);
}

