/**
 * Setup wizard shell and terminal states: standalone header (logo, language,
 * loopback badge), step indicator, footer, completion page with OS restart
 * commands, ended/error screens and the abort dialog. No dashboard chrome.
 */
import { el, clear, focusNode } from '../../core/dom.js';
import { setupApi } from '../../core/setup-api.js';
import { languageSelector } from '../../components/language-selector.js';
import { errorState } from '../../components/states.js';
import { icon } from '../../core/icons.js';
import { getLanguage, setLanguage, t } from '../../i18n/index.js';

const RESTART_COMMANDS = {
  windows: 'Restart-Service GeDefenseRetail',
  linux: 'sudo systemctl restart gedefense-retail',
  macos: 'sudo launchctl kickstart -k system/tech.visiongaia.gedefense.retail',
};

export function buildHeader(view, render) {
  const header = el('header', { class: 'setup-header' });
  const brand = el('div', { class: 'setup-brand' });
  brand.append(
    el('img', { class: 'setup-brand__logo', attrs: { src: '/assets/gedefense-logo.png', alt: '', width: '44', height: '44' } }),
    el('span', { class: 'setup-brand__text' }, [
      el('span', { class: 'setup-brand__product', text: t('app.name') }),
      el('span', { class: 'setup-brand__edition', text: t('setup.product') }),
    ])
  );
  const actions = el('div', { class: 'setup-header__actions' });
  actions.append(
    languageSelector({
      value: getLanguage(),
      compact: true,
      onChange: async (code) => {
        setLanguage(code);
        if (view.data) {
          view.data.language = code;
          try {
            await setupApi.setLanguage(code);
          } catch {
            /* language stays local; the next step reports server errors */
          }
        }
        render();
      },
    }),
    el('span', { class: 'setup-loopback' }, [
      icon('lock', { size: 'sm' }),
      el('span', { text: t('setup.loopback') }),
    ])
  );
  header.append(brand, actions);
  return header;
}

export function buildStepper(view, steps) {
  const list = el('ol', { class: 'setup-stepper', attrs: { 'aria-label': t('setup.title') } });
  steps.forEach((step, index) => {
    const item = el('li', {
      class: 'setup-stepper__item',
      dataset: { state: index === view.step ? 'current' : index < view.step ? 'done' : 'todo' },
      attrs: { 'aria-current': index === view.step ? 'step' : undefined },
    });
    item.append(
      el('span', { class: 'setup-stepper__dot', text: index < view.step ? '✓' : String(index + 1) }),
      el('span', { class: 'setup-stepper__label', text: t(`setup.step.${step}`) })
    );
    list.append(item);
  });
  return list;
}

export function buildFooter() {
  const footer = el('footer', { class: 'setup-footer' });
  footer.append(
    el('span', { text: `${t('app.name')} ${t('app.retail')}` }),
    el('span', { class: 'mono', text: '0.2.0-alpha.2' })
  );
  return footer;
}

export function renderCompleted(view, response, steps) {
  clear(view.root);
  const app = el('div', { class: 'setup-app', id: 'setup-app' });
  const site = view.data.site || {};
  const success = el('main', { class: 'setup-main setup-main--done' });
  success.append(
    el('div', { class: 'setup-done plane plane--focus' }, [
      el('img', { class: 'setup-done__logo', attrs: { src: '/assets/gedefense-logo.png', alt: '', width: '64', height: '64' } }),
      el('p', { class: 'setup-intro__kicker', text: t('setup.product') }),
      el('h1', { class: 'setup-intro__title', text: t('setup.completedTitle') }),
      el('p', { class: 'setup-help', text: t('setup.completedText') }),
      el('div', { class: 'setup-done__meta' }, [
        site.site_id ? el('span', { class: 'mono', text: site.site_id }) : null,
        el('span', { text: t('setup.stepOf', { current: steps.length, total: steps.length }) }),
      ].filter(Boolean)),
      buildRestartBlock(response?.bind_hint || view.data.bindHint),
      el('a', { class: 'btn btn--primary', href: '#/overview' }, el('span', { text: t('setup.openOverview') })),
      el('p', { class: 'provenance', text: t('setup.restartHint') })
    ])
  );
  app.append(success, buildFooter());
  view.root.append(app);
  focusNode(success);
}

function buildRestartBlock(bindHint) {
  const wrapper = el('div', { class: 'setup-restart' });
  wrapper.append(el('h3', { class: 'setup-restart__title', text: t('setup.restartTitle') }));
  if (bindHint) wrapper.append(el('p', { class: 'provenance', text: `${t('setup.bindHint')}: ${bindHint}` }));
  for (const os of ['windows', 'linux', 'macos']) {
    const row = el('div', { class: 'setup-restart__row' });
    const command = RESTART_COMMANDS[os];
    const copy = el('button', {
      type: 'button',
      class: 'btn btn--ghost btn--sm',
      attrs: { 'aria-label': `${t('setup.copy')} (${t(`setup.os.${os}`)})` },
    }, icon('copy', { size: 'sm' }), el('span', { text: t('setup.copy') }));
    copy.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(command);
        copy.lastChild.textContent = t('setup.copied');
        window.setTimeout(() => { copy.lastChild.textContent = t('setup.copy'); }, 2000);
      } catch {
        /* clipboard may be blocked; the command stays selectable */
      }
    });
    row.append(
      el('span', { class: 'setup-restart__os', text: t(`setup.os.${os}`) }),
      el('code', { class: 'setup-restart__cmd mono', text: command }),
      copy
    );
    wrapper.append(row);
  }
  return wrapper;
}

export function renderEnded(view) {
  clear(view.root);
  const app = el('div', { class: 'setup-app', id: 'setup-app' });
  const main = el('main', { class: 'setup-main setup-main--done' });
  main.append(
    el('div', { class: 'setup-done plane plane--focus' }, [
      el('img', { class: 'setup-done__logo', attrs: { src: '/assets/gedefense-logo.png', alt: '', width: '64', height: '64' } }),
      el('p', { class: 'setup-intro__kicker', text: t('setup.product') }),
      el('h1', { class: 'setup-intro__title', text: t('setup.completedTitle') }),
      el('p', { class: 'setup-help', text: t('setup.completedText') }),
      buildRestartBlock(view.data.bindHint),
      el('a', { class: 'btn btn--primary', href: '#/overview' }, el('span', { text: t('setup.openOverview') })),
      el('p', { class: 'provenance', text: t('setup.restartHint') })
    ])
  );
  app.append(buildHeader(view, () => renderEnded(view)), main, buildFooter());
  view.root.append(app);
}

export function renderLoadError(view, error) {
  clear(view.root);
  const app = el('div', { class: 'setup-app', id: 'setup-app' });
  const main = el('main', { class: 'setup-main setup-main--done' });
  main.append(
    el('div', { class: 'setup-done plane plane--focus' }, [
      el('p', { class: 'setup-intro__kicker', text: t('setup.product') }),
      el('h1', { class: 'setup-intro__title', text: t('setup.error') }),
      errorState({
        title: t('setup.error'),
        error,
        actions: [
          el('button', { type: 'button', class: 'btn btn--primary', text: t('common.retry'), on: { click: () => window.location.reload() } }),
          el('a', { class: 'btn btn--ghost', href: '#/overview', text: t('setup.openOverview') }),
        ],
      }),
      el('p', { class: 'provenance', text: t('setup.loopback') }),
    ])
  );
  app.append(buildHeader(view, () => window.location.reload()), main, buildFooter());
  view.root.append(app);
}

export function openAbortDialog() {
  const overlay = el('div', { class: 'setup-abort__backdrop', attrs: { role: 'presentation' } });
  const dialog = el('div', { class: 'setup-abort__dialog plane plane--focus', attrs: { role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': 'setup-abort-title' } });
  dialog.append(
    el('h2', { id: 'setup-abort-title', class: 'setup-abort__title', text: t('setup.abort') }),
    el('p', { class: 'setup-help', text: t('setup.abortText') }),
    el('div', { class: 'setup-abort__actions' }, [
      el('button', { type: 'button', class: 'btn btn--ghost', text: t('common.back'), on: { click: () => overlay.remove() } }),
      el('a', { class: 'btn btn--danger', href: '#/overview', text: t('setup.abort') }),
    ])
  );
  overlay.append(dialog);
  document.body.append(overlay);
  dialog.querySelector('button')?.focus();
  overlay.addEventListener('click', (event) => { if (event.target === overlay) overlay.remove(); });
}
