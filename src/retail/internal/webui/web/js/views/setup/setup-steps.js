/**
 * Setup wizard steps: language, site, whitelist, admin, collectors, summary.
 * Each builder receives the shared wizard context (view, render, goStep,
 * saveStep, complete) so the container only owns navigation and state.
 */
import { el, focusNode } from '../../core/dom.js';
import { setupApi } from '../../core/setup-api.js';
import { banner, inlineError } from '../../components/states.js';
import { getLanguage, getLocaleTag, LANGUAGES, setLanguage, t } from '../../i18n/index.js';

export function buildStep(step, host, errorSlot, ctx) {
  const builders = {
    language: buildLanguageStep,
    site: buildSiteStep,
    whitelist: buildWhitelistStep,
    admin: buildAdminStep,
    collectors: buildCollectorsStep,
    summary: buildSummaryStep,
  };
  return step === 'whitelist' ? builders[step](host, errorSlot, ctx) : builders[step](host, ctx);
}

function buildLanguageStep(host, ctx) {
  host.append(el('p', { class: 'setup-help', text: t('setup.languageHelp') }));
  const list = el('div', { class: 'setup-language-list', attrs: { role: 'radiogroup', 'aria-label': t('nav.language') } });
  for (const language of LANGUAGES) {
    const selected = language.code === getLanguage();
    const label = el('label', { class: 'setup-language-option', dataset: { selected: String(selected) } });
    const radio = el('input', {
      type: 'radio',
      name: 'setup-language',
      class: 'radio',
      attrs: { value: language.code },
    });
    radio.checked = selected;
    radio.addEventListener('change', async () => {
      setLanguage(language.code);
      if (ctx.view.data) ctx.view.data.language = language.code;
      ctx.render();
      try {
        await setupApi.setLanguage(language.code);
      } catch (error) {
        ctx.view.error = errorText(error);
        ctx.render();
      }
    });
    label.append(radio, el('span', { class: 'setup-language-option__native', text: language.native }), el('span', { class: 'setup-language-option__code mono', text: language.code }));
    list.append(label);
  }
  host.append(list);
  return {
    primaryLabel: t('common.next'),
    primaryIcon: 'arrow-right',
    async submit() {
      if (ctx.view.data) ctx.view.data.language = getLanguage();
      await ctx.saveStep(() => setupApi.setLanguage(getLanguage()), 1);
    },
  };
}

function countryOptions() {
  const tags = ['DE', 'AT', 'CH', 'FR', 'IT', 'ES', 'GB', 'US', 'JP', 'CN'];
  let display;
  try {
    display = new Intl.DisplayNames([getLocaleTag()], { type: 'region' });
  } catch {
    display = null;
  }
  return tags.map((code) => [code, display ? display.of(code) || code : code]);
}

function buildSiteStep(host, ctx) {
  host.append(el('p', { class: 'setup-help', text: t('setup.siteHelp') }));
  const form = el('form', { class: 'setup-form', id: 'setup-site-form' });
  form.addEventListener('submit', (event) => event.preventDefault());
  const site = ctx.view.data.site || {};
  const fields = el('div', { class: 'setup-grid setup-grid--2' });
  fields.append(
    field('setup-site-id', t('setup.siteId'), site.site_id || 'filiale-001', { required: true, hint: 'a-z, 0-9, -' }),
    field('setup-site-name', t('setup.siteName'), site.name || '', { required: true }),
    selectField('setup-site-country', t('setup.country'), countryOptions(), site.country || 'DE'),
    field('setup-site-timezone', t('setup.timezone'), site.timezone || guessTimezone(), { required: true, hint: 'Europe/Berlin' })
  );
  form.append(fields);
  form.append(field('setup-site-zones', `${t('setup.zones')} (${t('common.optional')})`, zonesToText(site.zones), {
    multiline: true,
    hint: t('setup.zonesHint'),
  }));
  host.append(form);
  return {
    primaryLabel: t('common.next'),
    primaryIcon: 'arrow-right',
    formId: 'setup-site-form',
    submitAsForm: true,
    submit: async () => saveSiteStep(ctx),
  };
}

function buildWhitelistStep(host, errorSlot, ctx) {
  host.append(el('p', { class: 'setup-help', text: t('setup.whitelistHelp') }));
  const detected = el('div', { class: 'setup-detected' });
  detected.append(
    el('div', { class: 'setup-detected__main' }, [
      el('span', { class: 'setup-detected__label', text: t('setup.detectedIp') }),
      el('span', { class: 'setup-detected__value mono', text: ctx.view.data.remoteIp || '127.0.0.1' }),
    ]),
    el('div', { class: 'setup-detected__actions' }, [
      button(t('setup.addMyIp'), 'btn btn--secondary btn--sm', () => addCidr(ctx.view.data.remoteIp, ctx)),
      button(t('setup.addLoopback'), 'btn btn--ghost btn--sm', () => addCidr('127.0.0.1/32', ctx)),
    ])
  );
  host.append(detected);
  host.append(
    banner({
      variant: 'warn',
      title: t('setup.whitelistEmpty'),
      text: t('setup.cidrsHint'),
    })
  );
  const form = el('form', { class: 'setup-form', id: 'setup-whitelist-form' });
  form.addEventListener('submit', (event) => event.preventDefault());
  const textarea = el('textarea', { id: 'setup-whitelist', class: 'textarea mono', attrs: { rows: '7', placeholder: '127.0.0.1/32\n::1/128\n10.20.30.0/24', 'aria-describedby': 'setup-whitelist-hint' } });
  textarea.value = (ctx.view.data.whitelist || []).join('\n');
  const fieldWrap = el('div', { class: 'field' });
  fieldWrap.append(
    el('label', { class: 'field__label', text: t('setup.cidrs'), attrs: { for: 'setup-whitelist' } }),
    textarea,
    el('p', { id: 'setup-whitelist-hint', class: 'field__hint', text: t('setup.cidrsHint') })
  );
  form.append(fieldWrap);
  host.append(form);
  return {
    primaryLabel: t('common.next'),
    primaryIcon: 'arrow-right',
    formId: 'setup-whitelist-form',
    submitAsForm: true,
    submit: async () => saveWhitelistStep(textarea, errorSlot, ctx),
  };
}

function buildAdminStep(host, ctx) {
  host.append(el('p', { class: 'setup-help', text: t('setup.adminHelp') }));
  if (ctx.view.token) {
    const block = el('div', { class: 'setup-token' });
    block.append(
      banner({ variant: 'critical', title: t('setup.tokenTitle'), text: t('setup.tokenWarning') }),
      el('code', { class: 'setup-token__value', text: ctx.view.token }),
      el('label', { class: 'setup-ack' }, [
        (() => {
          const checkbox = el('input', { type: 'checkbox', id: 'setup-token-ack', class: 'checkbox' });
          ctx.view.ack = false;
          checkbox.addEventListener('change', () => { ctx.view.ack = checkbox.checked; });
          return checkbox;
        })(),
        el('span', { text: t('setup.tokenOnce') }),
      ])
    );
    host.append(block);
    return {
      primaryLabel: t('common.next'),
      primaryIcon: 'arrow-right',
      async submit() {
        if (!ctx.view.ack) {
          ctx.view.error = t('setup.tokenOnce');
          ctx.render();
          return;
        }
        ctx.view.token = '';
        ctx.goStep(4);
      },
    };
  }
  if (ctx.view.adminExists) {
    host.append(
      banner({
        variant: 'warn',
        title: t('setup.adminExistsTitle'),
        text: t('setup.adminExistsText'),
      })
    );
    return { primaryLabel: t('common.next'), primaryIcon: 'arrow-right', async submit() { ctx.goStep(4); } };
  }
  if (ctx.view.data.adminCreated) {
    host.append(banner({ variant: 'success', title: t('setup.adminDone'), text: t('setup.adminHelp') }));
    return { primaryLabel: t('common.next'), primaryIcon: 'arrow-right', async submit() { ctx.goStep(4); } };
  }
  const form = el('form', { class: 'setup-form', id: 'setup-admin-form' });
  form.addEventListener('submit', (event) => event.preventDefault());
  form.append(
    el('div', { class: 'setup-grid setup-grid--2' }, [
      field('setup-admin-id', t('setup.adminUserId'), 'admin', { required: true, hint: 'a-z, 0-9, -' }),
      field('setup-admin-name', t('setup.adminName'), 'Filial-Administrator', { required: true }),
    ])
  );
  host.append(form);
  return {
    primaryLabel: t('setup.createAdmin'),
    primaryIcon: 'user',
    formId: 'setup-admin-form',
    submitAsForm: true,
    submit: async () => createAdminStep(ctx),
  };
}

function buildCollectorsStep(host, ctx) {
  host.append(el('p', { class: 'setup-help', text: t('setup.collectorsHelp') }));
  const list = el('div', { class: 'setup-collector-list' });
  const selected = new Set(ctx.view.data.collectors || []);
  for (const collector of ctx.view.data.supported) {
    const id = collector.id || collector.adapter || collector.name;
    const checkbox = el('input', { type: 'checkbox', class: 'checkbox', attrs: { value: id, id: `setup-collector-${id}` } });
    checkbox.checked = selected.has(id);
    const card = el('label', { class: 'setup-collector' }, [
      checkbox,
      el('span', { class: 'setup-collector__text' }, [
        el('span', { class: 'setup-collector__name', text: collector.name || id }),
        el('span', { class: 'setup-collector__hint', text: collector.hint || collector.description || '' }),
      ]),
    ]);
    list.append(card);
  }
  host.append(list, el('p', { class: 'provenance', text: t('setup.collectorsHint') }));
  if (!ctx.view.data.supported.length) host.append(el('p', { class: 'provenance', text: t('setup.collectorsNone') }));
  return {
    primaryLabel: t('common.next'),
    primaryIcon: 'arrow-right',
    async submit() {
      const adapters = [...host.querySelectorAll('input[type="checkbox"]:checked')].map((input) => input.value);
      await ctx.saveStep(() => setupApi.setCollectors(adapters), 5, () => { ctx.view.data.collectors = adapters; });
    },
  };
}

function buildSummaryStep(host, ctx) {
  host.append(el('p', { class: 'setup-help', text: t('setup.summaryHelp') }));
  const summary = el('dl', { class: 'setup-summary' });
  const site = ctx.view.data.site || {};
  appendSummary(summary, t('setup.summarySite'), site.site_id ? `${site.site_id} · ${site.name || ''} · ${site.country || ''}` : '—');
  appendSummary(summary, t('setup.summaryWhitelist'), (ctx.view.data.whitelist || []).join(', ') || '—');
  appendSummary(summary, t('setup.summaryAdmin'), ctx.view.data.adminCreated ? 'ok' : '—');
  appendSummary(summary, t('setup.summaryCollectors'), (ctx.view.data.collectors || []).join(', ') || t('common.optional'));
  host.append(summary);
  host.append(
    banner({
      variant: 'accent',
      title: t('setup.restartTitle'),
      text: t('setup.restartText'),
    })
  );
  return {
    primaryLabel: t('setup.complete'),
    primaryIcon: 'check',
    async submit() { await ctx.complete(); },
  };
}

async function saveSiteStep(ctx) {
  const siteId = value('setup-site-id');
  const name = value('setup-site-name');
  const country = value('setup-site-country');
  const timezone = value('setup-site-timezone');
  if (!siteId || !name || !country || !timezone) {
    ctx.view.error = t('setup.siteInvalid');
    ctx.render();
    return;
  }
  const zones = parseZones(value('setup-site-zones'));
  const site = { site_id: siteId, name, country, timezone, zones };
  await ctx.saveStep(() => setupApi.setSite(site), 2, () => { ctx.view.data.site = site; });
}

async function saveWhitelistStep(textarea, errorSlot, ctx) {
  const cidrs = textarea.value.split(/\r?\n|,/).map((entry) => entry.trim()).filter(Boolean);
  if (ctx.view.busy) return;
  ctx.view.busy = true;
  ctx.view.error = '';
  ctx.render();
  try {
    await setupApi.setWhitelist(cidrs);
    ctx.view.data.whitelist = cidrs;
    ctx.view.busy = false;
    ctx.goStep(3);
  } catch (error) {
    applyError(ctx, error);
    errorSlot?.append(inlineError(ctx.view.error || ''));
    focusNode(document.getElementById('setup-whitelist'));
  }
}

async function createAdminStep(ctx) {
  const userId = value('setup-admin-id');
  const name = value('setup-admin-name');
  if (!userId || !name) {
    ctx.view.error = t('common.required');
    ctx.render();
    return;
  }
  if (ctx.view.busy) return;
  ctx.view.busy = true;
  ctx.view.error = '';
  ctx.render();
  try {
    const response = await setupApi.createAdmin(userId, name);
    ctx.view.busy = false;
    ctx.view.token = String(response?.token || '');
    ctx.view.data.adminCreated = true;
    if (!ctx.view.token) {
      ctx.view.error = t('setup.error');
    }
    ctx.render();
    focusNode(document.querySelector('.setup-token__value'));
  } catch (error) {
    ctx.view.busy = false;
    if (error && error.code === 'admin_exists') {
      ctx.view.adminExists = true;
      ctx.view.data.adminCreated = true;
      ctx.view.error = '';
      ctx.render();
      return;
    }
    ctx.view.error = errorText(error);
    ctx.render();
  }
}

function addCidr(cidr, ctx) {
  const textarea = document.getElementById('setup-whitelist');
  if (!textarea || !cidr) return;
  const current = textarea.value.split(/\r?\n|,/).map((entry) => entry.trim()).filter(Boolean);
  if (!current.includes(cidr)) current.push(cidr);
  textarea.value = current.join('\n');
  focusNode(textarea);
}

function field(id, label, initial = '', { required = false, hint = '', multiline = false } = {}) {
  const wrapper = el('div', { class: 'field' });
  wrapper.append(el('label', { class: 'field__label', text: label, attrs: { for: id } }));
  const input = multiline
    ? el('textarea', { id, class: 'textarea mono', attrs: { rows: '4', 'aria-describedby': hint ? `${id}-hint` : undefined } })
    : el('input', { id, class: 'input', type: 'text', attrs: { autocomplete: 'off', spellcheck: 'false', required: required ? 'required' : undefined, 'aria-describedby': hint ? `${id}-hint` : undefined } });
  input.value = initial || '';
  wrapper.append(input);
  if (hint) wrapper.append(el('p', { id: `${id}-hint`, class: 'field__hint', text: hint }));
  return wrapper;
}

function selectField(id, label, options, initial) {
  const wrapper = el('div', { class: 'field' });
  wrapper.append(el('label', { class: 'field__label', text: label, attrs: { for: id } }));
  const select = el('select', { id, class: 'select' });
  for (const [value, text] of options) {
    const option = el('option', { text, attrs: { value } });
    if (value === initial) option.selected = true;
    select.append(option);
  }
  wrapper.append(select);
  return wrapper;
}

function appendSummary(dl, label, value) {
  dl.append(el('dt', { text: label }), el('dd', { text: value || '—' }));
}

function value(id) {
  return String(document.getElementById(id)?.value || '').trim();
}

function button(label, className, onClick) {
  const node = el('button', { type: 'button', class: className, text: label });
  node.addEventListener('click', onClick);
  return node;
}

function zonesToText(zones) {
  if (!Array.isArray(zones)) return '';
  return zones.map((zone) => `${zone.zone_id || zone.id || ''}|${zone.name || ''}|${zone.kind || ''}`).join('\n');
}

function parseZones(text) {
  return String(text || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const [id, name, kind] = line.split('|').map((part) => part.trim());
      return { zone_id: id || 'zone', name: name || id || 'Zone', kind: kind || 'refrigeration' };
    });
}

function guessTimezone() {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'Europe/Berlin';
  } catch {
    return 'Europe/Berlin';
  }
}

function applyError(ctx, error) {
  ctx.view.busy = false;
  if (error && error.code === 'setup_session_invalid') {
    ctx.view.sessionExpired = true;
    ctx.view.error = t('setup.sessionExpired', null, 'Setup-Sitzung abgelaufen — Seite neu laden');
  } else {
    ctx.view.error = errorText(error);
  }
  ctx.render();
}

export function errorText(error) {
  if (!error) return t('setup.error');
  if (error.status === 0) return t('setup.error');
  if (error.code === 'setup_session_invalid') return t('setup.sessionExpired', null, 'Setup-Sitzung abgelaufen — Seite neu laden');
  if (error.status === 403 && error.code === 'forbidden') {
    return t('setup.forbidden');
  }
  if (error.status === 403 && error.code === 'ip_not_allowed') return t('setup.loopback');
  return `${t('setup.error')} ${error.diagnostic || error.message || ''}`.trim();
}
