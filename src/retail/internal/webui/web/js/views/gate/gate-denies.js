/**
 * Access Gate — deny timeline. Every denied write attempt is a security signal
 * with evidence (source, target, function, reason, severity), never a plain log
 * line. The audit reference is shown alongside each deny.
 */
import { el, clear } from '../../core/dom.js';
import { gateApi } from '../../core/api.js';
import { formatDateTime, formatRelative } from '../../core/format.js';
import { denyReasonLabel, protocolLabel } from '../../core/labels.js';
import { panel } from '../../components/panel.js';
import { emptyState, errorState, skeletonPage } from '../../components/states.js';
import { bypassChip, severityChip } from '../../components/chips.js';
import { icon } from '../../core/icons.js';
import { t } from '../../i18n/index.js';

const filter = { target: '' };
let loadSeq = 0;

export async function renderDenies(host, ctx) {
  const listHost = el('div');
  const summary = el('span', { class: 'filterbar__result', text: t('gate.common.loading') });

  const targetField = el('div', { class: 'field' });
  targetField.append(el('label', { class: 'field__label', text: t('gate.denies.target_label'), attrs: { for: 'gate-deny-target' } }));
  const select = el('select', { id: 'gate-deny-target', class: 'select' });
  select.append(el('option', { text: t('gate.common.all_targets'), attrs: { value: '' } }));
  for (const target of ctx.targets() || []) {
    const option = el('option', { text: `${target.label}`, attrs: { value: target.value } });
    if (filter.target === target.value) option.selected = true;
    select.append(option);
  }
  select.addEventListener('change', () => {
    filter.target = select.value;
    void load(ctx, listHost, summary);
  });
  targetField.append(select);

  const chainOk = ctx.status?.audit?.chain_ok !== false;
  const auditLine = el('div', { class: 'gate-deny-audit' }, [
    el('span', {
      class: 'chip chip--status',
      dataset: { status: chainOk ? 'resolved' : 'open' },
      text: chainOk ? t('gate.denies.chain_ok') : t('gate.denies.chain_bad'),
    }),
    el('span', {
      class: 'provenance',
      text: t('gate.denies.last_24h', { count: ctx.status?.denies?.last_24h ?? '—' }),
    }),
  ]);

  const filterBar = el('div', { class: 'gate-filters' }, [
    targetField,
    el('div', { class: 'gate-filters__actions' }, [summary]),
  ]);

  const listPanel = panel({
    title: t('gate.denies.title'),
    sub: t('gate.denies.subtitle'),
    actions: [
      el('button', {
        type: 'button',
        class: 'btn btn--ghost btn--sm',
        attrs: { 'aria-label': t('gate.denies.reload_aria') },
        on: { click: () => void load(ctx, listHost, summary) },
      }, icon('refresh', { size: 'sm' }), el('span', { text: t('gate.common.reload') })),
    ],
    body: el('div', { class: 'gate-inbox__body' }, [auditLine, filterBar, listHost]),
    flush: true,
  });

  host.append(el('div', { class: 'gate-single' }, listPanel));
  await load(ctx, listHost, summary);
}

async function load(ctx, listHost, summary) {
  const sequence = ++loadSeq;
  clear(listHost);
  listHost.append(el('div', { class: 'panel__body' }, skeletonPage(t('gate.denies.loading'))));
  summary.textContent = t('gate.common.loading');
  try {
    const response = await gateApi.getDenies({ limit: 200, target_id: filter.target || undefined });
    if (sequence !== loadSeq) return;
    const denies = Array.isArray(response.items) ? response.items : [];
    summary.textContent = denies.length === 1 ? t('gate.denies.count_one', { count: denies.length }) : t('gate.denies.count_many', { count: denies.length });
    clear(listHost);
    if (denies.length === 0) {
      listHost.append(
        emptyState({
          icon: 'shield',
          title: filter.target ? t('gate.denies.empty_target_title') : t('gate.denies.empty_title'),
          text: t('gate.denies.empty_text'),
          actions: [
            el('button', {
              type: 'button',
              class: 'btn btn--secondary',
              text: t('gate.denies.reset_filters'),
              on: {
                click: () => {
                  filter.target = '';
                  void ctx.reloadAll();
                },
              },
            }),
          ],
        })
      );
      return;
    }
    const list = el('div', { class: 'gate-deny-list' });
    for (const deny of denies) list.append(buildDenyRow(deny));
    listHost.append(list);
  } catch (error) {
    if (sequence !== loadSeq) return;
    clear(listHost);
    listHost.append(
      errorState({
        title: t('gate.denies.error_title'),
        error,
        actions: [
          el('button', {
            type: 'button',
            class: 'btn btn--primary',
            text: t('gate.common.reload'),
            on: { click: () => void load(ctx, listHost, summary) },
          }),
        ],
      })
    );
    summary.textContent = t('gate.common.error');
  }
}

function buildDenyRow(deny) {
  const row = el('div', { class: 'gate-deny-row', dataset: { severity: deny.severity || 'info' } });
  const main = el('div', { class: 'gate-deny-row__main' });
  const head = el('div', { class: 'gate-deny-row__head' });
  head.append(
    ...[
      severityChip(deny.severity),
      el('span', { class: 'gate-deny-row__reason', text: denyReasonLabel(deny.reason) }),
      deny.via_bypass ? bypassChip() : null,
      el('span', { class: 'provenance', text: `${formatRelative(deny.at)} · ${formatDateTime(deny.at)}` }),
    ].filter(Boolean)
  );
  main.append(head);

  const route = el('div', { class: 'gate-deny-row__route' });
  route.append(
    el('span', { class: 'mono', text: deny.source_ip || '—' }),
    icon('arrow-right', { size: 'sm' }),
    el('span', { class: 'mono', text: deny.target_id || '—' }),
    el('span', { class: 'chip chip--protocol', text: protocolLabel(deny.protocol) }),
    el('span', { class: 'gate-deny-row__call', text: `${deny.function || '—'} ${deny.address || ''}`.trim() })
  );
  main.append(route);

  const meta = el('div', { class: 'gate-deny-row__meta' });
  meta.append(
    ...[
      el('span', { class: 'mono', text: deny.deny_id || '' }),
      deny.plan_id
        ? el('span', { class: 'mono', text: t('gate.denies.plan_ref', { id: deny.plan_id }) })
        : el('span', { class: 'provenance', text: t('gate.denies.no_plan') }),
      deny.session_id ? el('span', { class: 'mono', text: t('gate.denies.session_ref', { id: deny.session_id }) }) : null,
      deny.user_id ? el('span', { text: t('gate.denies.user_ref', { id: deny.user_id }) }) : null,
      deny.value_hint ? el('span', { class: 'mono', text: t('gate.denies.value_hint_ref', { value: deny.value_hint }) }) : null,
    ].filter(Boolean)
  );
  main.append(meta);
  row.append(main);

  const audit = el('div', { class: 'gate-deny-row__audit' }, [
    el('span', { class: 'provenance', text: t('gate.denies.audit_ref') }),
    el('span', { class: 'mono', text: deny.deny_id || '—' }),
  ]);
  row.append(audit);
  return row;
}
