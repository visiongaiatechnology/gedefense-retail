/**
 * Access Gate — Approval-Inbox and write-plan detail. This is the product's
 * enforcement workbench: a plan is only approved with MFA, four-eyes state is
 * visible, and the one-time token is shown exactly once at final approval.
 */
import { el, clear } from '../../core/dom.js';
import { gateApi } from '../../core/api.js';
import { toast } from '../../core/store.js';
import { formatDateTime, formatRelative } from '../../core/format.js';
import {
  gateCanApprove,
  gateHasAnyRole,
  planApprovalSummary,
  planNeedsFourEyes,
  protocolLabel,
  unitLabel,
} from '../../core/labels.js';
import { panel } from '../../components/panel.js';
import { dataTable } from '../../components/table.js';
import { emptyState, errorState, banner, skeletonPage } from '../../components/states.js';
import { criticalityChip, planStateChip, protocolChips, severityChip } from '../../components/chips.js';
import { icon } from '../../core/icons.js';
import {
  openApproveDialog,
  openCancelDialog,
  openRejectDialog,
  openTokenRevealDialog,
} from './gate-dialogs.js';
import { t } from '../../i18n/index.js';

const inbox = { state: 'pending', target: '', risk: '', selected: '' };
let loadSeq = 0;

const RISK_OPTIONS = [
  { value: '', label: t('gate.inbox.risk_all') },
  { value: 'critical', label: t('gate.inbox.risk_critical') },
  { value: 'four_eyes', label: t('gate.inbox.risk_four_eyes') },
  { value: 'standard', label: t('gate.inbox.risk_standard') },
];

const STATE_OPTIONS = [
  { value: 'pending', label: t('enum.plan_state.pending') },
  { value: '', label: t('gate.inbox.state_all') },
  { value: 'approved', label: t('enum.plan_state.approved') },
  { value: 'executed', label: t('enum.plan_state.executed') },
  { value: 'rejected', label: t('enum.plan_state.rejected') },
  { value: 'expired', label: t('enum.plan_state.expired') },
  { value: 'cancelled', label: t('enum.plan_state.cancelled') },
];

export async function renderInbox(host, ctx) {
  if (ctx.planId && ctx.planId !== inbox.selected) inbox.selected = ctx.planId;

  const listHost = el('div');
  const detailHost = el('div');
  const summary = el('span', { class: 'filterbar__result', text: t('gate.common.loading') });

  const filters = el('form', { class: 'gate-filters', attrs: { 'aria-label': t('gate.inbox.filters_aria'), role: 'search' } });
  filters.append(
    selectField('gate-filter-state', t('gate.common.status'), STATE_OPTIONS, inbox.state, (value) => {
      inbox.state = value;
      void loadPlans(ctx, listHost, detailHost, summary);
    }),
    selectField('gate-filter-target', t('gate.inbox.target_label'), [{ value: '', label: t('gate.common.all_targets') }, ...(ctx.targets() || [])], inbox.target, (value) => {
      inbox.target = value;
      void loadPlans(ctx, listHost, detailHost, summary);
    }),
    selectField('gate-filter-risk', t('gate.inbox.risk_label'), RISK_OPTIONS, inbox.risk, (value) => {
      inbox.risk = value;
      void loadPlans(ctx, listHost, detailHost, summary);
    })
  );
  filters.append(el('div', { class: 'gate-filters__actions' }, [summary]));
  filters.addEventListener('submit', (event) => event.preventDefault());

  const listPanel = panel({
    title: t('gate.inbox.title'),
    sub: t('gate.inbox.subtitle'),
    actions: [
      el('button', {
        type: 'button',
        class: 'btn btn--ghost btn--sm',
        attrs: { 'aria-label': t('gate.inbox.reload_aria') },
        on: { click: () => void loadPlans(ctx, listHost, detailHost, summary) },
      }, icon('refresh', { size: 'sm' }), el('span', { text: t('gate.common.reload') })),
    ],
    body: el('div', { class: 'gate-inbox__body' }, [filters, listHost]),
    flush: true,
  });

  const detailPanel = panel({
    title: t('gate.inbox.detail_title'),
    sub: t('gate.inbox.detail_subtitle'),
    body: detailHost,
  });

  const workspace = el('div', { class: 'gate-workspace' });
  workspace.append(el('div', { class: 'gate-workspace__list' }, listPanel), el('div', { class: 'gate-workspace__detail' }, detailPanel));
  host.append(workspace);

  await loadPlans(ctx, listHost, detailHost, summary);
}

async function loadPlans(ctx, listHost, detailHost, summary) {
  const sequence = ++loadSeq;
  clear(listHost);
  listHost.append(el('div', { class: 'panel__body' }, skeletonPage(t('gate.inbox.loading'))));
  summary.textContent = t('gate.common.loading');
  try {
    const response = await gateApi.getPlans({
      state: inbox.state || undefined,
      target_id: inbox.target || undefined,
      limit: 200,
    });
    if (sequence !== loadSeq) return;
    const all = Array.isArray(response.items) ? response.items : [];
    let items = all;
    if (inbox.risk) {
      items = items.filter((plan) => {
        if (inbox.risk === 'critical') return plan.critical === true;
        if (inbox.risk === 'four_eyes') return planNeedsFourEyes(plan);
        return !planNeedsFourEyes(plan);
      });
    }
    summary.textContent = t('gate.inbox.count', { shown: items.length, total: Number(response.total ?? all.length) });
    if (items.length === 0) {
      clear(listHost);
      listHost.append(emptyStateForFilters(ctx, listHost, detailHost, summary));
      clear(detailHost);
      detailHost.append(
        el('p', { class: 'provenance', text: t('gate.inbox.no_selection') })
      );
      return;
    }
    const selectedVisible = items.some((plan) => plan.plan_id === inbox.selected);
    if (!inbox.selected || (!selectedVisible && ctx.planId !== inbox.selected)) {
      inbox.selected = items[0].plan_id;
      ctx.setPlanUrl(inbox.selected);
    }
    renderList(items, listHost, detailHost, ctx, summary);
    await renderDetail(inbox.selected, detailHost, ctx, listHost, summary);
  } catch (error) {
    if (sequence !== loadSeq) return;
    clear(listHost);
    listHost.append(
      el('div', { class: 'panel__body' }, [
        errorState({
          title: t('gate.inbox.error_title'),
          error,
          actions: [
            el('button', {
              type: 'button',
              class: 'btn btn--primary',
              text: t('gate.common.reload'),
              on: { click: () => void loadPlans(ctx, listHost, detailHost, summary) },
            }),
          ],
        }),
      ])
    );
    summary.textContent = t('gate.common.error');
  }
}

function renderList(items, listHost, detailHost, ctx, summary) {
  clear(listHost);
  const list = el('div', { class: 'gate-plan-list', attrs: { role: 'group', 'aria-label': t('gate.inbox.list_aria') } });
  for (const plan of items) {
    const selected = plan.plan_id === inbox.selected;
    const approvals = planApprovalSummary(plan);
    const button = el('button', {
      type: 'button',
      class: 'gate-plan-row',
      attrs: { 'aria-current': selected ? 'true' : undefined, 'aria-label': t('gate.sessions.plan_open_aria', { id: plan.plan_id }) },
      on: {
        click: () => {
          inbox.selected = plan.plan_id;
          ctx.setPlanUrl(plan.plan_id);
          renderList(items, listHost, detailHost, ctx, summary);
          void renderDetail(plan.plan_id, detailHost, ctx, listHost, summary);
        },
      },
    });
    const head = el('span', { class: 'gate-plan-row__head' });
    head.append(planStateChip(plan.state), el('span', { class: 'mono', text: plan.plan_id }));
    if (plan.critical) head.append(severityChip('critical'));
    else if (plan.four_eyes) head.append(el('span', { class: 'chip chip--sev', dataset: { severity: 'high' }, text: t('gate.inbox.four_eyes') }));
    const title = el('span', { class: 'gate-plan-row__title' });
    title.append(
      el('span', { text: `${plan.target_id || '—'} · ${plan.asset_id || '—'}` }),
      el('span', { class: 'gate-plan-row__proto', text: protocolLabel(plan.protocol) })
    );
    const meta = el('span', { class: 'gate-plan-row__meta' });
    meta.append(
      el('span', { text: t('gate.inbox.operations_count', { count: Array.isArray(plan.operations) ? plan.operations.length : 0 }) }),
      el('span', { text: t('gate.inbox.window', { from: formatDateTime(plan.window_start), to: formatDateTime(plan.window_end) }) }),
      el('span', { text: t('gate.inbox.request_line', { user: plan.requested_by || '—', age: formatRelative(plan.requested_at) }) }),
      el('span', { class: approvals.fourEyes ? 'gate-plan-row__eyes' : 'provenance', text: approvals.fourEyes ? t('gate.inbox.four_eyes_progress', { count: approvals.count, required: approvals.required }) : t('gate.inbox.single_approval') })
    );
    button.append(head, title, meta);
    list.append(button);
  }
  listHost.append(list);
}

async function renderDetail(planId, detailHost, ctx, listHost, summary) {
  clear(detailHost);
  detailHost.append(skeletonPage(t('gate.inbox.detail_loading')));
  try {
    const response = await gateApi.getPlan(planId);
    clear(detailHost);
    detailHost.append(buildPlanDetail(response.plan, ctx, listHost, detailHost, summary));
  } catch (error) {
    clear(detailHost);
    detailHost.append(
      errorState({
        title: t('gate.inbox.detail_error_title'),
        error,
        actions: [
          el('button', {
            type: 'button',
            class: 'btn btn--secondary',
            text: t('gate.common.retry'),
            on: { click: () => void renderDetail(planId, detailHost, ctx, listHost, summary) },
          }),
        ],
      })
    );
  }
}

function buildPlanDetail(plan, ctx, listHost, detailHost, summary) {
  const wrapper = el('div', { class: 'stack gate-plan-detail' });
  const approvals = planApprovalSummary(plan);
  const windowExpired = plan.window_end ? new Date(plan.window_end).getTime() < Date.now() : false;
  const me = ctx.me;
  const canApprove = gateCanApprove(me);
  const canRequest = gateHasAnyRole(me, ['vendor_write_requester']);
  const ownPlan = me?.user?.user_id && plan.requested_by === me.user.user_id;

  const head = el('div', { class: 'gate-plan-detail__head' });
  const titleBlock = el('div', { class: 'stack stack--tight' });
  titleBlock.append(
    el('div', { class: 'cluster' }, [
      planStateChip(plan.state),
      el('span', { class: 'mono provenance', text: plan.plan_id }),
      plan.critical ? criticalityChip('critical') : null,
      plan.four_eyes ? el('span', { class: 'chip chip--sev', dataset: { severity: 'high' }, text: t('gate.inbox.four_eyes') }) : null,
    ].filter(Boolean)),
    el('h3', { class: 'gate-plan-detail__title', text: `${plan.target_id || '—'} · ${plan.asset_id || '—'}` }),
    el('div', { class: 'gate-plan-detail__meta' }, [
      protocolChips([plan.protocol]),
      el('span', { text: t('gate.inbox.operations_count', { count: Array.isArray(plan.operations) ? plan.operations.length : 0 }) }),
      el('span', { text: t('gate.inbox.requester', { user: plan.requested_by || '—' }) }),
    ])
  );
  head.append(titleBlock);

  const actions = el('div', { class: 'gate-plan-detail__actions' });
  if (plan.state === 'pending') {
    if (canApprove) {
      const approve = el('button', { type: 'button', class: 'btn btn--primary btn--sm' });
      approve.append(icon('check', { size: 'sm' }), el('span', { text: t('gate.inbox.approve') }));
      if (windowExpired) {
        approve.disabled = true;
        approve.title = t('gate.inbox.approve_window_expired');
      } else {
        approve.addEventListener('click', () => {
          openApproveDialog(plan, {
            onApproved: async (result) => {
              if (result && result.token && result.token.token) {
                openTokenRevealDialog({
                  token: result.token.token,
                  expiresAt: result.token.expires_at,
                  plan: result.plan || plan,
                });
                toast({ variant: 'success', title: t('gate.inbox.approved_toast_title'), text: t('gate.inbox.approved_toast_text') });
              } else {
                toast({
                  variant: 'success',
                  title: t('gate.inbox.partial_toast_title'),
                  text: t('gate.inbox.partial_toast_text'),
                });
              }
              await ctx.reloadAll();
            },
          });
        });
      }
      actions.append(approve);
    }
    if (canApprove) {
      const reject = el('button', { type: 'button', class: 'btn btn--danger btn--sm', text: t('gate.inbox.reject') });
      reject.addEventListener('click', () => {
        openRejectDialog(plan, {
          onRejected: async () => {
            toast({ variant: 'success', title: t('gate.inbox.rejected_toast_title'), text: t('gate.inbox.rejected_toast_text') });
            await ctx.reloadAll();
          },
        });
      });
      actions.append(reject);
    }
    if (canRequest && ownPlan) {
      const cancel = el('button', { type: 'button', class: 'btn btn--ghost btn--sm', text: t('gate.inbox.cancel_request') });
      cancel.addEventListener('click', () => {
        openCancelDialog(plan, {
          onCancelled: async () => {
            toast({ variant: 'success', title: t('gate.inbox.cancelled_toast_title') });
            await ctx.reloadAll();
          },
        });
      });
      actions.append(cancel);
    }
    if (!canApprove) {
      actions.append(el('span', { class: 'provenance', text: t('gate.inbox.approve_role_hint') }));
    }
  } else if (plan.state === 'approved') {
    actions.append(el('span', { class: 'chip chip--status', dataset: { status: 'resolved' }, text: t('gate.inbox.approved_token_hint') }));
  } else if (plan.state === 'executed') {
    actions.append(el('span', { class: 'chip chip--status', dataset: { status: 'resolved' }, text: t('enum.plan_state.executed') }));
  }
  head.append(actions);
  wrapper.append(head);

  if (windowExpired && plan.state === 'pending') {
    wrapper.append(
      banner({
        variant: 'warn',
        title: t('gate.inbox.window_banner_title'),
        text: t('gate.inbox.window_banner_text'),
      })
    );
  }

  wrapper.append(
    el('div', { class: 'gate-plan-detail__grid' }, [
      metaField(t('gate.inbox.field_target'), plan.target_id, true),
      metaField(t('gate.inbox.field_asset'), plan.asset_id, true),
      metaField(t('gate.inbox.field_protocol'), protocolLabel(plan.protocol)),
      metaField(t('gate.inbox.field_ticket'), plan.ticket_ref || '—', true),
      metaField(t('gate.inbox.field_requested'), formatDateTime(plan.requested_at)),
      metaField(t('gate.inbox.field_window'), `${formatDateTime(plan.window_start)} – ${formatDateTime(plan.window_end)}`),
      metaField(t('gate.inbox.field_plan_hash'), shortenHash(plan.plan_hash), true, plan.plan_hash),
      metaField(t('gate.inbox.field_updated'), formatDateTime(plan.updated_at)),
    ])
  );

  wrapper.append(
    el('section', { class: 'gate-reason' }, [
      el('h4', { class: 'gate-reason__label', text: t('gate.inbox.reason_label') }),
      el('p', { class: 'gate-reason__text', text: plan.reason || t('gate.inbox.reason_missing') }),
    ])
  );

  // Operations: exact address + value, the only thing the gate will execute.
  const opRows = Array.isArray(plan.operations) ? plan.operations : [];
  const operationsTable = dataTable({
    columns: [
      { key: 'operation_id', label: t('gate.inbox.col_op'), render: (op) => el('span', { class: 'mono', text: op.operation_id || '—' }) },
      { key: 'function', label: t('gate.inbox.col_function'), render: (op) => el('span', { class: 'mono', text: op.function || '—' }) },
      { key: 'address', label: t('gate.inbox.col_address'), render: (op) => el('span', { class: 'mono', text: op.address || '—' }) },
      {
        key: 'value',
        label: t('gate.inbox.col_values'),
        render: (op) =>
          el('span', { class: 'gate-op-flow' }, [
            el('span', { class: 'gate-op-flow__from', text: op.current_value || '—' }),
            icon('arrow-right', { size: 'sm' }),
            el('span', { class: 'gate-op-flow__to', text: op.new_value || '—' }),
            op.unit ? el('span', { class: 'provenance', text: unitLabel(op.unit) || op.unit }) : null,
          ].filter(Boolean)),
      },
      { key: 'notes', label: t('gate.inbox.col_note'), render: (op) => op.notes || '—' },
    ],
    rows: opRows,
    caption: t('gate.inbox.operations_caption'),
  });
  wrapper.append(sectionBlock(t('gate.inbox.operations_section'), operationsTable));

  wrapper.append(buildFourEyes(plan, approvals));

  wrapper.append(
    el('p', {
      class: 'provenance',
      text: t('gate.inbox.audit_note'),
    })
  );
  return wrapper;
}

function buildFourEyes(plan, approvals) {
  const block = el('section', { class: 'gate-eyes', dataset: { complete: String(approvals.complete), required: String(approvals.fourEyes) } });
  block.append(
    el('div', { class: 'gate-eyes__head' }, [
      el('h4', { class: 'panel__title', text: t('gate.inbox.four_eyes_title') }),
      approvals.fourEyes
        ? el('span', { class: 'chip chip--sev', dataset: { severity: approvals.complete ? 'low' : 'high' }, text: t('gate.inbox.four_eyes_chip', { count: approvals.count, required: approvals.required }) })
        : el('span', { class: 'chip chip--category', text: t('gate.inbox.single_approval') }),
    ])
  );
  const statusText = approvals.fourEyes
    ? approvals.complete
      ? t('gate.inbox.four_eyes_complete')
      : t('gate.inbox.four_eyes_pending', { remaining: approvals.required - approvals.count, master: approvals.masterApproved ? t('gate.inbox.master_present') : t('gate.inbox.master_missing') })
    : t('gate.inbox.four_eyes_not_required');
  block.append(el('p', { class: 'provenance', text: statusText }));

  const list = Array.isArray(plan.approvals) ? plan.approvals : [];
  if (list.length === 0) {
    block.append(el('p', { class: 'provenance', text: t('gate.inbox.no_approval_yet') }));
    return block;
  }
  const approvalsList = el('ul', { class: 'gate-eyes__list' });
  for (const approval of list) {
    const item = el('li', { class: 'gate-eyes__item' });
    item.append(
      el('span', { class: 'gate-eyes__marker', dataset: { approved: String(approval.approved === true) }, attrs: { 'aria-hidden': 'true' } }),
      el('span', { class: 'gate-eyes__main' }, [
        el('span', { class: 'gate-eyes__who', text: approval.approver_id || t('gate.common.unknown_person') }),
        el('span', { class: 'gate-eyes__meta' }, [
          el('span', { class: 'chip chip--category', text: approval.role || t('gate.inbox.role_unknown') }),
          el('span', { text: approval.approved ? t('gate.inbox.approval_given') : t('gate.inbox.approval_denied') }),
          el('span', { text: approval.mfa_used ? t('gate.inbox.mfa_confirmed') : t('gate.inbox.mfa_unproven') }),
          el('span', { text: formatDateTime(approval.at) }),
        ]),
        approval.comment ? el('span', { class: 'gate-eyes__comment', text: approval.comment }) : null,
      ].filter(Boolean))
    );
    approvalsList.append(item);
  }
  block.append(approvalsList);
  return block;
}

function selectField(id, label, options, value, onChange) {
  const field = el('div', { class: 'field' });
  field.append(el('label', { class: 'field__label', text: label, attrs: { for: id } }));
  const select = el('select', { id, class: 'select' });
  for (const option of options) {
    const optionEl = el('option', { text: option.label, attrs: { value: option.value } });
    if (String(value) === String(option.value)) optionEl.selected = true;
    select.append(optionEl);
  }
  select.addEventListener('change', () => onChange(select.value));
  field.append(select);
  return field;
}

function metaField(label, value, mono = false, title = '') {
  const field = el('div', { class: 'gate-meta' });
  field.append(
    el('span', { class: 'gate-meta__label', text: label }),
    el('span', { class: mono ? 'gate-meta__value gate-meta__value--mono' : 'gate-meta__value', text: value || '—', attrs: title ? { title } : {} })
  );
  return field;
}

function sectionBlock(title, content) {
  const section = el('section', { class: 'stack stack--tight' });
  section.append(el('h4', { class: 'gate-section__title', text: title }), content);
  return section;
}

function shortenHash(hash) {
  const value = String(hash || '');
  if (!value) return '—';
  if (value.length <= 20) return value;
  return `${value.slice(0, 12)}…${value.slice(-6)}`;
}

function emptyStateForFilters(ctx, listHost, detailHost, summary) {
  const filtered = Boolean(inbox.risk || inbox.target || inbox.state !== 'pending');
  return el('div', { class: 'panel__body' }, [
    emptyState({
      icon: 'gate',
      title: filtered ? t('gate.inbox.empty_filtered_title') : t('gate.inbox.empty_title'),
      text: filtered ? t('gate.inbox.empty_filtered_text') : t('gate.inbox.empty_text'),
      actions: [
        el('button', {
          type: 'button',
          class: 'btn btn--secondary',
          text: t('gate.inbox.show_all_states'),
          on: {
            click: () => {
              inbox.state = '';
              inbox.risk = '';
              inbox.target = '';
              void ctx.reloadAll();
            },
          },
        }),
      ],
    }),
  ]);
}
