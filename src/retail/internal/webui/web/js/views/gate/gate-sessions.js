/**
 * Access Gate — active and revoked write sessions. A session is the runtime
 * authorisation the proxies check for every write; revoking it takes effect
 * immediately. The UI only documents/ends sessions, it never opens one.
 */
import { el, clear } from '../../core/dom.js';
import { gateApi } from '../../core/api.js';
import { toast } from '../../core/store.js';
import { formatDateTime, formatDuration } from '../../core/format.js';
import { gateCanApprove } from '../../core/labels.js';
import { panel } from '../../components/panel.js';
import { emptyState, errorState, skeletonPage } from '../../components/states.js';
import { icon } from '../../core/icons.js';
import { openRevokeSessionDialog } from './gate-dialogs.js';
import { t } from '../../i18n/index.js';

const FILTERS = [
  { value: 'active', label: t('gate.sessions.filter_active') },
  { value: 'all', label: t('gate.common.filter_all') },
  { value: 'revoked', label: t('gate.sessions.filter_revoked') },
];

const filters = { value: 'active' };
let loadSeq = 0;

export async function renderSessions(host, ctx) {
  const listHost = el('div');
  const summary = el('span', { class: 'filterbar__result', text: t('gate.common.loading') });

  const filterField = el('div', { class: 'field' });
  filterField.append(el('label', { class: 'field__label', text: t('gate.sessions.filter_label'), attrs: { for: 'gate-session-filter' } }));
  const select = el('select', { id: 'gate-session-filter', class: 'select' });
  for (const option of FILTERS) {
    const optionEl = el('option', { text: option.label, attrs: { value: option.value } });
    if (option.value === filters.value) optionEl.selected = true;
    select.append(optionEl);
  }
  select.addEventListener('change', () => {
    filters.value = select.value;
    void load(ctx, listHost, summary);
  });
  filterField.append(select);

  const filterBar = el('div', { class: 'gate-filters' }, [filterField, el('div', { class: 'gate-filters__actions' }, [summary])]);

  const listPanel = panel({
    title: t('gate.sessions.title'),
    sub: t('gate.sessions.subtitle'),
    actions: [
      el('button', {
        type: 'button',
        class: 'btn btn--ghost btn--sm',
        attrs: { 'aria-label': t('gate.sessions.reload_aria') },
        on: { click: () => void load(ctx, listHost, summary) },
      }, icon('refresh', { size: 'sm' }), el('span', { text: t('gate.common.reload') })),
    ],
    body: el('div', { class: 'gate-inbox__body' }, [filterBar, listHost]),
    flush: true,
  });

  host.append(el('div', { class: 'gate-single' }, listPanel));
  await load(ctx, listHost, summary);
}

async function load(ctx, listHost, summary) {
  const sequence = ++loadSeq;
  clear(listHost);
  listHost.append(el('div', { class: 'panel__body' }, skeletonPage(t('gate.sessions.loading'))));
  summary.textContent = t('gate.common.loading');
  try {
    const activeParam = filters.value === 'active' ? true : filters.value === 'revoked' ? false : undefined;
    const response = await gateApi.getSessions({ active: activeParam });
    if (sequence !== loadSeq) return;
    const sessions = Array.isArray(response.items) ? response.items : [];
    summary.textContent = sessions.length === 1 ? t('gate.sessions.count_one', { count: sessions.length }) : t('gate.sessions.count_many', { count: sessions.length });
    clear(listHost);
    if (sessions.length === 0) {
      listHost.append(
        emptyState({
          icon: 'gate',
          title: filters.value === 'active' ? t('gate.sessions.empty_active_title') : t('gate.sessions.empty_filtered_title'),
          text: t('gate.sessions.empty_text'),
          actions: [
            el('button', {
              type: 'button',
              class: 'btn btn--secondary',
              text: t('gate.sessions.show_all'),
              on: {
                click: () => {
                  filters.value = 'all';
                  void ctx.reloadAll();
                },
              },
            }),
          ],
        })
      );
      return;
    }
    const list = el('div', { class: 'gate-session-list' });
    for (const session of sessions) list.append(buildSessionRow(session, ctx, listHost, summary));
    listHost.append(list);
  } catch (error) {
    if (sequence !== loadSeq) return;
    clear(listHost);
    listHost.append(
      errorState({
        title: t('gate.sessions.error_title'),
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

function buildSessionRow(session, ctx, listHost, summary) {
  const row = el('div', { class: 'gate-session-row' });
  const main = el('div', { class: 'gate-session-row__main' });
  const active = !session.revoked && new Date(session.expires_at).getTime() > Date.now();
  const stateChip = active
    ? el('span', { class: 'chip chip--status', dataset: { status: 'resolved' }, text: t('gate.sessions.state_active') })
    : session.revoked
      ? el('span', { class: 'chip chip--status', dataset: { status: 'closed' }, text: t('gate.sessions.state_revoked') })
      : el('span', { class: 'chip chip--status', dataset: { status: 'open' }, text: t('gate.sessions.state_expired') });

  const head = el('div', { class: 'gate-session-row__head' }, [
    stateChip,
    el('span', { class: 'mono', text: session.session_id }),
    session.revoked ? el('span', { class: 'provenance', text: t('gate.sessions.revoked_by', { user: session.revoked_by || '—' }) }) : null,
  ].filter(Boolean));
  main.append(head);

  const meta = el('div', { class: 'gate-session-row__meta' });
  meta.append(
    el('span', { text: t('gate.sessions.meta_target', { value: session.target_id || '—' }) }),
    el('span', { text: t('gate.sessions.meta_user', { value: session.user_id || '—' }) }),
    el('span', { class: 'mono', text: t('gate.sessions.meta_source', { value: session.source_ip || '—' }) }),
    el('span', { text: t('gate.sessions.meta_uses', { uses: session.uses ?? 0, max: session.max_uses ?? 1 }) }),
    el('span', { text: t('gate.sessions.meta_start', { time: formatDateTime(session.created_at) }) }),
    el('span', { text: t('gate.sessions.meta_expires', { time: formatDateTime(session.expires_at) }) }),
    el('span', { text: remainingLabel(session) })
  );
  main.append(meta);
  row.append(main);

  const actions = el('div', { class: 'gate-session-row__actions' });
  if (session.plan_id) {
    const planButton = el('button', {
      type: 'button',
      class: 'btn btn--ghost btn--sm',
      text: t('gate.sessions.plan_button'),
      attrs: { 'aria-label': t('gate.sessions.plan_open_aria', { id: session.plan_id }) },
      on: { click: () => ctx.showPlan(session.plan_id) },
    });
    actions.append(planButton);
  }
  if (active && gateCanApprove(ctx.me)) {
    const revoke = el('button', {
      type: 'button',
      class: 'btn btn--danger btn--sm',
      text: t('gate.sessions.revoke'),
      attrs: { 'aria-label': t('gate.sessions.revoke_aria', { id: session.session_id }) },
    });
    revoke.addEventListener('click', () => {
      openRevokeSessionDialog(session, {
        onRevoked: async () => {
          toast({ variant: 'success', title: t('gate.sessions.revoked_toast_title'), text: t('gate.sessions.revoked_toast_text') });
          await load(ctx, listHost, summary);
          ctx.reloadStatus();
        },
      });
    });
    actions.append(revoke);
  }
  row.append(actions);
  return row;
}

function remainingLabel(session) {
  const expires = new Date(session.expires_at).getTime();
  if (!Number.isFinite(expires)) return '';
  const seconds = Math.round((expires - Date.now()) / 1000);
  if (seconds <= 0) return t('gate.sessions.ttl_expired');
  return t('gate.sessions.ttl', { duration: formatDuration(seconds) });
}
