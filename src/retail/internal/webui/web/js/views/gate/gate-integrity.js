/**
 * Access Gate — setpoint integrity and automatic recovery (read-only). Shows
 * the poll interval, configured references and their observed/expected values,
 * recovery counters and per-row recovery state. Mismatch is a review task, not
 * an automatic asset action; automatic recovery is explicitly opt-in per
 * register and off by default. The panel never offers write/allow controls.
 */
import { el } from '../../core/dom.js';
import { formatCount, formatDateTime, formatDuration } from '../../core/format.js';
import { readOnlyBadge } from '../../components/chips.js';
import { dataTable } from '../../components/table.js';
import { panel } from '../../components/panel.js';
import { banner, emptyState, errorState } from '../../components/states.js';
import { t } from '../../i18n/index.js';

const STATE_KEYS = {
  ok: 'gate.integrity.state.ok',
  mismatch: 'gate.integrity.state.mismatch',
  unreadable: 'gate.integrity.state.unreadable',
  stale: 'gate.integrity.state.stale',
};

const STATE_SEVERITY = {
  ok: 'low',
  mismatch: 'critical',
  unreadable: 'high',
  stale: 'medium',
};

function stateChip(state) {
  const value = STATE_KEYS[state] ? state : 'stale';
  return el('span', {
    class: 'chip chip--sev',
    dataset: { severity: STATE_SEVERITY[value] },
    text: t(STATE_KEYS[value]),
  });
}

function normalizeReference(entry) {
  const ref = entry || {};
  const recovery = ref.recovery || {};
  const state = ['ok', 'mismatch', 'unreadable', 'stale'].includes(ref.state) ? ref.state : 'stale';
  return {
    targetId: ref.target_id || '—',
    fc: ref.fc || '',
    register: ref.register === undefined || ref.register === null ? '—' : String(ref.register),
    unit: ref.unit || '',
    reference: ref.reference === undefined || ref.reference === null ? '—' : String(ref.reference),
    current: ref.current === undefined || ref.current === null ? '—' : String(ref.current),
    state,
    lastReadAt: ref.last_read_at || '',
    confirmedMismatches: Number(ref.confirmed_mismatches) || 0,
    recovery: {
      enabled: recovery.enabled === true,
      lastAttemptAt: recovery.last_attempt_at || '',
      lastResult: recovery.last_result || '',
      cooldownUntil: recovery.cooldown_until || '',
    },
  };
}

function recoveryCell(ref) {
  const wrapper = el('div', { class: 'gate-integrity__recovery' });
  wrapper.append(
    el('span', {
      class: ref.recovery.enabled ? 'chip chip--category' : 'chip chip--muted',
      text: ref.recovery.enabled ? t('gate.integrity.recovery.enabled') : t('gate.integrity.recovery.disabled'),
    })
  );
  if (ref.recovery.lastResult) {
    wrapper.append(el('span', { class: 'provenance', text: t('gate.integrity.recovery.result', { result: ref.recovery.lastResult }) }));
  }
  if (ref.recovery.lastAttemptAt) {
    wrapper.append(el('span', { class: 'provenance', text: formatDateTime(ref.recovery.lastAttemptAt) }));
  }
  if (ref.recovery.cooldownUntil) {
    wrapper.append(el('span', { class: 'provenance', text: t('gate.integrity.recovery.cooldown', { until: formatDateTime(ref.recovery.cooldownUntil) }) }));
  }
  if (!ref.recovery.enabled && !ref.recovery.lastResult) {
    wrapper.append(el('span', { class: 'provenance', text: t('gate.integrity.recovery.none') }));
  }
  return wrapper;
}

function buildTable(references) {
  const rows = references.map((ref) => ({
    ...ref,
    registerLabel: [ref.fc ? `fc${ref.fc}` : '', ref.register].filter(Boolean).join(' · '),
  }));
  return dataTable({
    caption: t('gate.integrity.caption'),
    rows,
    columns: [
      { key: 'targetId', label: t('gate.integrity.column.target'), render: (row) => el('span', { class: 'mono', text: row.targetId }) },
      {
        key: 'registerLabel',
        label: t('gate.integrity.column.register'),
        render: (row) => el('span', { class: 'mono', text: row.registerLabel || '—' }),
      },
      { key: 'unit', label: t('gate.integrity.column.unit'), render: (row) => row.unit || '—' },
      { key: 'reference', label: t('gate.integrity.column.reference'), render: (row) => el('span', { class: 'mono', text: row.reference }) },
      { key: 'current', label: t('gate.integrity.column.current'), render: (row) => el('span', { class: 'mono', text: row.current }) },
      { key: 'state', label: t('gate.integrity.column.state'), render: (row) => stateChip(row.state) },
      {
        key: 'lastReadAt',
        label: t('gate.integrity.column.last_read'),
        render: (row) => el('span', { text: row.lastReadAt ? formatDateTime(row.lastReadAt) : '—' }),
      },
      { key: 'recovery', label: t('gate.integrity.column.recovery'), render: (row) => recoveryCell(row) },
    ],
  });
}

/**
 * Build the read-only integrity panel for the Gate status tab.
 * @param {{enabled?:boolean,interval_s?:number,references?:object[],recovery?:object}|null} integrity
 * @param {Error|null} error
 * @param {() => void} onRetry
 */
export function buildIntegrityPanel(integrity, error, onRetry) {
  const title = t('gate.integrity.title');
  const actions = [
    readOnlyBadge(),
    el('button', {
      type: 'button',
      class: 'btn btn--ghost btn--sm',
      text: t('gate.common.reload'),
      on: { click: () => onRetry?.() },
    }),
  ];

  if (error) {
    return panel({
      title,
      sub: t('gate.integrity.subtitle'),
      actions,
      body: errorState({
        title: t('gate.integrity.error_title'),
        error,
        actions: [
          el('button', {
            type: 'button',
            class: 'btn btn--secondary btn--sm',
            text: t('gate.common.reload'),
            on: { click: () => onRetry?.() },
          }),
        ],
      }),
    });
  }
  if (!integrity) {
    return panel({
      title,
      sub: t('gate.integrity.subtitle'),
      actions,
      body: el('p', { class: 'provenance', text: t('gate.integrity.unavailable') }),
    });
  }

  const data = integrity || {};
  const enabled = data.enabled === true;
  const references = Array.isArray(data.references) ? data.references.map(normalizeReference) : [];
  const recovery = data.recovery || {};
  const interval = Number(data.interval_s);
  const body = el('div', { class: 'stack' });

  body.append(
    el('div', { class: 'cluster gate-integrity__meta' }, [
      el('span', {
        class: enabled ? 'chip chip--status' : 'chip chip--muted',
        dataset: { status: enabled ? 'resolved' : 'closed' },
        text: enabled ? t('gate.integrity.enabled') : t('gate.integrity.disabled'),
      }),
      el('span', {
        class: 'provenance',
        text: Number.isFinite(interval) && interval > 0
          ? t('gate.integrity.interval', { interval: formatDuration(interval) })
          : t('gate.integrity.interval_unknown'),
      }),
      el('span', {
        class: 'provenance',
        text: t('gate.integrity.recovery_counts', {
          hour: formatCount(recovery.actions_last_hour),
          day: formatCount(recovery.actions_last_day),
        }),
      }),
    ])
  );

  body.append(
    banner({
      variant: 'info',
      title: t('gate.integrity.recovery_note_title'),
      text: t('gate.integrity.recovery_note'),
    })
  );

  if (!enabled) {
    body.append(
      banner({
        variant: 'info',
        title: t('gate.integrity.disabled_title'),
        text: t('gate.integrity.disabled_text'),
      })
    );
  } else if (references.length === 0) {
    body.append(
      emptyState({
        icon: 'shield',
        title: t('gate.integrity.empty_title'),
        text: t('gate.integrity.empty_text'),
      })
    );
  } else {
    const mismatches = references.filter((ref) => ref.state === 'mismatch');
    if (mismatches.length > 0) {
      body.append(
        banner({
          variant: 'warn',
          title: t('gate.integrity.mismatch_title'),
          text: t('gate.integrity.mismatch_text', { count: formatCount(mismatches.length) }),
        })
      );
    }
    body.append(buildTable(references));
    body.append(
      el('p', {
        class: 'provenance',
        text: t('gate.integrity.footer_note'),
      })
    );
  }

  return panel({
    title,
    sub: t('gate.integrity.subtitle'),
    actions,
    body,
    flush: false,
  });
}
