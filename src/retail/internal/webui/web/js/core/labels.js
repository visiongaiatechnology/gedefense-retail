/**
 * Translated product language for every closed enum in the API contract. The UI
 * never invents a value: unknown enum members stay visible as their raw token
 * (marked) instead of being silently mapped to a friendly word.
 *
 * Every map stores an i18n message key; labels are resolved through `t()` at
 * call time (and at option-list build time), so the language switch and the
 * English fallback of the runtime both apply. Protocol names and unit symbols
 * are not translated: they are proper names / SI symbols.
 */
import { t } from '../i18n/index.js';

const SEVERITY = {
  info: 'enum.severity.info',
  low: 'enum.severity.low',
  medium: 'enum.severity.medium',
  high: 'enum.severity.high',
  critical: 'enum.severity.critical',
};

const CATEGORY = {
  access: 'enum.category.access',
  network: 'enum.category.network',
  thermal: 'enum.category.thermal',
  integrity: 'enum.category.integrity',
  device_health: 'enum.category.device_health',
  data_quality: 'enum.category.data_quality',
};

const ALERT_STATUS = {
  open: 'enum.alert_status.open',
  acknowledged: 'enum.alert_status.acknowledged',
  investigating: 'enum.alert_status.investigating',
  resolved: 'enum.alert_status.resolved',
  closed: 'enum.alert_status.closed',
  false_positive: 'enum.alert_status.false_positive',
};

const INCIDENT_STATUS = {
  open: 'enum.incident_status.open',
  investigating: 'enum.incident_status.investigating',
  contained: 'enum.incident_status.contained',
  resolved: 'enum.incident_status.resolved',
  closed: 'enum.incident_status.closed',
};

const SITE_STATUS = {
  online: 'enum.site_status.online',
  degraded: 'enum.site_status.degraded',
  offline: 'enum.site_status.offline',
  unknown: 'enum.site_status.unknown',
};

const QUALITY = {
  good: 'enum.quality.good',
  uncertain: 'enum.quality.uncertain',
  bad: 'enum.quality.bad',
  missing: 'enum.quality.missing',
  frozen: 'enum.quality.frozen',
  stale: 'enum.quality.stale',
  clock_uncertain: 'enum.quality.clock_uncertain',
  mixed: 'enum.quality.mixed',
};

const ASSET_TYPE = {
  refrigeration_controller: 'enum.asset_type.refrigeration_controller',
  plc: 'enum.asset_type.plc',
  hmi: 'enum.asset_type.hmi',
  sensor_gateway: 'enum.asset_type.sensor_gateway',
  bms: 'enum.asset_type.bms',
  network_device: 'enum.asset_type.network_device',
  edge_gateway: 'enum.asset_type.edge_gateway',
  cooling_rack: 'enum.asset_type.cooling_rack',
  cold_room: 'enum.asset_type.cold_room',
  unknown: 'enum.asset_type.unknown',
};

const CRITICALITY = {
  low: 'enum.criticality.low',
  medium: 'enum.criticality.medium',
  high: 'enum.criticality.high',
  critical: 'enum.criticality.critical',
};

const ZONE_KIND = {
  ot_process: 'enum.zone_kind.ot_process',
  ot_monitoring: 'enum.zone_kind.ot_monitoring',
  retail_it: 'enum.zone_kind.retail_it',
  management: 'enum.zone_kind.management',
  external_maintenance: 'enum.zone_kind.external_maintenance',
  unknown: 'enum.zone_kind.unknown',
};

/** Trust-boundary order: external access first, process last. */
export const ZONE_KIND_ORDER = [
  'external_maintenance',
  'management',
  'retail_it',
  'ot_monitoring',
  'ot_process',
  'unknown',
];

const WINDOW_STATUS = {
  planned: 'enum.window_status.planned',
  active: 'enum.window_status.active',
  closed: 'enum.window_status.closed',
  cancelled: 'enum.window_status.cancelled',
};

const EVENT_KIND = {
  telemetry: 'enum.event_kind.telemetry',
  flow: 'enum.event_kind.flow',
  asset_seen: 'enum.event_kind.asset_seen',
  device_health: 'enum.event_kind.device_health',
  access_session: 'enum.event_kind.access_session',
  write_attempt: 'enum.event_kind.write_attempt',
  config_change: 'enum.event_kind.config_change',
  integrity: 'enum.event_kind.integrity',
  clock_skew: 'enum.event_kind.clock_skew',
};

const TIMELINE_KIND = {
  alert: 'enum.timeline_kind.alert',
  event: 'enum.timeline_kind.event',
  access: 'enum.timeline_kind.access',
  incident: 'enum.timeline_kind.incident',
};

/** Protocol names are proper names and stay untranslated. */
const PROTOCOL = {
  modbus_tcp: 'Modbus TCP',
  mqtt: 'MQTT',
  bacnet_ip: 'BACnet/IP',
  snmp: 'SNMP',
  snmp_v3: 'SNMPv3',
  opcua: 'OPC UA',
  pcap: 'PCAP',
  http: 'HTTP(S)',
  https: 'HTTP(S)',
  arp: 'ARP',
  unknown: 'enum.protocol.unknown',
};

const UNIT = {
  celsius: '°C',
  kelvin: 'K',
  percent: '%',
  kwh: 'kWh',
  bar: 'bar',
  rpm: 'rpm',
  boolean: '',
  seconds: 's',
  count: 'enum.unit.count',
  unknown: '',
};

const COLLECTION = {
  passive_tap: 'enum.collection.passive_tap',
  read_only_poll: 'enum.collection.read_only_poll',
  operator_export: 'enum.collection.operator_export',
};

const DQ_KIND = {
  frozen: 'enum.dq_kind.frozen',
  gap: 'enum.dq_kind.gap',
  clock_skew: 'enum.dq_kind.clock_skew',
  divergence: 'enum.dq_kind.divergence',
};

const LIMIT_KIND = {
  below_min: 'enum.limit_kind.below_min',
  above_max: 'enum.limit_kind.above_max',
};

const INTEGRITY_SUBJECT = {
  controller_parameters: 'enum.integrity_subject.controller_parameters',
  firmware: 'enum.integrity_subject.firmware',
  configuration: 'enum.integrity_subject.configuration',
};

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const STATUS_RANK = { open: 5, investigating: 4, acknowledged: 3, contained: 3, resolved: 2, closed: 1, false_positive: 0 };

/** Resolve an enum label; unknown values stay visible and marked. */
export function labelLookup(map, value, fallback = '—') {
  if (value === null || value === undefined || value === '') return fallback;
  const key = String(value);
  if (Object.prototype.hasOwnProperty.call(map, key)) {
    const message = map[key];
    // Protocol names and unit symbols are literals; keys always contain a dot.
    return message.includes('.') ? t(message) : message;
  }
  return t('enum.unknown_value', { value: key });
}

export const severityLabel = (value) => labelLookup(SEVERITY, value, t('enum.fallback.unknown'));
export const categoryLabel = (value) => labelLookup(CATEGORY, value, '—');
export const alertStatusLabel = (value) => labelLookup(ALERT_STATUS, value, '—');
export const incidentStatusLabel = (value) => labelLookup(INCIDENT_STATUS, value, '—');
export const siteStatusLabel = (value) => labelLookup(SITE_STATUS, value, t('enum.fallback.unknown'));
export const qualityLabel = (value) => labelLookup(QUALITY, value, t('enum.fallback.unknown'));
export const assetTypeLabel = (value) => labelLookup(ASSET_TYPE, value, t('enum.fallback.unknown'));
export const criticalityLabel = (value) => labelLookup(CRITICALITY, value, '—');
export const zoneKindLabel = (value) => labelLookup(ZONE_KIND, value, t('enum.fallback.unknown'));
export const windowStatusLabel = (value) => labelLookup(WINDOW_STATUS, value, '—');
export const eventKindLabel = (value) => labelLookup(EVENT_KIND, value, '—');
export const timelineKindLabel = (value) => labelLookup(TIMELINE_KIND, value, '—');
export const protocolLabel = (value) => labelLookup(PROTOCOL, value, String(value ?? '—'));
export const unitLabel = (value) => labelLookup(UNIT, value, String(value ?? ''));
export const collectionLabel = (value) => labelLookup(COLLECTION, value, String(value ?? '—'));
export const dataQualityKindLabel = (value) => labelLookup(DQ_KIND, value, t('enum.fallback.data_quality'));
export const limitKindLabel = (value) => labelLookup(LIMIT_KIND, value, String(value ?? t('enum.fallback.limit')));
export const integritySubjectLabel = (value) => labelLookup(INTEGRITY_SUBJECT, value, String(value ?? '—'));

export function severityRank(value) {
  return SEVERITY_RANK[value] ?? -1;
}

export function statusRank(value) {
  return STATUS_RANK[value] ?? -1;
}

/** Accessibility tone for a confidence value: never colour alone in the UI. */
export function confidenceTone(confidence) {
  const value = Number(confidence);
  if (!Number.isFinite(value)) return 'neutral';
  if (value >= 0.75) return 'high';
  if (value >= 0.5) return 'medium';
  return 'low';
}

/** Quality classes that require operator attention in dense lists. */
export function qualityNeedsAttention(quality) {
  return quality === 'bad' || quality === 'frozen' || quality === 'uncertain' || quality === 'clock_uncertain';
}

export function isOpenAlert(status) {
  return status === 'open' || status === 'acknowledged' || status === 'investigating';
}

export function isOpenIncident(status) {
  return status !== 'resolved' && status !== 'closed';
}

function toOptions(map) {
  return Object.entries(map).map(([value, message]) => ({
    value,
    label: message.includes('.') ? t(message) : message,
  }));
}

/** Filter option lists derived from the same enum maps as the labels. */
export const ASSET_TYPE_OPTIONS = toOptions(ASSET_TYPE);
export const CRITICALITY_OPTIONS = toOptions(CRITICALITY);
export const SEVERITY_OPTIONS = toOptions(SEVERITY);
export const CATEGORY_OPTIONS = toOptions(CATEGORY);
export const ALERT_STATUS_OPTIONS = toOptions(ALERT_STATUS);
export const INCIDENT_STATUS_OPTIONS = toOptions(INCIDENT_STATUS);
export const WINDOW_STATUS_OPTIONS = toOptions(WINDOW_STATUS);
export const ZONE_KIND_OPTIONS = toOptions(ZONE_KIND);
export const PROTOCOL_OPTIONS = toOptions(PROTOCOL);

/* ------------------------------------------------------------- Access Gate */

const PLAN_STATE = {
  pending: 'enum.plan_state.pending',
  approved: 'enum.plan_state.approved',
  rejected: 'enum.plan_state.rejected',
  expired: 'enum.plan_state.expired',
  executed: 'enum.plan_state.executed',
  cancelled: 'enum.plan_state.cancelled',
};

const GATE_ROLE = {
  vendor_read: 'enum.gate_role.vendor_read',
  vendor_write_requester: 'enum.gate_role.vendor_write_requester',
  approver: 'enum.gate_role.approver',
  master_admin: 'enum.gate_role.master_admin',
  auditor: 'enum.gate_role.auditor',
};

const GATE_USER_KIND = {
  vendor: 'enum.gate_user_kind.vendor',
  operator: 'enum.gate_user_kind.operator',
  admin: 'enum.gate_user_kind.admin',
};

const DENY_REASON = {
  no_session: 'enum.deny_reason.no_session',
  session_expired: 'enum.deny_reason.session_expired',
  session_revoked: 'enum.deny_reason.session_revoked',
  wrong_source: 'enum.deny_reason.wrong_source',
  wrong_target: 'enum.deny_reason.wrong_target',
  not_approved: 'enum.deny_reason.not_approved',
  operation_not_approved: 'enum.deny_reason.operation_not_approved',
  value_mismatch: 'enum.deny_reason.value_mismatch',
  address_mismatch: 'enum.deny_reason.address_mismatch',
  outside_window: 'enum.deny_reason.outside_window',
  token_invalid: 'enum.deny_reason.token_invalid',
  token_expired: 'enum.deny_reason.token_expired',
  token_used: 'enum.deny_reason.token_used',
  mfa_required: 'enum.deny_reason.mfa_required',
  policy_missing: 'enum.deny_reason.policy_missing',
  failsafe_clock: 'enum.deny_reason.failsafe_clock',
  failsafe_store: 'enum.deny_reason.failsafe_store',
};

const TARGET_STATE = {
  listening: 'enum.target_state.listening',
  connected: 'enum.target_state.connected',
  degraded: 'enum.target_state.degraded',
  failed: 'enum.target_state.failed',
  stopped: 'enum.target_state.stopped',
  unknown: 'enum.target_state.unknown',
};

export const planStateLabel = (value) => labelLookup(PLAN_STATE, value, String(value ?? '—'));
export const gateRoleLabel = (value) => labelLookup(GATE_ROLE, value, String(value ?? '—'));
export const gateUserKindLabel = (value) => labelLookup(GATE_USER_KIND, value, String(value ?? '—'));
export const denyReasonLabel = (value) => labelLookup(DENY_REASON, value, String(value ?? t('enum.fallback.reason')));
export const targetStateLabel = (value) => labelLookup(TARGET_STATE, value, String(value ?? t('enum.fallback.unknown')));

export const PLAN_STATE_OPTIONS = toOptions(PLAN_STATE);
export const DENY_REASON_OPTIONS = toOptions(DENY_REASON);
export const GATE_ROLE_OPTIONS = toOptions(GATE_ROLE);

export const GATE_APPROVER_ROLES = ['approver', 'master_admin'];

/** Roles carried by the gate session (from /auth/me). */
export function gateUserRoles(me) {
  const roles = me?.user?.roles;
  return Array.isArray(roles) ? roles : [];
}

export function gateHasAnyRole(me, roles) {
  const current = gateUserRoles(me);
  return roles.some((role) => current.includes(role));
}

export function gateCanApprove(me) {
  return gateHasAnyRole(me, GATE_APPROVER_ROLES);
}

/** Four-eyes requirement and progress, derived only from the plan payload. */
export function planApprovalSummary(plan) {
  const required = planNeedsFourEyes(plan) ? 2 : 1;
  const approvals = Array.isArray(plan?.approvals) ? plan.approvals : [];
  const distinct = new Set();
  let masterApproved = false;
  for (const approval of approvals) {
    if (!approval || approval.approved !== true) continue;
    distinct.add(String(approval.approver_id || ''));
    if (approval.role === 'master_admin') masterApproved = true;
  }
  const count = distinct.size;
  return {
    required,
    count,
    // Four-eyes is only complete when a distinct master_admin approval exists.
    complete: count >= required && (required === 1 || masterApproved),
    masterApproved,
    fourEyes: required > 1,
  };
}

export function planNeedsFourEyes(plan) {
  return Boolean(plan && (plan.four_eyes === true || plan.critical === true));
}

/** Severity filter is derived (the API has no plan severity field). */
export function planRisk(plan) {
  if (!plan) return 'standard';
  if (plan.critical === true) return 'critical';
  if (plan.four_eyes === true) return 'four_eyes';
  return 'standard';
}
