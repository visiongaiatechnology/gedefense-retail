/**
 * Formatting helpers. All timestamps from the API are UTC (RFC 3339); the UI
 * renders them in the active UI language and the site's IANA timezone when
 * known, and always keeps the precise UTC value available in the tooltip.
 *
 * Relative-time and duration labels are translated through the i18n runtime. The
 * generic `common.*` namespace is used (not `gate.*`) because these helpers are
 * shared by every view, not only the Access Gate.
 */
import { getLocaleTag, t } from '../i18n/index.js';

const FALLBACK_LOCALE = 'en-GB';
const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

const dateTimeFormatters = new Map();
const dateFormatters = new Map();
const timeFormatters = new Map();
const clockFormatters = new Map();
const weekdayFormatters = new Map();
const utcFormatters = new Map();
const numberFormatters = new Map();

function activeLocale() {
  try {
    return getLocaleTag() || FALLBACK_LOCALE;
  } catch {
    return FALLBACK_LOCALE;
  }
}

function cacheKey(timeZone) {
  return `${activeLocale()}|${timeZone || ''}`;
}

function safeTimeZone(timeZone) {
  if (!timeZone) return undefined;
  try {
    new Intl.DateTimeFormat(activeLocale(), { timeZone }).format(new Date());
    return timeZone;
  } catch {
    return undefined;
  }
}

function dateFormatter(cache, options, timeZone) {
  const zone = safeTimeZone(timeZone);
  const key = cacheKey(zone);
  if (!cache.has(key)) {
    cache.set(key, new Intl.DateTimeFormat(activeLocale(), zone ? { ...options, timeZone: zone } : options));
  }
  return cache.get(key);
}

function numberFormatter(digits) {
  const key = `${activeLocale()}|${digits}`;
  if (!numberFormatters.has(key)) {
    numberFormatters.set(
      key,
      new Intl.NumberFormat(activeLocale(), {
        minimumFractionDigits: digits,
        maximumFractionDigits: digits,
      })
    );
  }
  return numberFormatters.get(key);
}

/** @returns {Date|null} */
export function toDate(value) {
  if (value === null || value === undefined || value === '') return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

export function formatDateTime(value, timeZone) {
  const date = toDate(value);
  if (!date) return '—';
  return dateFormatter(dateTimeFormatters, { dateStyle: 'medium', timeStyle: 'short' }, timeZone).format(date);
}

export function formatDate(value, timeZone) {
  const date = toDate(value);
  if (!date) return '—';
  return dateFormatter(dateFormatters, { dateStyle: 'medium' }, timeZone).format(date);
}

export function formatTime(value, timeZone) {
  const date = toDate(value);
  if (!date) return '—';
  return dateFormatter(timeFormatters, { hour: '2-digit', minute: '2-digit' }, timeZone).format(date);
}

export function formatClock(value, timeZone) {
  const date = toDate(value);
  if (!date) return '—';
  return dateFormatter(clockFormatters, { hour: '2-digit', minute: '2-digit', second: '2-digit' }, timeZone).format(date);
}

/** Explicit UTC rendering, used in evidence and export contexts. */
export function formatUTC(value) {
  const date = toDate(value);
  if (!date) return '—';
  const formatter = dateFormatter(utcFormatters, { dateStyle: 'short', timeStyle: 'medium', timeZone: 'UTC' }, 'UTC');
  return `${formatter.format(date)} UTC`;
}

export function formatDayLabel(value, timeZone) {
  const date = toDate(value);
  if (!date) return t('common.day_unknown');
  const options = { weekday: 'short', day: 'numeric', month: 'short', year: 'numeric' };
  return dateFormatter(weekdayFormatters, options, timeZone).format(date);
}

export function dayKey(value) {
  const date = toDate(value);
  if (!date) return 'invalid';
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

export function formatRange(start, end, timeZone) {
  const from = toDate(start);
  const to = toDate(end);
  if (!from && !to) return '—';
  if (!to) return t('common.range.from', { time: formatDateTime(from, timeZone) });
  if (!from) return t('common.range.to', { time: formatDateTime(to, timeZone) });
  return `${formatDateTime(from, timeZone)} – ${formatTime(to, timeZone)}`;
}

export function formatRelative(value, now = Date.now()) {
  const date = toDate(value);
  const reference = toDate(now);
  if (!date || !reference) return '—';
  const diff = reference.getTime() - date.getTime();
  if (diff < 0) return formatDateTime(date);
  if (diff < 45_000) return t('common.relative.just_now');
  if (diff < HOUR) return t('common.relative.minutes', { count: Math.max(1, Math.round(diff / MINUTE)) });
  if (diff < DAY) return t('common.relative.hours', { count: Math.round(diff / HOUR) });
  if (diff < 7 * DAY) {
    const days = Math.round(diff / DAY);
    return days === 1 ? t('common.relative.day_one') : t('common.relative.days', { count: days });
  }
  return formatDate(date);
}

export function formatAgeMs(ms) {
  if (!Number.isFinite(ms) || ms < 0) return '—';
  if (ms < 45_000) return t('common.relative.just_now');
  if (ms < HOUR) return t('common.relative.minutes', { count: Math.max(1, Math.round(ms / MINUTE)) });
  if (ms < DAY) return t('common.relative.hours', { count: Math.max(1, Math.round(ms / HOUR)) });
  return t('common.relative.days', { count: Math.round(ms / DAY) });
}

export function formatDuration(seconds) {
  const total = Math.max(0, Math.round(Number(seconds) || 0));
  if (total < 60) return t('common.duration.seconds', { count: total });
  const minutes = Math.floor(total / 60);
  if (minutes < 60) return t('common.duration.minutes', { count: minutes });
  const hours = Math.floor(minutes / 60);
  const rest = minutes % 60;
  if (hours < 48) {
    return rest
      ? t('common.duration.hours_minutes', { hours, minutes: rest })
      : t('common.duration.hours', { count: hours });
  }
  const days = Math.floor(hours / 24);
  return days === 1 ? t('common.duration.day_one') : t('common.duration.days', { count: days });
}

export function formatNumber(value, digits = 0) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return '—';
  return numberFormatter(digits).format(Number(value));
}

/** Fixed-decimal temperature in Celsius — the canonical cold-chain unit. */
export function formatCelsius(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return '—';
  return `${formatNumber(value, 1)} °C`;
}

export function formatValue(value, unitLabel, digits = 1) {
  const number = Number(value);
  if (!Number.isFinite(number)) return '—';
  const rendered = formatNumber(number, digits);
  return unitLabel ? `${rendered} ${unitLabel}` : rendered;
}

export function formatPercent(fraction, digits = 0) {
  const number = Number(fraction);
  if (!Number.isFinite(number)) return '—';
  return `${formatNumber(number * 100, digits)} %`;
}

export function formatConfidence(fraction) {
  return formatPercent(fraction, 0);
}

export function formatCount(value) {
  return formatNumber(value, 0);
}

export function formatMB(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return '—';
  return `${formatNumber(number, 0)} MB`;
}

export function plural(count, singular, pluralForm) {
  return `${formatCount(count)} ${count === 1 ? singular : pluralForm}`;
}

export function truncateMiddle(text, maxLength = 22) {
  const value = String(text ?? '');
  if (value.length <= maxLength) return value;
  const head = Math.ceil((maxLength - 1) / 2);
  const tail = Math.floor((maxLength - 1) / 2);
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

/** Shorten a long hash for dense tables; full value belongs in details. */
export function formatHash(hash) {
  const value = String(hash ?? '');
  if (!value) return '—';
  if (value.startsWith('sha256:')) {
    const body = value.slice(7);
    return `sha256:${body.slice(0, 10)}…${body.slice(-4)}`;
  }
  if (value.length <= 20) return value;
  return `${value.slice(0, 10)}…${value.slice(-4)}`;
}

export function nowIso() {
  return new Date().toISOString();
}

export function sinceIso(hours, now = Date.now()) {
  return new Date(now - hours * HOUR).toISOString();
}

/** ISO value for a native datetime-local input, in local wall time. */
export function toLocalInputValue(value) {
  const date = toDate(value);
  if (!date) return '';
  const pad = (n) => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(
    date.getHours()
  )}:${pad(date.getMinutes())}`;
}

export function isRecent(value, maxAgeMs, now = Date.now()) {
  const date = toDate(value);
  if (!date) return false;
  return now - date.getTime() <= maxAgeMs;
}
