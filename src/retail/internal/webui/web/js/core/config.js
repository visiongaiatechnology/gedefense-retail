/**
 * Static application configuration: API base, storage keys, navigation model
 * and timing budgets. No endpoint data and no demo content lives here.
 */
import { t } from '../i18n/index.js';

export const API_BASE = '/api/v1';
/** The Access Gate is a separate service with its own API prefix and session. */
export const GATE_API_BASE = '/api/v1/gate';

export const STORAGE = {
  token: 'gedefense.retail.token',
  gateToken: 'gedefense.retail.gateToken',
  site: 'gedefense.retail.site',
};

/** A view is considered out of date when no successful read happened. */
export const STALE_AFTER_MS = 75_000;
/** The gateway sends a heartbeat every 15 s; 45 s without one is degraded. */
export const STREAM_STALE_MS = 45_000;
/** Default time window for live-list reads (facts only, no decoration). */
export const FEED_WINDOW_HOURS = 24;

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

/**
 * Navigation model. `primary` entries stay in the phone bottom bar; the rest
 * are reachable through the "Mehr" sheet. Labels are German product language.
 */
export const NAV = [
  {
    id: 'overview',
    path: '/overview',
    title: t('nav.overview'),
    short: 'Lage',
    icon: 'dashboard',
    primary: true,
    description: 'Lagebild aller Filialen, Kollektoren und offenen Alarme.',
  },
  {
    id: 'site',
    path: '/site',
    title: t('nav.site'),
    short: t('nav.short.site'),
    icon: 'store',
    primary: false,
    description: t('nav.desc.site'),
  },
  {
    id: 'assets',
    path: '/assets',
    title: t('nav.assets'),
    short: t('nav.short.assets'),
    icon: 'layers',
    primary: false,
    description: t('nav.desc.assets'),
  },
  {
    id: 'coldchain',
    path: '/coldchain',
    title: t('nav.coldchain'),
    short: t('nav.short.coldchain'),
    icon: 'thermometer',
    primary: true,
    description: t('nav.desc.coldchain'),
  },
  {
    id: 'access',
    path: '/access',
    title: t('nav.access'),
    short: t('nav.short.access'),
    icon: 'key',
    primary: true,
    description: t('nav.desc.access'),
  },
  {
    id: 'gate',
    path: '/gate',
    title: t('nav.gate'),
    short: t('nav.short.gate'),
    icon: 'gate',
    primary: false,
    description: t('nav.desc.gate'),
  },
  {
    id: 'threat',
    path: '/threat',
    title: t('nav.threat'),
    short: t('nav.short.threat'),
    icon: 'radar',
    primary: true,
    description: t('nav.desc.threat'),
  },
  {
    id: 'integrity',
    path: '/integrity',
    title: t('nav.integrity'),
    short: t('nav.short.integrity'),
    icon: 'shield',
    primary: false,
    description: t('nav.desc.integrity'),
  },
  {
    id: 'incidents',
    path: '/incidents',
    title: t('nav.incidents'),
    short: t('nav.short.incidents'),
    icon: 'case',
    primary: false,
    description: t('nav.desc.incidents'),
  },
  {
    id: 'setup',
    path: '/setup',
    title: t('setup.title'),
    short: t('setup.title'),
    icon: 'settings',
    primary: false,
    hidden: true,
    description: 'First-run setup wizard (loopback only).',
  },
];

export const NAV_BY_ID = new Map(NAV.map((item) => [item.id, item]));

export const TIME_WINDOWS = [
  { id: '1h', label: '1 h', hours: 1 },
  { id: '6h', label: '6 h', hours: 6 },
  { id: '24h', label: '24 h', hours: 24 },
  { id: '7d', label: '7 Tage', hours: 24 * 7 },
];

export const DEFAULT_TIME_WINDOW = '24h';

/** Bounded list reads: the API caps at 200; the UI never asks for more. */
export const LIST_LIMIT = 200;

/** Note text limit mirrors the API's small, non-sensitive free-text field. */
export const NOTE_MAX_LENGTH = 2000;
