/**
 * Central i18n runtime. Locales are plain JS modules keyed by stable message
 * keys; German is the product source language, English is the fallback for any
 * key that has not been translated yet. Language resolution order:
 *   ?lang= → sessionStorage → navigator.languages → English.
 * The language is applied to <html lang> immediately. Changing it reloads the
 * dashboard usually, while the setup wizard re-renders in place.
 */
import de from './locales/de.js';
import en from './locales/en.js';
import fr from './locales/fr.js';
import it from './locales/it.js';
import es from './locales/es.js';
import ja from './locales/ja.js';
import zh from './locales/zh.js';
import ru from './locales/ru.js';

export const LANGUAGES = [
  { code: 'en', native: 'English', tag: 'en-GB' },
  { code: 'de', native: 'Deutsch', tag: 'de-DE' },
  { code: 'fr', native: 'Français', tag: 'fr-FR' },
  { code: 'it', native: 'Italiano', tag: 'it-IT' },
  { code: 'es', native: 'Español', tag: 'es-ES' },
  { code: 'ja', native: '日本語', tag: 'ja-JP' },
  { code: 'zh', native: '中文', tag: 'zh-CN' },
  { code: 'ru', native: 'Русский', tag: 'ru-RU' },
];

const DICTIONARIES = { de, en, fr, it, es, ja, zh, ru };
const CODES = new Set(LANGUAGES.map((language) => language.code));
const STORAGE_KEY = 'gedefense.retail.lang';
const FALLBACK = 'en';

let current = detectLanguage();

function persistLanguage(code) {
  try {
    sessionStorage.setItem(STORAGE_KEY, code);
  } catch {
    /* sessionStorage can be blocked; the URL parameter still works */
  }
}

function detectLanguage() {
  try {
    const fromUrl = new URLSearchParams(window.location.search).get('lang');
    if (fromUrl && CODES.has(fromUrl.toLowerCase())) return fromUrl.toLowerCase();
  } catch {
    /* ignore malformed URLs */
  }
  try {
    const stored = sessionStorage.getItem(STORAGE_KEY);
    if (stored && CODES.has(stored)) return stored;
  } catch {
    /* ignore */
  }
  const candidates = Array.isArray(navigator.languages) && navigator.languages.length
    ? navigator.languages
    : [navigator.language || ''];
  for (const candidate of candidates) {
    const base = String(candidate || '').toLowerCase().split('-')[0];
    if (CODES.has(base)) return base;
  }
  return FALLBACK;
}

function applyDocumentLanguage() {
  if (typeof document !== 'undefined' && document.documentElement) {
    document.documentElement.lang = getLocaleTag();
    document.documentElement.dir = 'ltr';
  }
}

/** Interpolate {name} placeholders; missing params stay visible on purpose. */
export function formatMessage(message, params) {
  if (!params) return message;
  return String(message).replace(/\{(\w+)\}/g, (match, name) =>
    Object.prototype.hasOwnProperty.call(params, name) ? String(params[name]) : match
  );
}

/**
 * Translate a message key. Unknown keys fall back to English and finally to the
 * optional fallback argument (used for server-provided rule texts).
 */
export function t(key, params, fallback) {
  const primary = DICTIONARIES[current] || DICTIONARIES[FALLBACK];
  const english = DICTIONARIES[FALLBACK];
  const message = primary[key] ?? english[key] ?? fallback ?? key;
  return formatMessage(message, params);
}

/** Translate the server-side alert title/summary by rule id, with the server
 * text as fallback for unknown rules. */
export function ruleTitle(ruleId, fallback) {
  if (!ruleId) return fallback;
  return t(`rule.${ruleId}.title`, {}, fallback);
}

export function ruleSummary(ruleId, fallback) {
  if (!ruleId) return fallback;
  return t(`rule.${ruleId}.summary`, {}, fallback);
}

export function getLanguage() {
  return current;
}

export function getLocaleTag() {
  const entry = LANGUAGES.find((language) => language.code === current);
  return entry ? entry.tag : 'en-GB';
}

export function setLanguage(code, { persist = true } = {}) {
  const normalized = String(code || '').toLowerCase();
  if (!CODES.has(normalized)) return false;
  current = normalized;
  if (persist) persistLanguage(normalized);
  applyDocumentLanguage();
  return true;
}

export function languageName(code) {
  const entry = LANGUAGES.find((language) => language.code === code);
  return entry ? entry.native : code;
}

export function hasExplicitLanguage() {
  try {
    if (new URLSearchParams(window.location.search).get('lang')) return true;
  } catch {
    /* ignore */
  }
  try {
    return Boolean(sessionStorage.getItem(STORAGE_KEY));
  } catch {
    return false;
  }
}

export function isLanguage(code) {
  return CODES.has(String(code || '').toLowerCase());
}

applyDocumentLanguage();

/** Alias used by server-text helpers: template with fallback. */
export function template(key, params, fallback) {
  return t(key, params, fallback);
}
