/**
 * Token handling. The bearer token lives in sessionStorage only (never
 * localStorage, never a cookie, never the URL), so closing the tab ends the
 * session. Storage access is wrapped because embedded browsers can throw.
 */
import { STORAGE } from './config.js';

export function getToken() {
  try {
    return sessionStorage.getItem(STORAGE.token) || '';
  } catch {
    return '';
  }
}

export function setToken(token) {
  const value = String(token || '').trim();
  if (!value) return false;
  try {
    sessionStorage.setItem(STORAGE.token, value);
    return true;
  } catch {
    return false;
  }
}

export function clearToken() {
  try {
    sessionStorage.removeItem(STORAGE.token);
  } catch {
    /* storage unavailable: session simply stays read-only */
  }
}

export function isAuthenticated() {
  return getToken().length > 0;
}

/** Only used for a masked display in the account menu — never logged. */
export function tokenHint() {
  const token = getToken();
  if (!token) return '';
  if (token.length <= 8) return '••••';
  return `${token.slice(0, 4)}…${token.slice(-2)}`;
}

/* ------------------------------------------------------------ Access Gate */

/**
 * The Access Gate has its own short-lived session token, kept separately in
 * sessionStorage (never localStorage, cookie or URL). Approvals additionally
 * require a per-action TOTP header; the gate token alone cannot approve.
 */
export function getGateToken() {
  try {
    return sessionStorage.getItem(STORAGE.gateToken) || '';
  } catch {
    return '';
  }
}

export function setGateToken(token) {
  const value = String(token || '').trim();
  if (!value) return false;
  try {
    sessionStorage.setItem(STORAGE.gateToken, value);
    return true;
  } catch {
    return false;
  }
}

export function clearGateToken() {
  try {
    sessionStorage.removeItem(STORAGE.gateToken);
  } catch {
    /* storage unavailable: the gate stays unauthenticated */
  }
}

export function gateTokenHint() {
  const token = getGateToken();
  if (!token) return '';
  if (token.length <= 8) return '••••';
  return `${token.slice(0, 4)}…${token.slice(-2)}`;
}
