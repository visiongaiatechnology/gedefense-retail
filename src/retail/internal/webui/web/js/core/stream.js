/**
 * Live updates over Server-Sent Events, read with `fetch` + ReadableStream so
 * the bearer token travels in the Authorization header (the contract forbids
 * EventSource and token-in-URL). Handles heartbeat staleness, clean server
 * disconnects, exponential backoff with jitter and offline transitions.
 */
import { API_BASE, STREAM_STALE_MS } from './config.js';
import { t } from '../i18n/index.js';
import { getToken } from './auth.js';

const BACKOFF_MS = [1_000, 2_000, 4_000, 8_000, 15_000, 30_000];
const STALE_CHECK_MS = 5_000;

/**
 * @param {{onEvent?: (event: string, data: unknown) => void, onStatus?: (info: {status: string, detail: string}) => void}} handlers
 */
export function createStream({ onEvent, onStatus } = {}) {
  let stopped = true;
  let controller = null;
  let reconnectTimer = 0;
  let staleTimer = 0;
  let lastMessageAt = 0;
  let attempt = 0;
  let status = 'idle';

  function reportStatus(next, detail = '') {
    if (status === next && detail === '') return;
    const changed = status !== next;
    status = next;
    if (changed || detail) onStatus?.({ status: next, detail });
  }

  function setConnectionHint(error) {
    if (!navigator.onLine) return t('stream.device_offline');
    if (error && error.message) return t('stream.interrupted_with_error', { error: error.message });
    return t('stream.interrupted');
  }

  function clearTimers() {
    window.clearTimeout(reconnectTimer);
    reconnectTimer = 0;
    window.clearInterval(staleTimer);
    staleTimer = 0;
  }

  function scheduleReconnect(reason = '') {
    if (stopped) return;
    clearTimers();
    const delay = BACKOFF_MS[Math.min(attempt, BACKOFF_MS.length - 1)];
    const jitter = Math.round(delay * 0.2 * Math.random());
    attempt += 1;
    if (reason) {
      reportStatus(reason === 'unauthorized' ? 'unauthorized' : 'reconnecting', t('stream.reconnecting'));
    }
    reconnectTimer = window.setTimeout(() => {
      reconnectTimer = 0;
      void run();
    }, delay + jitter);
  }

  function startStaleWatch() {
    window.clearInterval(staleTimer);
    lastMessageAt = Date.now();
    staleTimer = window.setInterval(() => {
      if (stopped) return;
      const age = Date.now() - lastMessageAt;
      if (age > STREAM_STALE_MS && (status === 'live' || status === 'degraded')) {
        reportStatus('degraded', t('stream.degraded'));
      }
    }, STALE_CHECK_MS);
  }

  function handleBlock(block) {
    let event = 'message';
    const dataLines = [];
    const lines = block.split(/\r?\n/);
    for (const line of lines) {
      if (!line) continue;
      if (line.startsWith(':')) {
        lastMessageAt = Date.now();
        continue;
      }
      if (line.startsWith('event:')) {
        event = line.slice(6).trim();
      } else if (line.startsWith('data:')) {
        dataLines.push(line.slice(5).replace(/^ /, ''));
      }
    }
    if (dataLines.length === 0) return;
    const raw = dataLines.join('\n');
    let data = raw;
    try {
      data = JSON.parse(raw);
    } catch {
      /* keep raw text: a malformed frame must not kill the stream */
    }
    lastMessageAt = Date.now();
    if (status !== 'live') reportStatus('live');
    onEvent?.(event, data);
  }

  async function readStream(body) {
    const reader = body.getReader();
    const decoder = new TextDecoder('utf-8');
    let buffer = '';
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let separator = findSeparator(buffer);
        while (separator.index >= 0) {
          const block = buffer.slice(0, separator.index);
          buffer = buffer.slice(separator.index + separator.length);
          if (block.trim()) handleBlock(block);
          separator = findSeparator(buffer);
        }
        // Guard against an unbounded frame with no separator.
        if (buffer.length > 1_000_000) buffer = buffer.slice(-4096);
      }
      if (buffer.trim()) handleBlock(buffer);
    } finally {
      try {
        reader.releaseLock();
      } catch {
        /* reader already released */
      }
    }
  }

  function findSeparator(buffer) {
    const lf = buffer.indexOf('\n\n');
    const crlf = buffer.indexOf('\r\n\r\n');
    if (crlf >= 0 && (lf < 0 || crlf < lf)) return { index: crlf, length: 4 };
    if (lf >= 0) return { index: lf, length: 2 };
    return { index: -1, length: 0 };
  }

  async function run() {
    if (stopped) return;
    if (controller) controller.abort();
    controller = new AbortController();
    const localController = controller;

    reportStatus(attempt === 0 ? 'connecting' : 'reconnecting', attempt === 0 ? t('stream.connecting') : t('stream.reconnecting_detail'));
    startStaleWatch();

    try {
      const response = await fetch(`${API_BASE}/stream`, {
        method: 'GET',
        headers: {
          Accept: 'text/event-stream',
          Authorization: `Bearer ${getToken()}`,
        },
        cache: 'no-store',
        credentials: 'same-origin',
        signal: localController.signal,
      });

      if (response.status === 401) {
        reportStatus('unauthorized', t('stream.unauthorized'));
        stop();
        return;
      }
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      if (!response.body) throw new Error(t('stream.interrupted'));

      attempt = 0;
      reportStatus('live');
      await readStream(response.body);
      if (!stopped && !localController.signal.aborted) {
        scheduleReconnect();
      }
    } catch (error) {
      if (stopped || localController.signal.aborted) return;
      const networkFailure = !navigator.onLine || (error && error.name === 'TypeError');
      if (!navigator.onLine || (networkFailure && attempt >= 1)) {
        reportStatus('offline', t('stream.offline'));
      } else if (networkFailure) {
        reportStatus('reconnecting', t('stream.reconnecting_detail'));
      } else {
        reportStatus(attempt === 0 ? 'reconnecting' : 'degraded', setConnectionHint(error));
      }
      scheduleReconnect();
    }
  }

  function handleOnline() {
    if (stopped) return;
    attempt = 0;
    clearTimers();
    void run();
  }

  function handleOffline() {
    if (stopped) return;
    reportStatus('offline', t('stream.device_offline_display'));
    clearTimers();
    if (controller) controller.abort();
  }

  return {
    start() {
      if (!stopped) return;
      stopped = false;
      attempt = 0;
      window.addEventListener('online', handleOnline);
      window.addEventListener('offline', handleOffline);
      if (!navigator.onLine) {
        reportStatus('offline', t('stream.device_offline_display'));
      }
      void run();
    },
    stop() {
      stopped = true;
      clearTimers();
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
      if (controller) {
        controller.abort();
        controller = null;
      }
      reportStatus('idle');
    },
    /** Force a fresh connection (e.g. after entering a new token). */
    restart() {
      this.stop();
      this.start();
    },
    get status() {
      return status;
    },
  };
}
