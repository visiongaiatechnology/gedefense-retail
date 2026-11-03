/**
 * Sirdu — the GeDefense mascot easter egg. Purely local, non-blocking and
 * intentionally low-frequency: five quick clicks on the brand logo or the
 * version badge open a small dialog. The mascot also appears on the 404 page
 * and in the offline banner, never inside operational workflows.
 */
import { el } from '../core/dom.js';
import { openDialog } from './dialog.js';
import { t } from '../i18n/index.js';

const CLICK_WINDOW_MS = 2600;
const CLICK_TARGET = 5;

let eggInstalled = false;

export function sirduFigure(className = 'sirdu-figure') {
  return el('img', {
    class: className,
    attrs: {
      src: '/assets/sirdu.png',
      alt: 'Sirdu, Maskottchen von GeDefense Retail',
      width: '468',
      height: '512',
      loading: 'lazy',
      decoding: 'async',
    },
  });
}

export function openSirduDialog() {
  const content = el('div', { class: 'sirdu-dialog' });
  content.append(
    sirduFigure('sirdu-dialog__figure'),
    el('div', { class: 'sirdu-dialog__text' }, [
      el('p', { class: 'sirdu-dialog__line', text: t('sirdu.text') }),
      el('p', { class: 'provenance', text: t('sirdu.hint') }),
    ])
  );
  openDialog({
    title: t('sirdu.title'),
    eyebrow: 'GeDefense Retail',
    content,
    size: 'medium',
    actions: [{ label: t('sirdu.close'), primary: true }],
    initialFocus: '.dialog__foot button',
  });
}

/**
 * Attach the five-click egg to a brand/version element. It navigates normally
 * on every click except the fifth, which opens the dialog instead.
 */
export function installSirduEgg(element) {
  if (!element || eggInstalled) return;
  eggInstalled = true;
  let count = 0;
  let firstAt = 0;
  element.addEventListener('click', (event) => {
    const now = Date.now();
    if (!firstAt || now - firstAt > CLICK_WINDOW_MS) {
      count = 0;
      firstAt = now;
    }
    count += 1;
    if (count >= CLICK_TARGET) {
      event.preventDefault();
      event.stopPropagation();
      count = 0;
      firstAt = 0;
      openSirduDialog();
    }
  });
}
