/**
 * Language selector used by the shell, the login gate and the setup wizard.
 * The select lists every supported locale by its native name. Changing the
 * language persists it in sessionStorage; the shell reloads so module-level
 * labels are rebuilt, while the setup wizard re-renders in place.
 */
import { el } from '../core/dom.js';
import { LANGUAGES, getLanguage, setLanguage, t } from '../i18n/index.js';

let sequence = 0;

export function languageSelector({ value = getLanguage(), onChange = null, compact = false, showLabel = false, label = null } = {}) {
  sequence += 1;
  const id = `language-${sequence}`;
  const wrapper = el('div', { class: compact ? 'lang-select lang-select--compact' : 'lang-select' });
  if (showLabel) {
    wrapper.append(el('label', { class: 'lang-select__label', text: label || t('nav.language'), attrs: { for: id } }));
  }
  const select = el('select', {
    id,
    class: 'select lang-select__select',
    attrs: { 'aria-label': label || t('nav.language'), autocomplete: 'off' },
  });
  for (const language of LANGUAGES) {
    const option = el('option', { text: language.native, attrs: { value: language.code, lang: language.tag } });
    if (language.code === value) option.selected = true;
    select.append(option);
  }
  select.addEventListener('change', () => {
    const next = select.value;
    if (!setLanguage(next)) return;
    if (onChange) onChange(next);
    else window.location.reload();
  });
  wrapper.append(select);
  return wrapper;
}
