/**
 * Filter bar and segmented controls. Controls are native form elements with
 * real labels; the search field is the view's primary search for "/".
 */
import { el, debounce, uid } from '../core/dom.js';
import { t } from '../i18n/index.js';
import { icon } from '../core/icons.js';

/**
 * @param {{
 *  fields: Array<{type:'search'|'select', key:string, label:string, placeholder?:string, value?:string, options?:Array<{value:string,label:string}>}>,
 *  onChange?: (key:string, value:string)=>void,
 *  actions?: Node[],
 *  summary?: string,
 * }} options
 */
export function filterBar({ fields = [], onChange = () => {}, actions = [], summary = '' }) {
  const form = el('form', {
    class: 'filterbar',
    attrs: { role: 'search', 'aria-label': t('component.filters.aria'), autocomplete: 'off' },
    on: { submit: (event) => event.preventDefault() },
  });
  const controls = new Map();
  const debounced = debounce((key, value) => onChange(key, value), 220);

  for (const field of fields) {
    if (field.type === 'search') {
      const id = uid('filter-search');
      const wrap = el('div', { class: 'field field--search' });
      wrap.append(el('label', { class: 'field__label sr-only', text: field.label, attrs: { for: id } }));
      const searchWrap = el('div', { class: 'search-wrap' });
      const input = el('input', {
        id,
        class: 'input input--search',
        type: 'search',
        attrs: {
          placeholder: field.placeholder || t('component.filters.search_placeholder'),
          'aria-label': field.label,
        },
        props: { value: field.value || '' },
      });
      input.dataset.primarySearch = 'true';
      input.addEventListener('input', () => debounced(field.key, input.value));
      searchWrap.append(icon('search'), input);
      wrap.append(searchWrap);
      form.append(wrap);
      controls.set(field.key, input);
      continue;
    }

    if (field.type === 'select') {
      const id = uid('filter-select');
      const wrap = el('div', { class: 'field' });
      wrap.append(el('label', { class: 'field__label', text: field.label, attrs: { for: id } }));
      const select = el('select', { id, class: 'select' });
      for (const option of field.options || []) {
        const optionEl = el('option', { text: option.label, attrs: { value: option.value } });
        if ((field.value ?? '') === String(option.value)) optionEl.selected = true;
        select.append(optionEl);
      }
      select.addEventListener('change', () => onChange(field.key, select.value));
      wrap.append(select);
      form.append(wrap);
      controls.set(field.key, select);
      continue;
    }

    if (field.type === 'checkbox') {
      const label = el('label', { class: 'checkbox' });
      const input = el('input', { type: 'checkbox' });
      input.checked = Boolean(field.value);
      input.addEventListener('change', () => onChange(field.key, input.checked ? '1' : ''));
      label.append(input, el('span', { text: field.label }));
      form.append(label);
      controls.set(field.key, input);
    }
  }

  const result = el('span', { class: 'filterbar__result', text: summary });
  const right = el('div', { class: 'filterbar__actions' });
  right.append(result);
  for (const action of actions) right.append(action);
  form.append(right);

  return {
    element: form,
    controls,
    setSummary(text) {
      result.textContent = text;
    },
    setValue(key, value) {
      const control = controls.get(key);
      if (!control) return;
      if (control.type === 'checkbox') control.checked = Boolean(value);
      else control.value = value;
    },
    getValue(key) {
      return controls.get(key)?.value ?? '';
    },
    focusPrimary() {
      const primary = controls.get('q') || [...controls.values()][0];
      primary?.focus();
    },
  };
}

/**
 * @param {{label:string, options:Array<{value:string,label:string}>, value:string, onChange:(value:string)=>void}} options
 */
export function segmented({ label, options = [], value, onChange }) {
  const group = el('div', { class: 'segmented', attrs: { role: 'group', 'aria-label': label } });
  const buttons = new Map();
  for (const option of options) {
    const button = el('button', {
      type: 'button',
      class: 'segmented__btn',
      text: option.label,
      attrs: { 'aria-pressed': String(option.value === value) },
      on: {
        click: () => {
          if (option.value === value) return;
          value = option.value;
          for (const [key, btn] of buttons) btn.setAttribute('aria-pressed', String(key === value));
          onChange(option.value);
        },
      },
    });
    buttons.set(option.value, button);
    group.append(button);
  }
  return group;
}

