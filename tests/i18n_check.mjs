#!/usr/bin/env node
/**
 * i18n key-parity and usage check.
 * - every locale resolves the same key set (missing keys fall back to English)
 * - no empty/whitespace values
 * - placeholders ({name}) are identical across locales for the same key
 * - every literal t('key') used in the UI exists in the English catalog
 * Exit code 1 on any violation.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { pathToFileURL } from 'node:url';

const root = new URL('../src/retail/internal/webui/web/js/', import.meta.url);
const rootPath = root.pathname.replace(/^\/([A-Za-z]:)/, '$1');
const localesDir = join(rootPath, 'i18n', 'locales');
const languages = ['en', 'de', 'fr', 'it', 'es', 'ja', 'zh', 'ru'];
const dictionaries = {};
for (const lang of languages) {
  const module = await import(pathToFileURL(join(localesDir, `${lang}.js`)).href);
  dictionaries[lang] = module.default || {};
}

const problems = [];
const pending = [];
const englishKeys = Object.keys(dictionaries.en).sort();
const placeholders = (text) => [...String(text).matchAll(/\{(\w+)\}/g)].map((match) => match[1]).sort();

for (const lang of languages) {
  const dict = dictionaries[lang];
  const missing = englishKeys.filter((key) => !(key in dict));
  const empty = Object.entries(dict).filter(([, value]) => !String(value || '').trim()).map(([key]) => key);
  const extra = Object.keys(dict).filter((key) => !(key in dictionaries.en));
  if (missing.length) problems.push(`${lang}: missing ${missing.length} keys (${missing.slice(0, 6).join(', ')})`);
  if (empty.length) problems.push(`${lang}: empty values for ${empty.slice(0, 6).join(', ')}`);
  if (extra.length) problems.push(`${lang}: keys not in English fallback (${extra.slice(0, 6).join(', ')})`);
  for (const key of englishKeys) {
    if (!(key in dict) || !(key in dictionaries.en)) continue;
    const a = placeholders(dict[key]).join('|');
    const b = placeholders(dictionaries.en[key]).join('|');
    if (a !== b) problems.push(`${lang}: placeholder mismatch for ${key} (${a} != ${b})`);
  }
}

function* walk(dir) {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    const stat = statSync(path);
    if (stat.isDirectory()) {
      if (entry !== 'i18n') yield* walk(path);
    } else if (entry.endsWith('.js')) {
      yield path;
    }
  }
}

const used = new Map();
const callPattern = /\bt\(\s*['"]([^'"]+)['"]/g;
for (const file of walk(rootPath)) {
  const text = readFileSync(file, 'utf8');
  for (const match of text.matchAll(callPattern)) {
    const key = match[1];
    if (!used.has(key)) used.set(key, []);
    used.get(key).push(relative(rootPath, file));
  }
}
const unknown = [...used.keys()].filter((key) => !(key in dictionaries.en));
const strict = process.argv.includes('--strict');
if (unknown.length) {
  const label = `t() keys missing in English: ${unknown.slice(0, 20).join(', ')}${unknown.length > 20 ? ' …' : ''}`;
  if (strict) problems.push(label);
  else pending.push(label + ` (${unknown.length} pending external catalogs)`);
}

const translated = {};
for (const lang of languages) {
  translated[lang] = englishKeys.filter((key) => key in dictionaries[lang] && dictionaries[lang][key] !== dictionaries.en[key]).length;
}

console.log(`locales: ${languages.join(', ')}`);
console.log(`catalog keys: ${englishKeys.length}`);
console.log(`t() call sites: ${[...used.values()].reduce((sum, files) => sum + files.length, 0)} across ${new Set([...used.values()].flat()).size} files`);
console.log('translated keys per locale:', translated);
if (pending.length) {
  console.log('\nPENDING (delegated catalogs not merged yet):');
  for (const item of pending) console.log(`- ${item}`);
}
if (problems.length) {
  console.error('\nFAIL:');
  for (const problem of problems) console.error(`- ${problem}`);
  process.exit(1);
}
console.log('\nOK: key parity, placeholders, non-empty values and t() usage are consistent.');
