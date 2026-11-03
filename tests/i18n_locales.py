"""Parsing, locale discovery and parity checks for tests/i18n_check.py.

Read-only helpers shared by the i18n QA harness; see i18n_check.py for the CLI
contract, exit codes and machine-readable report schema.
"""

from __future__ import annotations

import json
import os
import re


EXPECTED_LANGUAGES = ["en", "de", "fr", "it", "es", "ja", "zh", "ru"]
REFERENCE_LANGUAGE = "en"
GO_LOCALE_DIR = os.path.join("src", "retail", "internal", "i18n")
UI_LOCALE_DIR = os.path.join("src", "retail", "internal", "webui", "web", "js", "i18n")
GO_LOCALE_FILE = "locales_{lang}.go"

PERCENT_PLACEHOLDER = re.compile(r"%[sdvq]")
BRACE_PLACEHOLDER = re.compile(r"\{([A-Za-z0-9_]+)\}")
SECRET_PATTERNS = [
    re.compile(r"(?i)bearer\s+[a-z0-9._-]{8,}"),
    re.compile(r"(?i)(password|passwd|secret|hmac|api[_-]?key)\s*[:=]\s*\S"),
    re.compile(r"-----BEGIN [A-Z ]+-----"),
    re.compile(r"\b[A-Fa-f0-9]{32,}\b"),
    re.compile(r"\b(ghp_|sk-|AKIA)[A-Za-z0-9]{8,}"),
    re.compile(r"(?i)token\s*[:=]\s*[A-Za-z0-9._-]{8,}"),
]


def placeholder_set(value):
    tokens = set(PERCENT_PLACEHOLDER.findall(value))
    tokens.update("{%s}" % name for name in BRACE_PLACEHOLDER.findall(value))
    return tokens


def unescape_js_string(raw):
    try:
        return json.loads('"' + raw + '"')
    except json.JSONDecodeError:
        return raw


def parse_go_locale(path):
    """Parse a locales_<lang>.go map. Returns (entries, errors).

    The catalog format is intentionally machine friendly: one
    "key": "value", entry per line with double-quoted strings.
    """
    entries = {}
    errors = []
    pattern = re.compile(r'^\s*"((?:[^"\\]|\\.)*)"\s*:\s*"((?:[^"\\]|\\.)*)",\s*$')
    try:
        with open(path, "r", encoding="utf-8") as handle:
            lines = handle.readlines()
    except OSError as exc:
        return entries, ["cannot read %s: %s" % (path, exc)]
    inside_map = False
    for number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not inside_map:
            if re.search(r"=\s*map\[string\]string\{", stripped):
                inside_map = True
            continue
        if stripped.startswith("}"):
            inside_map = False
            continue
        if not stripped or stripped.startswith("//"):
            continue
        match = pattern.match(line)
        if not match:
            errors.append("%s:%d: unparsable catalog line" % (os.path.basename(path), number))
            continue
        key = unescape_js_string(match.group(1))
        value = unescape_js_string(match.group(2))
        if key in entries:
            errors.append("%s:%d: duplicate key %r" % (os.path.basename(path), number, key))
            continue
        entries[key] = value
    if not inside_map and not entries:
        errors.append("%s: no catalog map found" % os.path.basename(path))
    return entries, errors


def strip_js_comments(source):
    result = []
    index = 0
    length = len(source)
    quote = None
    while index < length:
        char = source[index]
        if quote is not None:
            result.append(char)
            if char == "\\" and index + 1 < length:
                result.append(source[index + 1])
                index += 2
                continue
            if char == quote:
                quote = None
            index += 1
            continue
        if char in ("'", '"', "`"):
            quote = char
            result.append(char)
            index += 1
            continue
        if char == "/" and index + 1 < length and source[index + 1] == "/":
            newline = source.find("\n", index)
            if newline < 0:
                break
            index = newline
            continue
        if char == "/" and index + 1 < length and source[index + 1] == "*":
            end = source.find("*/", index + 2)
            index = length if end < 0 else end + 2
            continue
        result.append(char)
        index += 1
    return "".join(result)


class TokenStream:
    """Minimal JS object-literal tokenizer for locale files."""

    def __init__(self, source):
        self.tokens = self._tokenize(strip_js_comments(source))
        self.index = 0

    @staticmethod
    def _tokenize(source):
        tokens = []
        index = 0
        length = len(source)
        while index < length:
            char = source[index]
            if char.isspace():
                index += 1
                continue
            if char in ("'", '"', "`"):
                quote = char
                buffer = []
                index += 1
                while index < length:
                    char = source[index]
                    if char == "\\" and index + 1 < length:
                        buffer.append(char)
                        buffer.append(source[index + 1])
                        index += 2
                        continue
                    if char == quote:
                        index += 1
                        break
                    buffer.append(char)
                    index += 1
                tokens.append(("string", "".join(buffer)))
                continue
            if char in "{}[]:,":
                tokens.append((char, char))
                index += 1
                continue
            match = re.match(r"[A-Za-z0-9_$.+-]+", source[index:])
            if match:
                tokens.append(("word", match.group(0)))
                index += len(match.group(0))
                continue
            index += 1
        return tokens

    def peek(self):
        if self.index < len(self.tokens):
            return self.tokens[self.index]
        return (None, None)

    def next(self):
        token = self.peek()
        self.index += 1
        return token


def skip_balanced(stream, open_token, close_token):
    depth = 0
    while True:
        kind, _ = stream.next()
        if kind is None:
            return
        if kind == open_token:
            depth += 1
        elif kind == close_token:
            depth -= 1
            if depth <= 0:
                return


def parse_js_value(stream, flat, prefix, warnings, unsupported):
    kind, value = stream.peek()
    if kind == "{":
        stream.next()
        parse_js_object(stream, flat, prefix, warnings, unsupported)
        return
    if kind in ("[",):
        stream.next()
        skip_balanced(stream, "[", "]")
        unsupported.append(prefix or "(root)")
        return
    stream.next()
    if kind == "string":
        flat[prefix] = unescape_js_string(value)
        return
    unsupported.append(prefix or "(root)")


def parse_js_object(stream, flat, prefix, warnings, unsupported):
    while True:
        kind, _ = stream.next()
        if kind is None or kind == "}":
            return
        if kind == ",":
            continue
        if kind not in ("string", "word"):
            warnings.append("unexpected token %r in object" % (kind,))
            continue
        key = _
        separator, _ = stream.next()
        if separator != ":":
            warnings.append("missing ':' after key %r" % key)
            continue
        full_key = "%s.%s" % (prefix, key) if prefix else key
        parse_js_value(stream, flat, full_key, warnings, unsupported)
        peek_kind, _ = stream.peek()
        if peek_kind == "}":
            stream.next()
            return
        if peek_kind == ",":
            stream.next()


def parse_js_locale(path):
    """Parse a JS locale module object literal into a flat key/value map."""
    warnings = []
    unsupported = []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            source = handle.read()
    except OSError as exc:
        return {}, ["cannot read %s: %s" % (path, exc)], warnings
    # Find the first object literal assigned/exported after the language marker.
    candidate = source
    marker = re.search(r"(?:export\s+)?(?:const|let|var|default)\s+[A-Za-z0-9_$]*\s*=?\s*", source)
    if marker:
        candidate = source[marker.end():]
    brace = candidate.find("{")
    if brace < 0:
        return {}, ["%s: no object literal found" % os.path.basename(path)], warnings
    stream = TokenStream(candidate[brace:])
    kind, _ = stream.next()
    if kind != "{":
        return {}, ["%s: expected object literal" % os.path.basename(path)], warnings
    flat = {}
    parse_js_object(stream, flat, "", warnings, unsupported)
    errors = []
    for key in unsupported:
        warnings.append("%s: non-string value at %r skipped" % (os.path.basename(path), key))
    return flat, errors, warnings


def find_locale_file(directory, language):
    """Locate one language file.

    Supported layouts (delivered by the UI work package):
      i18n/<lang>.js|.json
      i18n/locales/<lang>.js|.json
      any subdirectory containing exactly <lang>.js|.json (deterministic walk)
    """
    for base in (directory, os.path.join(directory, "locales")):
        for extension in (".json", ".js", ".mjs"):
            candidate = os.path.join(base, language + extension)
            if os.path.isfile(candidate):
                return candidate
    matches = []
    for current, dirs, files in os.walk(directory):
        dirs.sort()
        for name in sorted(files):
            stem, extension = os.path.splitext(name)
            if stem == language and extension in (".json", ".js", ".mjs"):
                matches.append(os.path.join(current, name))
    return matches[0] if matches else None


def parse_locale_file(path):
    if path.endswith(".json"):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            return {}, ["cannot parse JSON locale %s: %s" % (os.path.basename(path), exc)], []
        if not isinstance(data, dict):
            return {}, ["%s: JSON root is not an object" % os.path.basename(path)], []
        flat = {}

        def flatten(value, prefix):
            for key, item in value.items():
                full = "%s.%s" % (prefix, key) if prefix else str(key)
                if isinstance(item, dict):
                    flatten(item, full)
                else:
                    flat[full] = item

        flatten(data, "")
        return flat, [], []

    if path.endswith((".js", ".mjs")):
        return parse_js_locale(path)
    return {}, ["unsupported locale file extension: %s" % path], []


def check_language_set(entries_by_language, label, errors):
    missing = [lang for lang in EXPECTED_LANGUAGES if lang not in entries_by_language]
    extra = [lang for lang in entries_by_language if lang not in EXPECTED_LANGUAGES]
    for lang in missing:
        errors.append("%s: missing language %r" % (label, lang))
    for lang in extra:
        errors.append("%s: unexpected language %r" % (label, lang))


def check_parity(reference, entries_by_language, label, errors, warnings):
    if reference not in entries_by_language:
        errors.append("%s: reference language %r missing" % (label, reference))
        return
    reference_keys = set(entries_by_language[reference].keys())
    for lang, entries in entries_by_language.items():
        if lang == reference:
            continue
        keys = set(entries.keys())
        for key in sorted(reference_keys - keys):
            errors.append("%s/%s: missing key %r" % (label, lang, key))
        for key in sorted(keys - reference_keys):
            errors.append("%s/%s: extra key %r" % (label, lang, key))
        for key in sorted(reference_keys & keys):
            empty = entries.get(key)
            if isinstance(empty, str) and empty.strip() == "":
                errors.append("%s/%s: empty value for %r" % (label, lang, key))
            elif isinstance(empty, str) and isinstance(entries_by_language[reference].get(key), str):
                wanted = placeholder_set(entries_by_language[reference][key])
                got = placeholder_set(empty)
                if wanted != got:
                    errors.append(
                        "%s/%s: placeholder mismatch for %r (%s != %s)"
                        % (label, lang, key, sorted(got), sorted(wanted))
                    )
    for lang, entries in entries_by_language.items():
        for key, value in entries.items():
            if not isinstance(value, str):
                warnings.append("%s/%s: non-string value for %r" % (label, lang, key))
                continue
            for pattern in SECRET_PATTERNS:
                if pattern.search(value):
                    errors.append("%s/%s: secret-like content in %r" % (label, lang, key))


def check_go(root):
    directory = os.path.join(root, GO_LOCALE_DIR)
    result = {
        "status": "ok",
        "directory": directory,
        "languages": [],
        "keys": 0,
        "per_language": {},
        "errors": [],
        "warnings": [],
    }
    entries_by_language = {}
    if not os.path.isdir(directory):
        result["status"] = "fail"
        result["errors"].append("go locale directory not found: %s" % directory)
        return result
    for language in EXPECTED_LANGUAGES:
        path = os.path.join(directory, GO_LOCALE_FILE.format(lang=language))
        if not os.path.isfile(path):
            result["errors"].append("go locale file missing: %s" % os.path.basename(path))
            continue
        entries, errors = parse_go_locale(path)
        result["errors"].extend(errors)
        entries_by_language[language] = entries
        result["per_language"][language] = len(entries)
    check_language_set(entries_by_language, "go", result["errors"])
    reference = entries_by_language.get(REFERENCE_LANGUAGE, {})
    result["keys"] = len(reference)
    check_parity(REFERENCE_LANGUAGE, entries_by_language, "go", result["errors"], result["warnings"])
    if result["errors"]:
        result["status"] = "fail"
    result["languages"] = sorted(entries_by_language.keys())
    return result


def check_ui(root, require_ui):
    directory = os.path.join(root, UI_LOCALE_DIR)
    result = {
        "status": "ok",
        "directory": directory,
        "require_ui": require_ui,
        "languages": [],
        "keys": 0,
        "per_language": {},
        "errors": [],
        "warnings": [],
    }
    if not os.path.isdir(directory):
        result["status"] = "missing"
        result["warnings"].append("ui locale directory not created yet: %s" % directory)
        if require_ui:
            result["status"] = "fail"
            result["errors"].append("ui locale directory is required but missing")
        return result
    entries_by_language = {}
    for language in EXPECTED_LANGUAGES:
        path = find_locale_file(directory, language)
        if path is None:
            result["warnings"].append("ui locale file missing for %r" % language)
            continue
        entries, errors, warnings = parse_locale_file(path)
        result["errors"].extend(errors)
        result["warnings"].extend(warnings)
        entries_by_language[language] = entries
        result["per_language"][language] = len(entries)
    if not entries_by_language:
        result["status"] = "missing"
        result["warnings"].append("no ui locale files found in %s" % directory)
        if require_ui:
            result["status"] = "fail"
            result["errors"].append("ui locales are required but none were found")
        return result
    check_parity(REFERENCE_LANGUAGE, entries_by_language, "ui", result["errors"], result["warnings"])
    reference = entries_by_language.get(REFERENCE_LANGUAGE, {})
    result["keys"] = len(reference)
    result["languages"] = sorted(entries_by_language.keys())
    if result["errors"]:
        result["status"] = "fail"
    elif len(entries_by_language) < len(EXPECTED_LANGUAGES):
        result["status"] = "warn"
        if require_ui:
            result["status"] = "fail"
            result["errors"].append("ui locales incomplete (%d/%d)" % (len(entries_by_language), len(EXPECTED_LANGUAGES)))
    if result["status"] == "warn":
        result["warnings"].append("ui locale set incomplete: %d/%d languages" % (len(entries_by_language), len(EXPECTED_LANGUAGES)))
    return result


