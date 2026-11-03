#!/usr/bin/env python3
"""GeDefense Retail i18n QA harness.

Checks the server-side Go catalogs (internal/i18n/locales_<lang>.go) and the
browser locale files (internal/webui/web/js/i18n/*) for:

  * presence of all eight expected languages (en, de, fr, it, es, ja, zh, ru),
  * key parity between the reference language (en) and every other language,
  * empty values,
  * placeholder parity per key ("%s"/"%d" and "{name}" style),
  * secret-like content in messages.

The harness is read-only and stdlib-only. Output is a single JSON document on
stdout so Lead/QA can parse it; human-readable mode is available via --human.

Exit codes:
  0  checks passed (warnings are allowed, e.g. UI locales not created yet)
  1  checks failed (missing language, key mismatch, empty value, secret, ...)
  2  invalid invocation

Usage:
  python tests/i18n_check.py [--root PATH] [--require-ui] [--human]

--require-ui makes missing/incomplete UI locales a failure (release gate mode).
Without it a missing UI locale directory is reported as a warning, because the
UI i18n is delivered by a separate work package.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from i18n_locales import EXPECTED_LANGUAGES, REFERENCE_LANGUAGE, check_go, check_ui


def main(argv):
    parser = argparse.ArgumentParser(description="GeDefense Retail i18n QA harness")
    parser.add_argument("--root", default=None, help="repository root (default: parent of tests/)")
    parser.add_argument("--require-ui", action="store_true", help="fail when UI locales are missing/incomplete")
    parser.add_argument("--human", action="store_true", help="human-readable summary instead of JSON")
    args = parser.parse_args(argv)

    root = args.root
    if root is None:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        print(json.dumps({"tool": "i18n_check", "status": "fail", "errors": ["root not found: %s" % root]}))
        return 2

    go_result = check_go(root)
    ui_result = check_ui(root, args.require_ui)

    errors = go_result["errors"] + ui_result["errors"]
    warnings = go_result["warnings"] + ui_result["warnings"]
    status = "ok"
    if errors or go_result["status"] == "fail" or ui_result["status"] == "fail":
        status = "fail"
    elif warnings or ui_result["status"] in ("missing", "warn"):
        status = "warn"

    report = {
        "tool": "i18n_check",
        "version": 1,
        "product": "GeDefense Retail",
        "root": root,
        "status": status,
        "expected_languages": EXPECTED_LANGUAGES,
        "reference_language": REFERENCE_LANGUAGE,
        "go": go_result,
        "ui": ui_result,
        "errors": errors,
        "warnings": warnings,
    }

    if args.human:
        print("i18n_check status=%s root=%s" % (status, root))
        print("  go: status=%s languages=%d keys=%d" % (go_result["status"], len(go_result["languages"]), go_result["keys"]))
        print("  ui: status=%s languages=%d keys=%d dir=%s"
              % (ui_result["status"], len(ui_result["languages"]), ui_result["keys"], ui_result["directory"]))
        for error in errors:
            print("  ERROR   " + error)
        for warning in warnings:
            print("  WARNING " + warning)
    else:
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=False))

    return 0 if status in ("ok", "warn") else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
