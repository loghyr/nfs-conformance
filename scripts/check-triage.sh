#!/bin/sh
# SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only
#
# check-triage.sh -- enforce R-TRIAGE-1: every op_* test in the
# TESTS list has a matching ## op_<name> subsection in
# docs/TRIAGE.md.
#
# Intentionally thin: only checks top-level section presence.
# Full per-complain() coverage is future work (see TRIAGE.md
# Phase 3 notes).
#
# Exit 0 on clean, 1 on missing entries.  Prints the gap list.

set -eu

TOP=$(cd "$(dirname "$0")/.." && pwd)
MAKEFILE="$TOP/Makefile"
TRIAGE="$TOP/docs/TRIAGE.md"

[ -f "$MAKEFILE" ] || { echo "$0: no $MAKEFILE" >&2; exit 2; }
[ -f "$TRIAGE" ]   || { echo "$0: no $TRIAGE" >&2; exit 2; }

# Extract the TESTS list from the Makefile.  TESTS = ... \
# continuations supported; strip whitespace and split on spaces.
tests=$(awk '
  /^TESTS[[:space:]]*=/ { collect = 1 }
  collect {
    gsub(/^TESTS[[:space:]]*=[[:space:]]*/, "")
    gsub(/\\$/, "")
    print
    if (!/\\$/) collect = 0
  }
' "$MAKEFILE" | tr -s ' \t\n' '\n' | grep -v '^$' | sort -u)

[ -n "$tests" ] || { echo "$0: empty TESTS list in Makefile" >&2; exit 2; }

missing=""
for t in $tests; do
    if ! grep -q "^### <a id=\"$t\"></a>$t" "$TRIAGE" \
       && ! grep -q "^- \`$t\`" "$TRIAGE"; then
        missing="$missing $t"
    fi
done

if [ -n "$missing" ]; then
    echo "R-TRIAGE-1 violation: the following tests have no entry in docs/TRIAGE.md:"
    for t in $missing; do
        echo "  - $t"
    done
    echo ""
    echo "Add a subsection '### <a id=\"<name>\"></a><name>' OR a short-"
    echo "form entry '- \`<name>\`' under 'Remaining tests'."
    exit 1
fi

echo "OK: every op_* in TESTS has a TRIAGE.md entry."
exit 0
