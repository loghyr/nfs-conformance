#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only
#
# triage.sh -- look up nfs-conformance FAIL signatures against
# docs/TRIAGE.md.  Three invocation modes:
#
#   triage.sh op_NAME
#       Print the full TRIAGE section for op_NAME.
#
#   triage.sh op_NAME SIGNATURE
#       Print only the failure-pattern rows whose Signature column
#       contains SIGNATURE (case-insensitive substring match).
#
#   triage.sh --stdin
#       Read test output from stdin (raw or TAP).  For each
#       "TEST: op_X: ..." header followed by FAIL / "# FAIL" lines,
#       look each FAIL up in op_X's failure-patterns table AND the
#       global by-symptom table.  Prints the diagnose step for
#       every match.
#
# Typical usage after a FAIL on an NFS mount:
#
#       ./op_timestamps -d /mnt 2>&1 | scripts/triage.sh --stdin
#
# Exit codes:
#   0  section / row(s) / diagnosis printed
#   1  no match found
#   2  usage error or TRIAGE.md missing

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

TRIAGE_PATH = Path(__file__).resolve().parent.parent / "docs" / "TRIAGE.md"

# Matches a per-test section header like `### <a id="op_foo"></a>op_foo`.
SECTION_RE = re.compile(r'^### <a id="([^"]+)"></a>', re.MULTILINE)

# Matches the start of the by-symptom section (anchor form) or its
# next-section terminator.
BY_SYMPTOM_RE = re.compile(r'^## <a id="by-symptom"></a>', re.MULTILINE)
NEXT_TOP_RE = re.compile(r'^## ', re.MULTILINE)


def load_triage() -> str:
    if not TRIAGE_PATH.is_file():
        sys.stderr.write(f"triage.sh: {TRIAGE_PATH} not found\n")
        sys.exit(2)
    return TRIAGE_PATH.read_text()


def section_for(text: str, name: str) -> str | None:
    """Return the raw Markdown for op_<name>'s subsection, or None."""
    matches = list(SECTION_RE.finditer(text))
    for i, m in enumerate(matches):
        if m.group(1) == name:
            start = m.start()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
            # Stop at a top-level `## ` if it falls before the next ###.
            top_m = NEXT_TOP_RE.search(text, start + 1, end)
            if top_m is not None:
                end = top_m.start()
            return text[start:end].rstrip() + "\n"
    return None


def extract_rows(section: str) -> list[tuple[str, str, str]]:
    """Extract the (signature, cause, diagnose) rows from a section's
    failure-patterns table.  Returns an empty list if absent."""
    rows: list[tuple[str, str, str]] = []
    in_table = False
    header_seen = False
    for line in section.splitlines():
        stripped = line.strip()
        if stripped.startswith("| Signature"):
            header_seen = True
            in_table = False  # wait for the `|---` separator
            continue
        if header_seen and stripped.startswith("|---"):
            in_table = True
            continue
        if in_table:
            if not stripped.startswith("|"):
                in_table = False
                header_seen = False
                continue
            # Split and drop the leading/trailing empty cells.
            cells = [c.strip() for c in stripped.split("|")[1:-1]]
            if len(cells) == 3:
                rows.append((cells[0], cells[1], cells[2]))
    return rows


def by_symptom_rows(text: str) -> list[tuple[str, str, str]]:
    """Extract the (substring, tests, meaning) rows from the global
    by-symptom table.  Empty if the table isn't present."""
    m = BY_SYMPTOM_RE.search(text)
    if m is None:
        return []
    end_m = NEXT_TOP_RE.search(text, m.end())
    block = text[m.end(): end_m.start() if end_m else len(text)]
    rows: list[tuple[str, str, str]] = []
    in_table = False
    header_seen = False
    for line in block.splitlines():
        stripped = line.strip()
        if stripped.startswith("| Substring"):
            header_seen = True
            in_table = False
            continue
        if header_seen and stripped.startswith("|---"):
            in_table = True
            continue
        if in_table:
            if not stripped.startswith("|"):
                in_table = False
                header_seen = False
                continue
            cells = [c.strip() for c in stripped.split("|")[1:-1]]
            if len(cells) == 3:
                rows.append((cells[0], cells[1], cells[2]))
    return rows


def strip_backticks(s: str) -> str:
    """A markdown cell like `foo bar` drops its wrapping backticks
    for matching.  Handles inline formatting minimally."""
    t = s
    if t.startswith("`") and t.endswith("`") and len(t) > 1:
        t = t[1:-1]
    return t


def row_matches(row_sig: str, needle: str) -> bool:
    """Substring match (case-insensitive) between a FAIL message and
    a Signature cell.  The cell may be backtick-wrapped and may
    contain %-format placeholders which we treat as wildcards."""
    sig = strip_backticks(row_sig).lower()
    n = needle.lower()
    # Treat %s, %d, %zu, %lld etc. as `.*?` so format templates match
    # concrete values.
    pat = re.escape(sig)
    pat = re.sub(r"%%", "%", pat)
    pat = re.sub(r"%[-#0 +]*\d*\.?\d*[hljztL]*[sdiuoxXfFeEgGcpzn%]",
                 ".*?", pat)
    try:
        if re.search(pat, n):
            return True
    except re.error:
        pass
    # Fallback: plain substring check both directions for short cells.
    return sig in n or n in sig


def print_section(section: str) -> None:
    print(section, end="")


def print_rows(header: str, rows: list[tuple[str, str, str]]) -> None:
    if not rows:
        return
    print(f"=== {header} ===")
    for sig, cause, diag in rows:
        print(f"  Signature: {sig}")
        print(f"  Cause:     {cause}")
        print(f"  Diagnose:  {diag}")
        print()


def cmd_section(test_name: str) -> int:
    text = load_triage()
    section = section_for(text, test_name)
    if section is None:
        print(f"triage.sh: no TRIAGE section for {test_name}", file=sys.stderr)
        return 1
    print_section(section)
    return 0


def cmd_signature(test_name: str, needle: str) -> int:
    text = load_triage()
    section = section_for(text, test_name)
    if section is None:
        print(f"triage.sh: no TRIAGE section for {test_name}", file=sys.stderr)
        return 1
    rows = extract_rows(section)
    matched = [r for r in rows if row_matches(r[0], needle)]
    if not matched:
        print(f"triage.sh: no row in {test_name} matches {needle!r}",
              file=sys.stderr)
        print("(try `triage.sh --stdin` or run without a signature to see all)",
              file=sys.stderr)
        return 1
    print_rows(f"{test_name} -- {len(matched)} match(es) for {needle!r}",
               matched)

    # Cross-reference by-symptom for extra context.
    global_hits = [r for r in by_symptom_rows(text) if row_matches(r[0], needle)]
    if global_hits:
        print_rows("by-symptom cross-reference", global_hits)
    return 0


# stdin parsing -----------------------------------------------------------

# TEST: op_timestamps: atime/mtime/ctime cascades
TEST_RE = re.compile(r"^(?:# )?TEST:\s+(\S+):\s*(.*)$")
# FAIL: caseN: message           (non-TAP path, on stderr)
# # FAIL: caseN: message         (TAP path, on stdout)
FAIL_RE = re.compile(r"^(?:# )?FAIL:\s+(.*)$")


def cmd_stdin() -> int:
    text = load_triage()
    global_rows = by_symptom_rows(text)

    current_test: str | None = None
    fails: list[tuple[str, str]] = []  # (test, fail_message)

    for line in sys.stdin:
        line = line.rstrip("\n")
        m = TEST_RE.match(line.strip())
        if m:
            current_test = m.group(1)
            continue
        m = FAIL_RE.match(line.strip())
        if m:
            msg = m.group(1).strip()
            # complain() from a test prints `FAIL: case3: reason`; the
            # test name isn't repeated.  Strip it if it shows up.
            if current_test and msg.startswith(current_test + ":"):
                msg = msg[len(current_test) + 1:].strip()
            fails.append((current_test or "?", msg))

    if not fails:
        print("triage.sh: no FAIL lines seen on stdin", file=sys.stderr)
        print("(hint: run the test directly, not via prove)", file=sys.stderr)
        return 1

    any_match = False
    for test, msg in fails:
        print(f"---------------------------------------------------------")
        print(f"FAIL  {test}: {msg}")
        print()
        local_rows: list[tuple[str, str, str]] = []
        if test != "?":
            section = section_for(text, test)
            if section:
                local_rows = [r for r in extract_rows(section)
                              if row_matches(r[0], msg)]
        global_hits = [r for r in global_rows if row_matches(r[0], msg)]
        if local_rows:
            any_match = True
            print_rows(f"{test} failure-pattern match(es)", local_rows)
        if global_hits:
            any_match = True
            print_rows("by-symptom cross-reference", global_hits)
        if not local_rows and not global_hits:
            print("  (no matching row in docs/TRIAGE.md -- worth adding)")
            print()

    return 0 if any_match else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="triage.sh",
        description="Look up nfs-conformance FAIL signatures against "
                    "docs/TRIAGE.md.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Modes:\n"
            "  triage.sh op_foo                 full section\n"
            "  triage.sh op_foo SIGNATURE       matching row(s)\n"
            "  triage.sh --stdin                parse FAIL lines from stdin\n"
            "\n"
            "Stdin mode expects raw test output.  Pipe the binary directly,\n"
            "not prove(1), which filters per-case output:\n"
            "\n"
            "  ./op_timestamps -d /mnt 2>&1 | scripts/triage.sh --stdin\n"
        ),
    )
    parser.add_argument("--stdin", action="store_true",
                        help="parse FAIL lines from stdin")
    parser.add_argument("test", nargs="?",
                        help="op_* test name (e.g., op_timestamps)")
    parser.add_argument("signature", nargs="?",
                        help="substring to match in the Signature column")
    args = parser.parse_args()

    if args.stdin:
        if args.test or args.signature:
            parser.error("--stdin takes no positional arguments")
        return cmd_stdin()
    if not args.test:
        parser.print_help(sys.stderr)
        return 2
    if args.signature:
        return cmd_signature(args.test, args.signature)
    return cmd_section(args.test)


if __name__ == "__main__":
    sys.exit(main())
