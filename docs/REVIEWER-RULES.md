<!--
SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com>
SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only
-->

# Reviewer Rules

Checklist a human or AI reviewer must run against every PR to this
repository.  Listed in order of blast radius, so a PR that violates
an early rule is blocked regardless of the later ones.

## Charter

- **R-CHARTER-1**: The PR MUST respect the [charter](../README.md#charter).
  The unit under test is the OS NFS client driven through POSIX
  syscalls.  A test that opens its own TCP socket to port 2049, or
  that calls an RPC helper directly, is out of scope and must be
  rejected — or demoted to `scripts/` or a probe (`*_probe.c`)
  alongside `cb_*_probe`.  The only legitimate wire-level binary is
  `server_caps_probe`, flagged as such in the README.

- **R-CHARTER-2**: New tests MUST be tagged with a charter tier
  (POSIX / SPEC / CLIENT) in their `.c` header comment AND in the
  matching [TRIAGE.md](TRIAGE.md) entry.  If the reviewer cannot
  decide which tier applies, the test's scope is probably unclear
  and needs sharpening before merge.

## Triage coverage

- **R-TRIAGE-1**: Every new `op_*` test added to `TESTS` in the
  Makefile MUST ship with a new subsection in
  [`docs/TRIAGE.md`](TRIAGE.md) in the same PR.  The subsection
  must include:
    - Charter tier
    - One-paragraph "Asserts" summary
    - Case list
    - A failure-patterns table with one row per distinct
      `complain(...)` string in the test source.

- **R-TRIAGE-2**: Every edit to an existing test that adds or
  changes a `complain(...)` string MUST update the matching
  TRIAGE.md row in the same commit.  A string that exists in the
  source but does not appear in TRIAGE (modulo trivial %-format
  paraphrase) is a bug.

- **R-TRIAGE-3**: Deleting a test MUST delete its TRIAGE subsection
  and its row(s) in § 2 (By Symptom) in the same commit.

- **R-TRIAGE-4**: Renaming a test (e.g., `op_foo` → `op_bar`) MUST
  update the TRIAGE subsection anchor, the TOC link, every § 2 row
  referencing it, and any cross-reference from other entries.

- **R-TRIAGE-5**: A PR that introduces a test whose FAIL message
  cannot be mapped to a likely cause is not ready for merge —
  either the reviewer understands the failure well enough to fill
  in the table, or the test's assertion is muddled and needs
  tightening.

## Code

- **R-CODE-1**: Every new `op_*` test MUST be portable in the same
  dimensions as existing tests: build clean on Linux / FreeBSD /
  macOS via both GNU make and bmake.  Platform-specific code paths
  go behind `#ifdef __linux__` / `#ifdef __FreeBSD__` / etc., with
  a skip stub for unsupported platforms.

- **R-CODE-2**: Feature-test macros: `_POSIX_C_SOURCE 200809L` is
  always required.  `_XOPEN_SOURCE=700` and `_DEFAULT_SOURCE` come
  from the Makefile — do not duplicate in source files (the
  compiler flag `-D_XOPEN_SOURCE=700` + a per-file define of the
  same name triggers `-Wmacro-redefined`).  On FreeBSD, guard
  `_XOPEN_SOURCE` with `#ifndef __FreeBSD__` when the test uses
  BSD-namespace symbols (SEEK_HOLE/SEEK_DATA, copy_file_range,
  usleep).  On macOS use `#ifdef __APPLE__ #define _DARWIN_C_SOURCE`
  for pwritev/preadv etc.

- **R-CODE-3**: Tests use the shared harness (`prelude`, `complain`,
  `skip`, `sleep_ms`, `finish`, `RUN_CASE`) declared in
  [`tests.h`](../tests.h).  Do not duplicate their behaviour;
  extend `subr.c` if you need a new primitive.

- **R-CODE-4**: `sleep_ms()` is the portable millisecond sleep —
  do NOT call `usleep(3)` (hidden by `_XOPEN_SOURCE=700` on
  FreeBSD).  The helper is the first thing new tests discover
  wrong, so it's worth a dedicated rule.

- **R-CODE-5**: Scratch file names MUST embed `getpid()` to avoid
  collisions across concurrent test runs on shared mounts.  Pattern:
  `snprintf(name, sizeof(name), "t_<tag>.%ld", (long)getpid());`

- **R-CODE-6**: Never-acted-on failures are not acceptable.  Every
  `complain()` must either cause a FAIL the reviewer can interpret
  or be replaced by a `NOTE:` printf (non-failing diagnostic).
  "complain() but carry on as if nothing happened" is a code smell.

## Testing discipline

- **R-TEST-1**: Contributors MUST run `make check CHECK_DIR=/tmp`
  locally (or at minimum on the author's workstation) before
  opening a PR.  A test that FAILs locally on a clean POSIX fs is
  either broken or platform-sensitive and needs a skip.

- **R-TEST-2**: A PR is not ready for merge until `make check`
  completes without BUG (exit code 99) on at least one NFS mount.
  FAILs against a server are interesting — they're findings.  BUGs
  are defects in the test itself.

- **R-TEST-3**: PRs adding NFS-specific assertions SHOULD link to
  the RFC clause, bug report, or kernel commit they target when
  relevant.  Precedent (e.g., "FreeBSD 39d96e08b0c4") makes the
  test's purpose immediately obvious to future maintainers.

## Make hygiene

- **R-MAKE-1**: Every new test MUST be added to `TESTS` in the
  Makefile.  Every deleted test MUST be removed.  The `.gitignore`
  pattern `op_*` with `!op_*.c !op_*.h` already ignores the
  binaries automatically.

- **R-MAKE-2**: Both `make` and `bmake` must build the test
  cleanly.  If the Makefile needs to dispatch (rare), use suffix
  rules and `$*.c` — not GNU pattern rules (`%`) or `$(shell ...)`.

## Out of scope (by design)

These are NOT reviewer rules and should not block a PR:

- Performance benchmarking (`op_*_stress`, throughput measurements).
  The suite is correctness-focused.  Benchmarks belong in `fio`/`fstest`.
- Wire-level RPC correctness (XDR, session sequence IDs, channel
  binding).  Use `pynfs`.
- Multi-user / sticky-bit enforcement testing.  Use `pjdfstest`.

---

*When in doubt about a rule, err on the side of requiring more — a
rejected PR can be revised; a merged PR with bad triage coverage
rots until the next author has to reverse-engineer it.*
