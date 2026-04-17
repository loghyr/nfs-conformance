<!--
SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com>
SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only
-->

# Full-Repo Review — 2026-04-17

First complete reviewer pass over the nfs-conformance repo as if no
review had been done.  Four parallel reviewer agents covered a
partition of all `.c` + `.h` files with a consistent rubric
(correctness, resource safety, portability, concurrency, charter
alignment, triage coverage).

## Summary

**65 findings across 77 files: 7 BLOCKER, 31 WARNING, 27 NOTE.**

BLOCKERs are correctness bugs likely to produce false PASS / false
FAIL, data loss, memory unsafety, or reliable resource leaks.  Fix
before next test-run.  WARNINGs are real but lower-blast-radius.
NOTEs are lint-level or stylistic.

## § 1 — BLOCKER findings

Each BLOCKER is a false-PASS or false-FAIL surface, a fd leak on
every run, or a doc/code disagreement that deceives copy-pasters.

### 1.1 op_verify.c:269-345 — reads `stx_size`, not `stx_change_attr`

`case_change_attr` uses hand-rolled byte offsets into `struct statx`
via `STX_CHANGE_ATTR_OFF 40`.  That offset points at `stx_size`, not
a change cookie.  Since every case writes to the file (size goes
0 → 64), `ca2 > ca1` holds trivially — the test falsely PASSES even
against servers that do not advertise the attribute at all.  The
`#define STATX_CHANGE_COOKIE 0x40000000U` fallback also can't
distinguish "kernel supports cookie" from "kernel accepted a random
bit".

**Fix**: delete `case_change_attr` from `op_verify.c` and rely on
`op_change_attr.c` (which uses the typed field via the kernel
header).  If the raw-syscall approach must stay, compute the
offset via `offsetof(struct statx, stx_change_attr)` under
`#ifdef STATX_CHANGE_COOKIE`.

### 1.2 op_tmpfile.c:207-227 — `/proc` fallback skipped under `-s`

`if (errno == ENOENT && !Sflag) { try /proc fallback; }`.  When
`-s` (silent) is set, the fallback is skipped and control falls
through to `else { complain(...); }`.  A silent run FAILs on
exactly the setup that a non-silent run passes on.

**Fix**: split the concerns: `if (errno == ENOENT) { try /proc
fallback; if (!Sflag) print NOTE; } else complain(...)`.

### 1.3 op_lookup.c:282-322 — case7 false PASS when server caps name length

`case_long_name` tries to `open` a 255-byte filename.  If the
server returns `ENAMETOOLONG` at 255 (some servers cap below that),
a NOTE is printed and the case `return`s — the 256-byte negative
assertion is never exercised.  The case still reports `ok`; the
test name says "long_name" but no assertion ran.

**Fix**: after the 255-byte NOTE return, still attempt the 256-byte
create and assert it fails; or emit an explicit per-case SKIP so
`runtests` distinguishes "not tested" from "pass".

### 1.4 op_fdopendir.c:283-295 — fd leak on expected ENOTDIR path

`case_not_directory` opens an fd, calls `fdopendir(fd)`, and
expects `NULL` with `ENOTDIR`.  The `close(fd)` only fires in the
`else if (errno != ENOTDIR)` arm — the expected-success-of-the-
expectation path leaks the fd every invocation.

**Fix**: move `close(fd)` out of the else-if so it runs whenever
`dp == NULL`.

### 1.5 op_timestamps.c:161 and :337 — two cases share scratch name `t_ts.ra.$pid`

`case_read_atime` and `case_rename_ctime` both build the filename
`t_ts.ra.%ld`.  Works today because each case unlinks at entry and
exit, but a tap_case failure path that leaks the file between
cases will cause `case_rename_ctime` to observe the wrong inode
and report a spurious failure.

**Fix**: rename one of the tags (e.g., `case_rename_ctime` tag from
`ra/rb` → `rn.a/rn.b`).

### 1.6 op_deleg_read.c:74 — usage string advertises `-s SERVER`

The usage block prints `[-s SERVER]` but the flag parser binds
`-s` to `Sflag` (silent) and `-S` to server.  A user copy-pasting
from the usage silently runs in silent mode without specifying a
server → case never reaches the cross-client path → false PASS.

**Fix**: change the usage string to `-S SERVER`.

### 1.7 op_symlink.c:236-245 — unchecked malloc in case_long_target

`char *buf = malloc(want + 16);` is not checked.  `readlinkat` with
a NULL buf segfaults.  Low probability (4 KB allocation) but the
rubric flags any unchecked malloc.

**Fix**: `if (!buf) { complain("case4: malloc"); free(target);
return; }`.

---

## § 2 — WARNING findings

Grouped by file, one block per finding.  Severity is real but not
BLOCKER: portability gap, resource leak on error path, or missing
error check that mostly hides in practice.

### Across multiple tests: `skip()` leaks scratch files

`op_statx_btime.c:164/167`, `op_change_attr.c` feature_probe,
`op_copy.c` feature_probe, `op_rename_atomic.c` feature_probe,
`op_clone.c do_ficlone`.  When a feature probe detects the op is
unsupported, `skip()` calls `exit()` before the `out:` unlink.
Scratch files leak on the server.

**Fix**: unlink the scratch file(s) before `skip(...)`.  Pattern:
`unlink(name); skip("...");`.

### op_utimensat.c:125-132, 163-168, 299-305 — nsec-strict equality

`case_nsec_roundtrip` / `case_dir_timestamps` / `case_utime_omit`
FAIL when the returned `tv_nsec` differs from the requested value.
Many legitimate NFS servers coarsen timestamps to ms/us granularity;
`op_timestamps.c case8` correctly downgrades this to NOTE, but
`op_utimensat` will produce fleet-wide FAILs against conformant
servers.

**Fix**: when `tv_sec` matches but `tv_nsec` does not, emit NOTE
instead of complain().  Reserve complain() for `tv_sec` mismatches.

### op_utimensat.c:57-58 — `_GNU_SOURCE` / `_DARWIN_C_SOURCE` without guards

R-CODE-2 says feature macros come from the Makefile.  This file
defines `_GNU_SOURCE` and `_DARWIN_C_SOURCE` unconditionally,
triggering `-Wmacro-redefined` on FreeBSD where the Makefile's
`-D_XOPEN_SOURCE=700` interacts.

**Fix**: guard with `#ifdef __APPLE__` around `_DARWIN_C_SOURCE`;
remove `_GNU_SOURCE` if Makefile sets it, or `#ifndef _GNU_SOURCE`.

### op_zero_to_hole.c:162-185 — `verify_all_zero` uses bare `pread`

`pread(fd, buf, size, 0)` without loop — on NFS an EINTR or short
read will produce a false FAIL.  The shared `pread_all` helper
handles this.

**Fix**: replace with `pread_all(fd, buf, (size_t)size, 0, label)`.

### op_verify.c:249 — `st_mtime < before.mtime` regression-only check

The comparison `st_after.st_mtime < st_before.st_mtime` only fires
if mtime regresses; it will never fail when mtime simply didn't
advance (which is what the test claims to assert).  Compare against
`ST_MTIM` at nsec precision for a real advance check.

**Fix**: follow `op_rename_nlink`'s nsec-level pattern.

### op_writev.c:317-319 — unchecked open before `read(rfd, ...)`

`case_writev_plain_read` opens rfd and immediately reads from it;
failure produces a confusing `'' != 'ABCDEFGHIJKL'` diagnostic
rather than an open-failure complaint.

**Fix**: `if (rfd < 0) { complain("case5: reopen: %s",
strerror(errno)); unlink(a); return; }`.

### op_fd_sharing.c:136-156 — unchecked reopen hides false PASS

`int rfd2 = open(a, O_RDONLY);` branch lacks an `else complain(...)`.
If the reopen fails, the assertion is skipped silently.

**Fix**: add `else complain("case2: reopen a: %s", strerror(errno));`
on the rfd2 branch (and on rfd).

### op_append.c — multiple

**Line 186-191, 242-248, 426-428, 506-509, 547-551**: unchecked
`stat()`/`fstat()` return; the subsequent `st.st_size != expected`
reads uninitialised data on failure.  **Fix**: explicit
`if (fstat(...) != 0) { complain(...); return; }`.

**Line 273, 342**: parent `close(pipefd[0])` is in the success
path; on `goto reap`, pipefd[0] is leaked.  **Fix**: move
`close(pipefd[0])` into the reap block.

**Line 308, 331, 369**: `write(...) != sizeof(rec)` is a signed-
vs-unsigned compare; cast to `(ssize_t)sizeof(rec)` for consistency
with the rest of the suite.

### op_overwrite.c:175-177 — nested `fstat` in complain() args

`complain("...", (long long)(fstat(fd, &st) == 0 ? st.st_size :
-1));` calls `fstat` a second time from inside the format argument.
Unreadable and discards the original error.

**Fix**: test `fstat` and `st.st_size` in two separate `if`s; emit
one complain with the value already in `st`.

### op_readdir.c:99-115 — `rmdir_r1` snprintf not checked for truncation

`snprintf` into `path[512]` with a 64-byte dir and a 255-byte
d_name fits today, but no truncation check — any FS that permits
longer d_names produces wrong paths that unlink then operates on.

**Fix**: check `snprintf` return and complain on truncation (same
pattern as `case_mixed_types` line 220).

### op_readdir_mutation.c:82-102, 116-131 — helpers don't rmdir subdirs

`make_scratch_dir`/`cleanup_dir` call `unlink()` on each entry but
never fall back to `rmdir()`.  If a prior aborted run leaves a
subdirectory, subsequent runs abort with `EEXIST` on `mkdir`.

**Fix**: on `unlink` returning `EISDIR`, try `rmdir` before moving
on.

### op_readdir_mutation.c:372-413 — `case_two_streams` counts `.`/`..`

The test advances d1 by 3 and d2 by 6 readdir calls, then counts
remaining entries.  Dot-and-dotdot handling is order-dependent
across servers; not POSIX-guaranteed.  A server that orders
entries differently can spuriously FAIL.

**Fix**: filter `.`/`..` explicitly in both advancement and
counting phases, or assert the relationship symbolically.

### op_unlink.c:138-172 — dead code: stat(".") before create

Two `stat(".", &st_before)` calls; the first (line 139) is
overwritten without being read.  Confusing — the "before"
measurement is actually taken after the create.

**Fix**: remove the first stat.

### op_symlink_loop.c and op_symlink.c — `t_sl.` prefix collision

Both files use `t_sl.` for scratch filenames.  If ever run
concurrently under the same `-d`, cleanup of one clobbers the
other's state.

**Fix**: pick distinct prefixes (e.g., `t_sll.` for
`op_symlink_loop`).

### op_symlink_nofollow.c:93-130 — local `link` shadows POSIX `link(2)`

Local `char link[64]` hides the POSIX `link(2)` function.  No
compile breakage today, but any future call to `link()` inside
the same function breaks unexpectedly.

**Fix**: rename to `linkname` (the convention in op_symlink.c).

### op_linkat.c:86-108 — `read_all` underflow when `cap < 2`

`while (total < (ssize_t)(cap - 1))` with `cap == 0` wraps to
SIZE_MAX.  No current caller passes cap<2, but the bound is
unsafe.

**Fix**: guard with `if (cap < 2) { close(fd); return 0; }` at
entry, or take a signed cap parameter.

### op_lock_posix.c:325-333 — second `fork()` missing `pid < 0` guard

`case_splitting` has two forks.  The first checks `pid < 0`; the
second does not.  If the second fork fails, `waitpid(pid, ...)` is
called with `pid=-1` — reaps any child, corrupts `rc`, masks
failures.

**Fix**: add the `pid < 0` check before `waitpid`.

### op_stale_handle.c:136 — `dup()` fd leaked on `fdopendir` failure

`DIR *dp = fdopendir(dup(dirfd));` — on `fdopendir` failure the
dup'd fd leaks.  Subsequent `close(dirfd)` closes the original, not
the dup.

**Fix**: materialise the dup into a named fd, close it on the
failure branch.

### op_errno_open.c:116-128 — strict EISDIR; some kernels emit EACCES

`case_dir_wronly_eisdir` and `case_dir_rdwr_eisdir` accept only
EISDIR.  POSIX allows EISDIR; some older Unixes and NFS servers
return EACCES (permission model first).

**Fix**: allowlist `{ EISDIR, EACCES }` via `check_fail_with()`
(as `op_errno_rename` does).

### op_rsize_wsize.c:395-399 — second `TEST:` line disturbs TAP plan

After `prelude()` emits the `TEST:` header, the test body emits a
second `TEST: %s: rsize=%zu ...` line.  Some TAP consumers
interpret this as a new subtest frame, disturbing the `1..N` plan.

**Fix**: emit as `NOTE:` (matches the convention elsewhere for
environmental context).

### op_owner_override.c:168-188 — `make_owned_file` ignores short write

`(void)write(fd, buf, sizeof(buf))` — a short write on a quota-
enforcing NFS server silently changes the test shape.

**Fix**: check `write(...) == (ssize_t)sizeof(buf)`; on short/
error, complain and return -1.

### op_deleg_attr.c:606-682 — mountinfo path parser loses after space

The `\040` space escape in mountinfo is not un-escaped.  An NFS
mount path containing a literal space (encoded `\040` in mountinfo)
silently causes the match to fail and `-m` strict mode degrades to
"mountstats unavailable".

**Fix**: un-escape `\040`/`\011`/`\134`/`\012` before `strcmp`; or
match by `st_dev` instead of text.

### op_deleg_attr.c:552-555 — single `read()` of probe pipe may truncate

`case_cb_getattr` reads probe output in a single `read()`.  If the
kernel delivers the probe's printf in two pieces (fork/exec barrier),
`sscanf` on a partial prefix returns a bogus probe_size and a
spurious FAIL.

**Fix**: loop reading until EOF before parsing (the standard
"collect subprocess stdout" pattern).

### op_soft_timeout.c:247-260 — closed-fd write relies on no fd reuse

`case_error_propagates` closes fd then writes to the same numeric
value.  Safe today; any future signal handler or pthread that
opens an fd between close() and write() silently reuses the fd
and the test passes for the wrong reason.

**Fix**: use a sentinel: `int bad_fd = -1; write(bad_fd, &b, 1);`
— expect EBADF directly.

### op_lock.c:223-231 — child pipe comment contradicts code

Comment says child reading `pipefd[1]` (write end) would release
the lock; in fact the child just calls `pause()`.  Misleading for
a future maintainer.

**Fix**: rewrite comment to "Child blocks in pause() until parent
sends SIGTERM; NFS client sends LOCKU on process exit".

### op_direct_io.c:164, 229 — 4 KiB verify buffers on stack

Inconsistent with the rest of the file which uses
`posix_memalign`/`malloc` for same-size buffers.  Safe on Linux
(8 MiB stack) but a maintenance hazard.

**Fix**: allocate via `malloc` (or `posix_memalign`); free on all
exit paths.

### op_read_write.c:100-117 — `%s` vs array of fixed length

The `write(fd, msg, sizeof(msg))` payload includes the trailing
NUL; complain format `'%s' vs '%s'` treats it as a C string.
Safe today; fragile for future edits.

**Fix**: `%.*s` with an explicit length, or memcmp+hex-dump.

---

## § 3 — NOTE findings

Lint-level and stylistic.  Fix at leisure.

- **op_append.c:286-298 case4 variable shadowing** — `recsz` computed as `sizeof(rec)` redeclared in each loop iteration; hoist to function scope.
- **op_commit.c:237-250 unconditional pre-flush** — `fsync(wfd)` before the case runs is intended for the Linux OPENMODE D-state hang; FreeBSD/macOS don't need it. Consider `#ifdef __linux__` or a code comment.
- **op_sync_dsync.c:61-63 O_DSYNC fallback silently weakens** — `#ifndef O_DSYNC / #define O_DSYNC O_SYNC` on platforms without O_DSYNC; cases 2 and 4 degenerate to O_SYNC. Printed NOTE helps humans but not TAP consumers. Consider per-case SKIP when `O_DSYNC == O_SYNC`.
- **op_concurrent_writes.c:192 early exit at 3 bad regions** — region count in FAIL undercounts real contamination. Add a "stopped at %d/%d regions" summary, or explanatory comment.
- **op_fd_sharing.c:159-161 post-dup2 close comment misleading** — dup2 does not leave fd2 closed; it reassigns. Update comment.
- **op_tmpfile.c:157 strncmp with `strlen(prefix)` inside loop** — hoist `size_t pfxlen = strlen(prefix);` above the loop.
- **op_read_write_large.c:46-48 feature macros without `_POSIX_C_SOURCE`** — inconsistent with neighbouring files.
- **op_writev.c:339 `iovec{NULL, 0}`** — POSIX-permitted but older BSDs EFAULT on NULL+0. Use `&unused_byte` to be uniformly safe.
- **op_symlink_nofollow.c:207 hard-coded mtime 500** — compare against observed baseline, not literal.
- **op_path_limits.c:140-162 case3 accepts both ENAMETOOLONG and ENOENT** — masks a server that performs no length check at all.
- **op_chmod_chown.c:173-174 case3 second-precision ctime** — `st_after.st_ctime < st_before.st_ctime` is regression-only; use nsec for real advance.
- **op_setattr.c:254-255 rolls its own `nanosleep`** — use `sleep_ms()` (R-CODE-4).
- **op_rename_open_target.c:109, 208 asymmetric `!= 0`** — `create_with(b, "dst")` missing `!= 0` in compound condition; style only.
- **op_copy.c:140-141 ignored ftruncate returns** — rewind failure leaves residual state; `(void)` cast or check.
- **op_timestamps.c — unchecked stat() returns** — multiple cases; low risk but precedent in case1 shows the right pattern.
- **op_root_squash.c:71-102 `squash_detected` sequencing** — initialise to -1; downstream cases SKIP if case1 didn't run.
- **op_mmap_msync.c:209-213 partial-page zero-fill** — add inline comment explaining the `min(page_size, 256)` clamp.
- **op_deleg_recall.c:213 EINTR loop** — correct; no fix.
- **op_lock.c:262-270 `l_pid` mismatch downgraded to NOTE** — correct per NFS semantics; no fix.
- **op_ofd_lock.c:68-83 dual-gated on `__linux__` + `F_OFD_SETLK`** — matches R-CODE rules; no fix.
- **op_delegation_write.c:299-304 advisory pipe read** — benign; waitpid is the real sync. Comment would help.
- **op_close_to_open.c:258 `(void)write`** — intentional; fine.
- **op_xattr.c:265 `fill_pattern(val, BIG_LEN, 0xBABE)`** — fine.
- **op_errno_rename.c:214 case_rename_into_child accepts EINVAL only** — defensible; some legacy systems returned ELOOP.
- **op_read_write.c:405-425 argv parse idiom duplicated 16×** — consider a `parse_common_flags()` helper in `subr.c`.
- **op_readdir_mutation.c:275-296 telldir-failure early return** — relies on `cleanup_dir`; fine.
- **op_tmpfile.c:157 strncmp hoist** — see above.

---

## § 4 — Triage coverage gaps

Spot-check found `complain()` strings NOT yet indexed in
`docs/TRIAGE.md`:

- `32-bit offset truncation?` — op_read_write_large case3
- `zero overwrite was dropped` — op_overwrite case6 (already partially indexed; case6 specifics missing)
- `NFS server followed the symlink on SETATTR` — op_symlink_nofollow case3/4
- `linkat appears to have followed the symlink` — op_linkat case5
- `parent nlink changed` — op_unlink case4

Add these rows to the by-symptom index.

---

## § 5 — Charter alignment

All 77 files were reviewed for charter compliance.  **Clean**: no
test binary (`op_*.c`) makes a direct TCP connection to port 2049,
opens raw sockets, or emits hand-rolled ONC RPC / XDR bytes.  The
three probes (`cb_*_probe`, `server_caps_probe`) use `rpc_wire.h`
as intended — that's the charter's explicit carve-out.

---

## § 6 — Clean files

Files where the full rubric surfaced no findings:

`tests.h`, `subr.c`, `op_access.c`, `op_allocate.c`, `op_at_variants.c`,
`op_change_attr.c`, `op_clone.c`, `op_deallocate.c`, `op_directory.c`,
`op_errno_link.c`, `op_io_advise.c`, `op_lookupp.c`, `op_mkdir.c`,
`op_mknod_fifo.c`, `op_noac.c`, `op_open_downgrade.c`, `op_open_excl.c`,
`op_readdir_many.c`, `op_rename_atomic.c`, `op_rename_nlink.c`,
`op_rename_self.c`, `op_rmdir.c`, `op_seek.c`, `op_sticky_bit.c`,
`op_truncate_grow.c`, `op_unicode_names.c`, `cb_getattr_probe.c`,
`cb_recall_probe.c`, `server_caps_probe.c`.

That's 29 of 77 files — every foundational utility and the newer
atomic-rename / errno / sticky / probe files.

---

## Recommended action order

1. **BLOCKERs first** (§ 1).  Each is a false-PASS or fd leak on
   every run.  Batch them as one commit per file since they're
   independent.
2. **WARNING cluster: `skip()` leaks scratch** across 5 files —
   one commit.
3. **WARNING: op_utimensat nsec-strict** — separate commit; touches
   assertion severity, not just code.
4. **Remaining WARNINGs** grouped by file.
5. **NOTEs** as a janitorial commit batch, or deferred.
6. **Triage gap rows** (§ 4) — add to `docs/TRIAGE.md` in the same
   commit as the source-code fix for each.

For each fix, `R-TRIAGE-2` applies: if the fix changes a
`complain()` string, update the matching `TRIAGE.md` row in the
same commit.
