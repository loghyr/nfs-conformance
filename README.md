<!--
SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com>
SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only
-->

# nfs-conformance

Syscall-level conformance tests for NFS servers: NFSv4.2 extensions
(RFC 7862), NFSv4 baseline ops, POSIX file semantics over NFS, and
NFS-specific client behaviour (close-to-open, cache bypass, mount
options, open flags).  Each test is a standalone C program, emits
TAP13 when `NFS_CONFORMANCE_TAP=1` is set, and exits `0/1/77/99`
(PASS / FAIL / SKIP / BUG, the GNU automake TESTS convention).

## Scope

Each test drives the op under test via its portable userspace
equivalent.  If the equivalent is unavailable on the running system,
the test SKIPs instead of failing.

### Naming

Test binaries are prefixed `op_` as a namespace marker — it
distinguishes conformance test binaries from helpers (`subr.o`,
the `cb_*_probe` tools) and makes `op_*` unambiguous in Makefile
lists, shell globs, and `.gitignore` negations.  The prefix
historically stood for "NFSv4 operation" and most tests still name
the op they exercise, but it applies equally to tests that target
POSIX features, mount-option behaviours, or NFS client semantics
with no one-to-one RFC operation.

### NFSv4.2 (RFC 7862)

| Test | Op | Userspace API | Portability |
|---|---|---|---|
| `op_allocate` | ALLOCATE | `posix_fallocate(3)` | POSIX |
| `op_io_advise` | IO_ADVISE | `posix_fadvise(2)` | POSIX |
| `op_seek` | SEEK, READ_PLUS | `lseek(SEEK_HOLE/SEEK_DATA)` | Linux / FreeBSD / Solaris / macOS 10.15+ |
| `op_copy` | COPY | `copy_file_range(2)` | Linux 4.5+, FreeBSD 13+ |
| `op_deallocate` | DEALLOCATE | `fallocate(FALLOC_FL_PUNCH_HOLE)` | Linux |
| `op_clone` | CLONE | `ioctl(FICLONE)` | Linux + reflink FS (btrfs, xfs reflink, zfs) |
| `op_statx_btime` | `time_create` (S12.2) | `statx(STATX_BTIME)` | Linux 4.11+ |
| `op_read_plus_sparse` | READ_PLUS over holes (S15) | `pread(2)` on sparse files | Linux / any NFSv4.2 client |

### NFSv4.2 XATTR extension (RFC 8276)

| Test | Op | Userspace API | Portability |
|---|---|---|---|
| `op_xattr` | GETXATTR, SETXATTR, LISTXATTRS, REMOVEXATTR | `setxattr(2)`, `getxattr(2)`, `listxattr(2)`, `removexattr(2)` (user.* namespace) | Linux |

### NFSv4.1 coverage

NFSv4.1's marquee additions (sessions, pNFS, EXCHANGE_ID / CREATE_SESSION, SECINFO_NO_NAME, directory delegations) don't have portable userspace hooks — they are state-machine internals or kernel-internal layer switches.  The one v4.1-era feature that *does* have a crisp syscall surface is open-file-description locks:

| Test | Op | Userspace API | Portability |
|---|---|---|---|
| `op_ofd_lock` | LOCK / LOCKU / LOCKT with OFD-scoped stateids | `fcntl(F_OFD_SETLK / F_OFD_GETLK)` | Linux 3.15+ |

### NFSv4 baseline ops

Bread-and-butter NFSv4 ops that predate v4.1 but matter for every server, exercised at the syscall-API boundary with a focus on edge cases that catch real bugs.

| Test | Op | Userspace API | Portability |
|---|---|---|---|
| `op_change_attr` | change attribute (RFC 7530 §5.8.1.4) | `statx(STATX_CHANGE_COOKIE)` | Linux 6.5+ |
| `op_rename_atomic` | RENAME with atomic flags | `renameat2(RENAME_NOREPLACE / RENAME_EXCHANGE)` | Linux (glibc 2.28+) |
| `op_symlink` | SYMLINK, READLINK (RFC 7530 §18.22/§18.26) | `symlinkat`, `readlinkat` | POSIX |
| `op_linkat` | LINK (RFC 7530 §18.14) | `link`, `linkat` | POSIX (case 6 Linux-only) |
| `op_access` | ACCESS (RFC 7530 §18.1) | `access`, `faccessat` | POSIX |
| `op_setattr` | SETATTR (RFC 7530 §18.30) | `chmod`, `chown`, `truncate`, `utimensat` | POSIX |
| `op_mkdir` | CREATE(NF4DIR) (RFC 7530 §18.4) | `mkdir`, `mkdirat` | POSIX |
| `op_rmdir` | REMOVE on dir (RFC 7530 §18.25) | `rmdir`, `unlinkat(AT_REMOVEDIR)` | POSIX |
| `op_readdir` | READDIR (RFC 7530 §18.23) | `opendir(3)`, `readdir(3)`, `rewinddir(3)` | POSIX |
| `op_open_excl` | OPEN createmode=EXCLUSIVE4_1 (RFC 7530 §18.16) | `open(O_CREAT\|O_EXCL)`, `openat` | POSIX |
| `op_mknod_fifo` | CREATE(NF4FIFO) (RFC 7530 §18.4) | `mkfifo(3)` | POSIX |
| `op_deleg_attr` | GETATTR / CB_GETATTR attribute delegation (RFC 7530 §18.7 / §20.1) | `fstat(2)`, `stat(2)`, `ftruncate(2)`, `lseek(SEEK_END)` | POSIX |
| `op_deleg_recall` | CB_RECALL of write delegation (RFC 5661 §20.3) | separate-client OPEN via `cb_recall_probe` | Linux NFS client |
| `op_deleg_read` | read delegation + recall on conflicting write (RFC 7530 §10.4.2) | separate-client OPEN via `cb_recall_probe -w` | Linux NFS client |
| `op_commit` | COMMIT (RFC 7530 §18.3) | `fsync(2)` / `fdatasync(2)` | POSIX |
| `op_truncate_grow` | SETATTR(size) hole-creating grow (RFC 7530 §5.8.1.5) | `ftruncate(2)` extending | POSIX |
| `op_unicode_names` | name encoding (RFC 7530 §1.4.2) | `open`/`stat`/`readdir`/`rename` with UTF-8 names | POSIX + UTF-8 locale |
| `op_readdir_many` | READDIR cookie continuation (RFC 7530 §18.23) | `opendir`/`readdir` over ~1024 entries | POSIX |
| `op_server_caps` | EXCHANGE_ID / SECINFO_NO_NAME | hand-rolled NFSv4.1 session | Linux + TCP/2049 to server (`-S SERVER` required) |
| `op_lookup` | LOOKUP (RFC 7530 §18.14) | `stat`, `open`, deep paths | POSIX |
| `op_lookupp` | LOOKUPP (RFC 7530 §18.15) | `stat("..")`, `openat(dirfd, "..")` | POSIX |
| `op_lock` | LOCK / LOCKU / LOCKT (RFC 7530 §18.10-12) | `fcntl(F_SETLK / F_GETLK)` | POSIX |
| `op_delegation_write` | OPEN_DELEGATE_WRITE (RFC 8881 §10.4) | `open(O_EXCL)`, write, recall via fork | POSIX |
| `op_verify` | VERIFY / NVERIFY (RFC 7530 §18.28/§18.19) | `stat` consistency, `statx` change_attr | POSIX (case 5 Linux-only) |
| `op_open_downgrade` | OPEN_DOWNGRADE (RFC 7530 §18.18) | multiple `open`/`close` fd patterns | POSIX |
| `op_unlink` | REMOVE on regular files (RFC 7530 §18.25) | `unlink`, silly rename (open+unlink+read) | POSIX |
| `op_chmod_chown` | SETATTR (RFC 7530 §18.30) | `chmod`, `chown`, setuid/setgid clearing | POSIX |
| `op_utimensat` | SETATTR timestamps (RFC 7530 §18.30) | `utimensat`, UTIME_NOW, UTIME_OMIT, nsec | POSIX.1-2008 |
| `op_rename_nlink` | RENAME nlink accounting (RFC 7530 §18.26) | cross-parent dir rename, replace | POSIX |
| `op_append` | O_APPEND atomic semantics (IEEE 1003.1 §6.3.1) | `open(O_APPEND)`, concurrent append, pwrite | POSIX.1-1990 |

### POSIX.1-2008/2024 conformance

Tests for specific POSIX features (POSIX.1-2008 / POSIX.1-2024)
targeting NFS server areas that historically have conformance gaps.

| Test | Feature | Userspace API | Portability |
|---|---|---|---|
| `op_symlink_nofollow` | AT_SYMLINK_NOFOLLOW + O_NOFOLLOW | `fstatat`, `utimensat`, `fchownat`, `linkat`, `open` | POSIX.1-2008 |
| `op_rename_self` | rename same-inode no-op (POSIX.1-2024) | `rename` of hardlinks to same file | POSIX |
| `op_at_variants` | *at() syscalls with real dirfds | `openat`, `mkdirat`, `mknodat`, `fchmodat`, `fchownat`, `renameat`, `unlinkat` | POSIX.1-2008 |
| `op_fdopendir` | fdopendir(3) on NFS dirfds | `openat` + `fdopendir` + `readdir` | POSIX.1-2008 |
| `op_read_write_large` | large I/O and offsets | `pread`/`pwrite` at >4 GiB, 1-4 MiB chunks, unaligned | POSIX |
| `op_owner_override` | Linux owner-override vs POSIX strict | `chmod`/`unlink`/`rename` on 0444 files (git gc path) | POSIX + Linux (`-P`/`-L` modes) |

### NFS-specific behavior tests

Tests derived from the NFS FAQ and real-world failure reports.  These
exercise NFS semantics that don't have an RFC section number but that
applications depend on.

| Test | What it tests | Portability | Special |
|---|---|---|---|
| `op_stale_handle` | ESTALE handling — the #1 NFS complaint | POSIX | |
| `op_mmap_msync` | mmap + msync coherence — #1 NFS data-loss source for mmap apps | POSIX | |
| `op_close_to_open` | Close-to-open cache consistency contract | POSIX | |
| `op_noac` | Attribute-cache-disabled semantics | POSIX (detection Linux) | **Requires `-o noac` mount** |
| `op_root_squash` | root_squash export behavior | POSIX | **Requires root** |

### Mount-option-gated tests

Some tests only make sense with specific mount options.  These tests
auto-detect mount options via `/proc/self/mountinfo` (Linux only) and
**skip** if the required option is not present:

| Test | Required option | How to run | Override |
|---|---|---|---|
| `op_noac` | `-o noac` | `mount -o noac ...; ./op_noac -d /mnt` | `-f` forces run |

On non-Linux platforms, mount option detection returns "unsupported" and
the test runs unconditionally (with a NOTE).  Use `-f` to force the test
on any platform regardless of detection.

The `mount_has_option(opt)` and `mount_get_option_value(key)` helpers in
`subr.c` are available for future mount-option-gated tests.  Pattern:

```c
if (!Fflag) {
    int rc = mount_has_option("noac");
    if (rc == 0)
        skip("%s: mount does not have noac; mount with -o noac "
             "to run this test (or -f to force)", myname);
    if (rc == -1 && !Sflag)
        printf("NOTE: %s: cannot detect mount options\n", myname);
}
```

`op_root_squash` does not use mount-option gating (root_squash is a
server export setting, not a client mount option).  It detects the
squash mode at runtime by checking the uid of a newly created file
and validates that subsequent operations are consistent with whatever
mode is active.  Both root_squash and no_root_squash are valid — the
test never fails on the choice of mode, only on inconsistent behavior.

## Non-goals (deferred)

Deliberately NOT covered by this suite, because there is no portable
userspace hook that exercises them:

- **WRITE_SAME** (RFC 7862 S10).  No userspace syscall maps to it on
  any Linux kernel this project tracks.
- **Inter-server COPY** and **COPY_NOTIFY** (RFC 7862 S7.2).
  `copy_file_range` only reaches intra-server COPY; the inter-server
  path is pre-coordinated between two servers out-of-band from any
  userspace API.
- **LAYOUTSTATS** (RFC 7862 S12).  pNFS-adjacent and statistics-only;
  no userspace trigger.
- **SEC_LABEL / Labeled NFS** (RFC 7204).  SELinux-specific policy
  attribute work; different audience, different test shape.
- **NFSv4.1 sessions, pNFS, directory delegations, SECINFO_NO_NAME,
  EXCHANGE_ID, CREATE_SESSION, referrals**.  Internal state-machine
  ops with no userspace knob.  `op_ofd_lock` is the one v4.1 feature
  with a clean syscall surface.

## Building

```
make
```

Produces all `op_*` binaries in the current directory.  No
autotools; plain Makefile with a single compile per test.

On macOS, the Linux- and XSI-only tests compile to skip stubs that
exit `77` at runtime.  `op_seek` runs on macOS 10.15+.

## Running a single test

```
./op_allocate [-h|-s|-t|-f|-n] [-d mountpoint]
```

Flags:

| Flag | Meaning |
|---|---|
| `-h` | print usage and exit |
| `-s` | silent (suppress non-error output) |
| `-t` | print execution timing |
| `-f` | function-only (skip any timed inner loop) |
| `-n` | skip working-directory create |
| `-d PATH` | run under PATH (default: current directory) |

## Running the whole suite

`make check` drives every test through `prove` (Perl's TAP
aggregator), which reads each binary's TAP13 stream and summarises
ok / not ok / skip counts.

Typical use against an NFSv4.2 mount:

```
sudo mount -t nfs -o vers=4.2 server:/export /mnt/nfs42
make check CHECK_DIR=/mnt/nfs42
```

Under the hood this is:

```
NFS_CONFORMANCE_TAP=1 prove -e '' ./op_* :: -d /mnt/nfs42
```

Parallel runs across independent mounts (`make check-j JOBS=N`) are
safe only when each prove slot is passed a *different* `-d` — tests
share scratch-file prefixes and collide on a single mount.  For
single-mount use, stay sequential.

## TAP13 output

Every test binary can emit TAP13 (Test Anything Protocol), so results
are consumable by `prove`, `tappy`, and any CI system that speaks TAP:

```
# Single binary, raw TAP (useful for scripting):
NFS_CONFORMANCE_TAP=1 ./op_commit -d /mnt/nfs42
```

In TAP mode each binary is one test with a `1..N` plan line where N
is the number of cases, followed by one `ok N - case_foo` or
`not ok N - case_foo` per case.  `prove` aggregates case-level results
across all binaries.

## Interpreting environmental NOTEs

Mount options and server configuration are tester decisions, not
test decisions.  The tests do not try to auto-fix your environment —
they run what you give them, report clearly when a failure is
environmental rather than server- or client-code-level, and let you
decide whether to change mount options, idmap, Kerberos, TLS, or the
test scope.

This section documents recurring `NOTE:` and `SKIP:` messages whose root
cause is configuration rather than a defect in the code under test.

### NFSv4 idmap and the chown no-op

Symptom (from `op_setattr`):

```
NOTE: op_setattr: case5 chown(1066,10) no-op returned EINVAL
      (likely NFS4ERR_BADOWNER from client-side idmap mismatch; see README)
```

Why: `SETATTR{owner, owner_group}` in NFSv4 transmits XDR strings of the
form `user@domain` / `group@domain`.  The Linux client consults
`nfs4_disable_idmapping` and `/etc/idmapd.conf` to decide whether to send
numeric IDs (`1066`) or resolved names (`loghyr@nfsv4bat.org`).  If
idmapping is enabled on the client but idmapd cannot reach its configured
backend (LDAP, NIS, nsswitch) *or* the domain the client uses does not
match the server's idmap domain, the server returns `NFS4ERR_BADOWNER`.
Linux surfaces that as `EINVAL`.  File *creation* still works because
AUTH_SYS carries the uid numerically in the RPC credential, bypassing
idmap entirely.  Only operations that encode `owner@` / `owner_group@`
strings — `SETATTR` primarily — hit the idmap path.

To verify: `stat` a file in the mount.  If ownership displays correctly,
the credential path is fine; the mismatch is limited to the string form.

Three ways to resolve, all tester-side:

1. Disable client-side idmapping (fastest; treat AUTH_SYS as fully
   numeric):

   ```
   echo Y | sudo tee /sys/module/nfs/parameters/nfs4_disable_idmapping
   ```

   Persist in `/etc/modprobe.d/nfs.conf`:

   ```
   options nfs nfs4_disable_idmapping=1
   ```

   Remount after changing.

2. Align the idmap domain between client and server and point idmapd at
   a working name source.  Typical working `/etc/idmapd.conf`:

   ```
   [General]
   Domain = your.domain

   [Translation]
   Method = nsswitch
   ```

   Restart `nfs-idmapd`.  The server must be in the same `Domain`.

3. Leave idmap as-is and accept the `NOTE`.  Other SETATTR cases
   (`chmod`, `truncate`, `utimensat`) do not encode owner strings and
   pass regardless.

### Kerberos (sec=krb5 / krb5i / krb5p)

These tests make no assumption about authentication flavour.  If you
mount with `sec=krb5*`, every uid that runs the suite needs its own
ticket:

```
kinit user@YOUR.REALM
klist                    # verify Default principal: user@YOUR.REALM
make check CHECK_DIR=/mnt/...
```

A cache that contains only a service principal (`nfs/host.domain@REALM`)
is not a user ticket.  The kernel will present it to the server, which
will map it to `nobody` or root-squash it, and every operation under the
mount will see `EACCES`.  `df` silently hides entries whose `statfs`
fails, which can make an apparently-unmounted filesystem look like a
different bug.  `mount | grep nfs` is authoritative.

### NFS over TLS (xprtsec=tls / xprtsec=mtls)

Mounting with `xprtsec=tls` or `xprtsec=mtls` is a tester decision; the
tests run the same over TLS as they do over plain TCP, because TLS is
below the RPC layer.  The usual failure mode is `mount` itself —
certificate trust, SAN, or `tlshd` not running — not a test result.
Check `systemctl status tlshd` on both ends and confirm the server's
certificate is trusted before running the suite.

### Renameat2 flags not supported

```
SKIP: op_rename_atomic: renameat2 RENAME_NOREPLACE not supported ...
```

Needs Linux NFS client ~6.1+ for `renameat2` flag passthrough.  Older
clients return `EINVAL` for any non-zero flag argument.

### op_deleg_attr case 8: `-m` mountstats-strict mode

Symptom (opt-in; only appears when `-m` is passed):

```
FAIL: case8: -m strict: GETATTR count rose by 3 during thread stat
      (client issued wire GETATTR despite holding a delegation, OR
       concurrent traffic bumped the counter -- -m requires a quiet mount)
```

Why: case 8 spawns a pthread that stat()s a file while the main thread
holds a write delegation.  Because the thread shares the kernel NFS
client, the server sees no conflicting OPEN, sends no CB_GETATTR, and
the client answers the stat from the delegation's in-core attribute
cache.  With `-m`, the test additionally parses
`/proc/self/mountstats` before and after the thread's stat and
asserts the client-side outgoing GETATTR counter did not change.

The counter is per-mount, not per-test, so ANY concurrent traffic on
the same mount (other processes, other test runs, a `find` in a
shell, a monitoring agent) during the few-microsecond stat window
bumps it and turns the assertion into a false positive.  `-m` is
opt-in precisely so the tester is explicitly acknowledging that the
mount is quiet for the duration of the test.

If you run the suite in parallel: do not pass `-m` unless you
serialise op_deleg_attr with `flock` or a lockfile on the
mountpoint.  Without `-m` the case still runs and
still verifies attribute correctness (the useful positive signal).
`-m` is Linux-only (`/proc/self/mountstats`); on other platforms the
flag is accepted but silently downgrades to lenient mode with a
NOTE.  Invoke as:

```
./op_deleg_attr -m -d /mnt/nfs
```

## Exit codes (per test binary)

| Code | Meaning |
|---|---|
| `0` | PASS |
| `1` | FAIL — at least one case verified a wrong result |
| `77` | SKIP — feature not available on this kernel / filesystem |
| `99` | BUG — test exited unexpectedly (crash, abort, etc.) |

## xfstests integration

The `xfstests/` subdirectory ships wrapper scripts that expose every
`op_*` binary as an xfstests test in the `nfs-conformance` group.
To integrate into an existing xfstests tree:

```
make xfstests XFSTESTS_DIR=/usr/src/xfstests-dev
cd /usr/src/xfstests-dev && sudo ./check -nfs -g nfs-conformance
```

The install script copies wrappers into `tests/nfs/`, registers the
`nfs-conformance` group in `doc/group-names.txt`, and prints the
`make` command to regenerate `tests/nfs/group.list`.

## License

Dual-licensed: `BSD-2-Clause OR GPL-2.0-only` at your option.  This
lets the code flow into both the permissive BSD/macOS/Solaris NFS
test ecosystems and the GPLv2 Linux NFS ecosystem (kernel, nfs-utils,
ktls-utils, tlshd).  See `LICENSE` for the full text and `NOTICE`
for attribution.
