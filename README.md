<!--
SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# nfsv42-tests

Syscall-level tests for NFSv4.2 extensions (RFC 7862) that post-date
the most recent active development cycle of the Connectathon NFS test
suite.  Each test is a standalone C program, uses the Connectathon
`-h/-s/-t/-f/-n/-d` flag conventions, and exits `0/1/77/99` (PASS /
FAIL / SKIP / BUG, the GNU automake TESTS convention).

## Scope

Each test drives the NFSv4.2 op under test via its portable userspace
equivalent.  If the userspace equivalent is unavailable on the
running system, the test SKIPs instead of failing.

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

Bread-and-butter NFSv4 ops that predate v4.1 but matter for every server.  Cthon04 covers some of these; these tests are a modern, at-syscall-API flavour focused on edge cases that catch real bugs.

| Test | Op | Userspace API | Portability |
|---|---|---|---|
| `op_change_attr` | change attribute (RFC 7530 §5.8.1.4) | `statx(STATX_CHANGE_COOKIE)` | Linux 6.5+ |
| `op_rename_atomic` | RENAME with atomic flags | `renameat2(RENAME_NOREPLACE / RENAME_EXCHANGE)` | Linux (glibc 2.28+) |
| `op_symlink` | SYMLINK, READLINK (RFC 7530 §18.22/§18.26) | `symlinkat`, `readlinkat` | POSIX |
| `op_linkat` | LINK (RFC 7530 §18.14) | `link`, `linkat` | POSIX (case 6 Linux-only) |

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

Produces the six `op_*` binaries in the current directory.  No
autotools; plain Makefile with a single compile per test.

On macOS, the Linux- and XSI-only tests compile to skip stubs that
exit `77` at runtime.  `op_seek` runs on macOS 10.15+.

## Running a single test

```
./op_allocate [-h|-s|-t|-f|-n] [-d mountpoint]
```

Flags (matching Connectathon cthon04 conventions):

| Flag | Meaning |
|---|---|
| `-h` | print usage and exit |
| `-s` | silent (suppress non-error output) |
| `-t` | print execution timing |
| `-f` | function-only (skip any timed inner loop) |
| `-n` | skip working-directory create |
| `-d PATH` | run under PATH (default: current directory) |

## Running the whole suite

```
./runtests [-d mountpoint]
```

Invokes all six tests in order.  Exit status summarises the worst
individual result.  Output is line-per-test so it can be wrapped by
external CI harnesses.

Typical use against an NFSv4.2 mount:

```
sudo mount -t nfs -o vers=4.2 server:/export /mnt/nfs42
make check CHECK_DIR=/mnt/nfs42
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | PASS |
| `1` | FAIL — at least one test verified a wrong result |
| `77` | SKIP — feature not available on this kernel / filesystem |
| `98` | MISS — at least one test binary was not built |
| `99` | BUG — a test exited with an unexpected code |

## License

Apache License 2.0.  See `LICENSE` for the full text and `NOTICE`
for attribution.
