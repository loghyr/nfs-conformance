<!--
SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com>
SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only
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

Bread-and-butter NFSv4 ops that predate v4.1 but matter for every server.  Cthon04 covers some of these; these tests are a modern, at-syscall-API flavour focused on edge cases that catch real bugs.

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

## Interpreting environmental NOTEs

In the Connectathon tradition, mount options and server configuration are
tester decisions, not test decisions.  The tests do not try to auto-fix
your environment — they run what you give them, report clearly when a
failure is environmental rather than server- or client-code-level, and
let you decide whether to change mount options, idmap, Kerberos, TLS, or
the test scope.

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
./runtests -d /mnt/...
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

## Exit codes

| Code | Meaning |
|---|---|
| `0` | PASS |
| `1` | FAIL — at least one test verified a wrong result |
| `77` | SKIP — feature not available on this kernel / filesystem |
| `98` | MISS — at least one test binary was not built |
| `99` | BUG — a test exited with an unexpected code |

## License

Dual-licensed: `BSD-2-Clause OR GPL-2.0-only` at your option.  This
lets the code flow into both the permissive BSD/macOS/Solaris NFS
test ecosystems and the GPLv2 Linux NFS ecosystem (kernel, nfs-utils,
ktls-utils, tlshd).  See `LICENSE` for the full text and `NOTICE`
for attribution.
