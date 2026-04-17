<!--
SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com>
SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only
-->

# Triage Guide

When a test fails, this document tells you:

1. What the test was asserting.
2. The most likely cause of that specific failure signature.
3. What to do next to confirm the diagnosis.
4. Whether the failure is environmental (not a bug) or a real defect.

The two lookup paths are:

- **[By test](#by-test)** — you know which test fired (e.g., `op_concurrent_writes`); find its section and match your failure message against the failure-patterns table.
- **[By symptom](#by-symptom)** — you have a failure substring and don't yet know which test surfaced it.

Cross-referenced — both lookup paths land on the same analytical content.

## How to read a failure

Test exit codes: `0` = PASS, `1` = FAIL (at least one `complain()` fired), `77` = SKIP (feature unavailable / environmental gate not met), `99` = BUG (test crashed or exited unexpectedly).

In TAP mode (`NFS_CONFORMANCE_TAP=1` — what `make check` sets), each case emits one `ok`/`not ok` line. FAIL lines from `complain()` appear BEFORE the plan summary. The FAIL message itself is the signature to match against the failure-patterns table for that test.

`NOTE:` lines are informational — they describe environmental conditions the test detected (noac not set, idmap not configured, clock skew, etc.). Not failures.

## Charter-tier legend

Each test is tagged with the charter tier it primarily exercises (see the charter in `README.md`):

| Tag | Meaning |
|---|---|
| **POSIX** | Does the mount behave like a POSIX filesystem? |
| **SPEC** | NFS RFC compliance at the syscall surface (NFSv4.2 extensions, NFSv4 ops) |
| **CLIENT** | OS-client behaviour: mount options, caches, platform extensions |

Tier affects how you read a failure: POSIX failures usually indicate a server bug OR a client-side POSIX regression; SPEC failures usually point at a server-side RFC deviation; CLIENT failures usually point at client-side cache/config issues.

## Environmental vs. real failures

Before chasing a failure, reproduce the test on a **local** filesystem (`make check CHECK_DIR=/tmp`). If it FAILs locally too, the issue is in the test or in the host platform, not in NFS. See the [local-first testing approach](../README.md#recommended-testing-approach-local-first-then-nfs) in README.

## <a id="by-test"></a>§ 1 — By Test

Top-priority tests (NFS-bug-finding value ranked high) are triaged in detail. Other tests get shorter entries.

### Table of contents

- [op_concurrent_writes](#op_concurrent_writes)
- [op_aio_races](#op_aio_races)
- [op_read_write](#op_read_write)
- [op_overwrite](#op_overwrite)
- [op_writev](#op_writev)
- [op_read_plus_sparse](#op_read_plus_sparse)
- [op_zero_to_hole](#op_zero_to_hole)
- [op_stale_handle](#op_stale_handle)
- [op_mmap_msync](#op_mmap_msync)
- [op_close_to_open](#op_close_to_open)
- [op_noac](#op_noac)
- [op_root_squash](#op_root_squash)
- [op_soft_timeout](#op_soft_timeout)
- [op_rsize_wsize](#op_rsize_wsize)
- [op_direct_io](#op_direct_io)
- [op_lock](#op_lock)
- [op_lock_posix](#op_lock_posix)
- [op_ofd_lock](#op_ofd_lock)
- [op_append](#op_append)
- [op_sync_dsync](#op_sync_dsync)
- [op_commit](#op_commit)
- [op_rename_nlink](#op_rename_nlink)
- [op_rename_open_target](#op_rename_open_target)
- [op_readdir_mutation](#op_readdir_mutation)
- [op_readdir_many](#op_readdir_many)
- [op_timestamps](#op_timestamps)
- [op_errno_rename](#op_errno_rename)
- [op_errno_open](#op_errno_open)
- [op_errno_link](#op_errno_link)
- [op_path_limits](#op_path_limits)
- [op_symlink_loop](#op_symlink_loop)
- [op_sticky_bit](#op_sticky_bit)
- [op_deleg_attr](#op_deleg_attr)
- [op_deleg_recall](#op_deleg_recall)
- [op_deleg_read](#op_deleg_read)
- [op_delegation_write](#op_delegation_write)
- [op_copy](#op_copy)
- [op_clone](#op_clone)
- [op_truncate_grow](#op_truncate_grow)
- [op_unicode_names](#op_unicode_names)
- [op_verify](#op_verify)
- [op_unlink](#op_unlink)
- [op_read_write_large](#op_read_write_large)
- [op_rename_atomic](#op_rename_atomic)
- [op_symlink_nofollow](#op_symlink_nofollow)
- [op_chmod_chown](#op_chmod_chown)
- [op_seek](#op_seek)
- [op_allocate](#op_allocate)
- [op_access](#op_access)
- [op_at_variants](#op_at_variants)
- [op_change_attr](#op_change_attr)
- [op_deallocate](#op_deallocate)
- [op_directory](#op_directory)
- [op_fd_sharing](#op_fd_sharing)
- [op_fdopendir](#op_fdopendir)
- [op_io_advise](#op_io_advise)
- [op_linkat](#op_linkat)
- [op_lookup](#op_lookup)
- [op_lookupp](#op_lookupp)
- [op_mkdir](#op_mkdir)
- [op_rmdir](#op_rmdir)
- [op_mknod_fifo](#op_mknod_fifo)
- [op_open_downgrade](#op_open_downgrade)
- [op_open_excl](#op_open_excl)
- [op_owner_override](#op_owner_override)
- [op_readdir](#op_readdir)
- [op_rename_self](#op_rename_self)
- [op_setattr](#op_setattr)
- [op_statx_btime](#op_statx_btime)
- [op_symlink](#op_symlink)
- [op_tmpfile](#op_tmpfile)
- [op_utimensat](#op_utimensat)
- [op_xattr](#op_xattr)

---

### <a id="op_concurrent_writes"></a>op_concurrent_writes

**Tier**: CLIENT (write-path serialization on shared fd)

**Asserts**: N concurrent workers pwrite()ing disjoint 1 MiB regions of a shared fd do not contaminate each other's bytes. Motivated by FreeBSD commit 39d96e08b0c4 where TCP segment interleaving between concurrent WRITE RPCs on the same socket scrambled bytes between workers.

**Cases**: `case_two_workers_1mib`, `case_four_workers_1mib`, `case_two_workers_small`, `case_overlapping_race`.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `region N byte M = 0x## (expected 0x##) -- cross-region contamination (wire-level write interleaving?)` | NFS client lacks per-fd write serialization. Concurrent WRITE RPCs on the shared TCP socket fragmented and the server reassembled incorrectly. Precedent: FreeBSD 39d96e08b0c4. | `tcpdump -i eth0 -w w.pcap port 2049` during test; look in wireshark for interleaved `NFS WRITE` requests with overlapping XIDs. If present → client socket-write bug. Check the client's per-fd write path for a mutex/semaphore. |
| `worker N exited 0x##` | `pwrite(2)` returned short or -1 inside a worker. Not a data-integrity finding; test harness problem. | `strace` the worker; check if fd survived fork (should; child inherits); check ulimit / RLIMIT_FSIZE. |
| `bit-level corruption during concurrent overlapping writes` (case 4 only) | Bytes that are neither worker tag value. Real corruption — almost always NIC / TCP checksum offload bug or memory fault. | Run `ethtool -K <dev> tx off rx off` and re-test. Check `dmesg` for RDMA errors. |

**False positives**: None known. This test has low noise — a FAIL is almost always meaningful.

**Environmental gates**: None. Runs on any POSIX mount.

---

### <a id="op_aio_races"></a>op_aio_races

**Tier**: POSIX (concurrent write vs truncate atomicity)

**Asserts**: A pwrite racing against ftruncate(fd, 0) on the same file must leave the file in one of two legal states: (A) size 0 (truncate won) or (B) pwrite's written size with exactly the written pattern (pwrite won). Any other state — non-zero size with torn content, oversize, hole not zero-filled — is a bug. Derived from xfstests generic/114's AIO-sub-block vs truncate shape, re-expressed via fork+pwrite so the test stays portable (no libaio / librt dependency).

**Cases**: `case_sub_block_vs_truncate` (512 B at offset 0), `case_extend_vs_truncate` (4 KiB at offset 4 KiB).

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `round %d: illegal size %lld (expected 0 or %lld) -- torn write / partial truncate` | Final file size is neither 0 nor the write's expected end. Server's WRITE and SETATTR(size=0) interleaved in a way that left a partial state. | Capture wire trace of the round. Look for a SETATTR(size=0) that was reordered after a WRITE without a cancelling effect. |
| `round %d: pwrite won but content differs from pattern` | File size matches pwrite but bytes are torn. Most often: server's WRITE landed on a page that SETATTR(size=0) had partially zeroed. | Real integrity bug; this is the generic/114 class. |
| `round %d: head [0..%lld) not zero after write-extend` | `case_extend_vs_truncate` only: after truncate-then-extend, the hole between offset 0 and the write offset must be zeros. Server left stale bytes. | Check server's sparse-write + truncate interaction. |
| `round %d: child exited unexpectedly (status=0x##)` | Child's pwrite hit an error the test classifies as unexpected (not EBADF/EINTR/ENOENT). | Examine `errno` reported by child's exit path. Usually transient; investigate if persistent. |

**False positives**: A race test is probabilistic. Many rounds without a FAIL does not prove absence of the bug — run under load (many parallel invocations, slow RPC path) to increase race surface.

**Environmental gates**: None. Runs on any POSIX mount.

---

### <a id="op_read_write"></a>op_read_write

**Tier**: POSIX (foundation)

**Asserts**: The basic `read`/`write`/`pread`/`pwrite` contract holds on the mount. If this test fails, every other test is built on sand.

**Cases**: `case_same_fd_round_trip`, `case_close_reopen_round_trip`, `case_pwrite_pread_offsets`, `case_sparse_write_past_eof`, `case_read_at_eof`, `case_read_past_eof`, `case_sequential_writes_accumulate`, `case_short_read_tail`, `case_zero_length`.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `case1: data mismatch (...)` | Client-side: write was silently dropped before read on same fd. Server-side: WRITE/READ RPCs not ordered. | Run `op_read_write` locally first; if it FAILs on `/tmp`, platform issue. If only on NFS, check `dmesg` for retransmits. |
| `case2: data mismatch after close-reopen` | Close-to-open coherence broken — classic NFS cache contract violation. | Check `mount | grep ...` for `noac`/`actimeo=0`; re-run under those options. Check server's `stable=FILE_SYNC` return on the close-time COMMIT. |
| `case4: size %lld, expected %zu` | Sparse write didn't extend file size. | Very suspicious. `stat` the file after the test (leaves scratch if FAIL); check server's `change_info` on the SETATTR+size path. |
| `case4: hole byte %zu = 0x%02x` | Hole region read returned non-zero bytes. | Server/client mishandled sparse-read path. Verify with `op_read_plus_sparse case_punch_middle` (same pattern, more detail). |
| `case5: pread at EOF returned %zd (expected 0)` | `read() == size` should return 0, not EIO / EINVAL / short bytes. Client-side POSIX regression. | Check client's EOF handling. |
| `case6: pread past EOF failed: %s (POSIX: return 0, not an error)` | `pread` beyond file size returning error instead of 0. | Same — client-side POSIX regression. |
| `case9: write(len=0) returned error %s` | Zero-length write/read must return 0. | Client or server erroneously returning EINVAL. |

**False positives**: None on any POSIX fs.

**Environmental gates**: None.

---

### <a id="op_overwrite"></a>op_overwrite

**Tier**: POSIX (write-invalidation contract)

**Asserts**: Subsequent writes correctly replace earlier data; overwrites are not silently dropped by client caches or server write-coalescing.

**Cases**: `case_full_same_length`, `case_partial_middle`, `case_extends_past_eof`, `case_unaligned_span`, `case_repeated`, `case_overwrite_with_zeros`.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `case1: overwrite lost -- file still contains 'A'` | Client-side write coalescing bug: second write merged into first and lost. Or server-side WRITE ordering bug. | Check client `/proc/self/mountstats` for merged write counters. Server: check WRITE RPC log for both writes actually reaching server. |
| `case2: got '...' (expected 'AAABBBAAAA')` | Partial middle overwrite not applied or applied at wrong offset. | Dump `pread` at the specific byte; check if the overwrite was truncated, shifted, or dropped. |
| `case4: ... (expected 0x##)` | Unaligned overwrite across a block boundary corrupted an adjacent block's data. | Classic client page-cache-eviction bug. Check whether the client does read-modify-write on misaligned writes. |
| `case5: final read != 'C' -- an intermediate overwrite survived` | Write-coalescing kept an earlier write instead of the last. | Client-side bug: write queue reordered. |
| `case6: byte %zu = 0x%02x (expected 0x00) -- zero overwrite was dropped; original 0xA5 survived` | Server dropped the explicit-zero write (misguided dedup optimization on an already-allocated block). | Server bug or misconfigured option. Compare behavior across server backends. |

**False positives**: None — every case is a POSIX requirement.

**Environmental gates**: None.

---

### <a id="op_writev"></a>op_writev

**Tier**: POSIX (vectored I/O)

**Asserts**: `writev`/`readv`/`pwritev`/`preadv` preserve iovec ordering, aggregate length, and atomic syscall semantics. Detects bugs in the client's iovec-to-WRITE-RPC fragmentation.

**Cases**: `case_small_round_trip`, `case_many_small_iovecs`, `case_mixed_sizes`, `case_pwritev_preadv`, `case_writev_plain_read`, `case_zero_length_in_middle`.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `writev returned %zd (expected N)` | Short writev or error. On NFS, partial writev is valid per POSIX but unusual — client buffer exhaustion? | Check client `dmesg` for write failures. Retry with `make check` to see if intermittent. |
| `iovec[N] mismatch ('...')` | iovec ordering broken. Bytes from a later iovec landed in an earlier slot or vice versa. | Client-side fragmentation bug. Check client's writev → RPC-chunk splitting. |
| `segment %zu ... mismatched -- iovec ordering broken` (case 3) | Same as above but with mixed sizes crossing wsize boundary. This is where fragmentation bugs hide. | Tcpdump the WRITE RPCs; verify each RPC's offset + length matches one or more iovec elements in order. |

**False positives**: None.

**Environmental gates**: `pwritev`/`preadv` are POSIX.1-2008; macOS builds need `_DARWIN_C_SOURCE` (handled in source).

---

### <a id="op_read_plus_sparse"></a>op_read_plus_sparse

**Tier**: SPEC (NFSv4.2 READ_PLUS, RFC 7862 §15)

**Asserts**: Sparse-file reads return correct bytes whether the client uses READ or READ_PLUS. We can't directly observe which was used (wire-level), but the visible contract is "reads through holes return zeros, across boundaries stitch correctly."

**Cases**: `case_punch_middle`, `case_giant_hole`, `case_cross_boundary`, `case_pure_hole`, `case_alternating_stripes`, `case_tail_hole`.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `hole region not all zero (READ_PLUS did not materialise hole as zeros)` | Server returned garbage for a hole extent, or client failed to zero-fill. | Compare against `op_read_write case_sparse_write_past_eof` — if both fail, general sparse bug. |
| `cross-boundary data extent mismatch (READ_PLUS lost data across hole boundary)` | Server REPLY extent list off-by-one. | Check server's READ_PLUS implementation. |
| `case 5 tail hole nonzero (READ_PLUS mis-stitched data-then-hole reply)` | Server returns data past file size or client appends non-zero garbage. | Common server bug. Check `ftruncate` handling on server. |
| `case 6 data stripe N corrupt at byte M (multi-extent stitch lost data)` | Multi-extent reply with alternating DATA/HOLE segments — server got an extent-length count off. | This is the most sensitive READ_PLUS conformance case. Reproduce server-side by dumping extent info. |
| `NOTE: fdatasync: %s` | Non-fatal — reports that fdatasync failed before the sparse read. Not a conformance issue unless accompanied by other FAILs. | None. Inspect the errno. |

**False positives**: None known.

**Environmental gates**: Requires NFSv4.2 mount for the READ_PLUS path to exercise. On NFSv3/v4.0 the client falls back to READ; the test still passes if the server-side sparse layout is correct.

---

### <a id="op_zero_to_hole"></a>op_zero_to_hole

**Tier**: CLIENT (observer; server-backend behaviour)

**Asserts**: Reports how the server represents explicit zero writes (as holes or as allocated zero blocks). Both are POSIX-conformant; the test asserts only the correctness axis (data reads back as zeros). The extent layout is emitted as `NOTE:` for you to see what the server did.

**Cases**: `case_single_zero_block`, `case_blocks_2_and_4`, `case_data_zero_data`, `case_zero_overwrites_data`.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `byte %lld = 0x%02x (expected 0)` | Server or client mangled the zero write — the read-back is non-zero. This IS a bug. | Compare with `op_overwrite case_overwrite_with_zeros`. If both fail, server dedup path is corrupting the actual bytes. |
| `NOTE: ... extent layout ...` | Informational only. Shows how the server represents the file after zero writes. Not a failure. | None. Record the server type for future reference. |

**False positives**: Neither "server punched the zero write" nor "server stored it as data" is a failure — both are legal.

**Environmental gates**: Requires `SEEK_HOLE`/`SEEK_DATA` support. SKIPs otherwise.

---

### <a id="op_stale_handle"></a>op_stale_handle

**Tier**: CLIENT (ESTALE, NFS-specific)

**Asserts**: Behaviour when a file handle becomes stale — the #1 NFS user complaint. Tests that ESTALE is returned at the right time, unlink-while-open works, rename tracks the inode correctly.

**Cases**: See header of `op_stale_handle.c` for the full list.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| any `ESTALE` where not expected | Server aggressively recycled a file handle while client still holds an open. On NFSv4, unlikely under normal conditions; NFSv3 more common. | Check server's `fsid`/handle-generation policy. Linux knfsd: `/proc/fs/nfsd/*`. |
| `case ... open fd became invalid after ...` | NFS client didn't silly-rename on open+unlink. | Inspect `/proc/self/mountstats`; look for silly-rename counters. |

**False positives**: On local filesystems everything passes. On NFS, occasional ESTALE on handle generation rollover is possible but rare.

**Environmental gates**: None; runs on any POSIX mount (local always passes).

---

### <a id="op_mmap_msync"></a>op_mmap_msync

**Tier**: POSIX (mmap over NFS — the #1 data-loss source for mmap apps)

**Asserts**: mmap'd writes are visible after `msync(MS_SYNC)`; munmap alone is NOT sufficient to flush dirty pages to the server; server-side data matches client-side mapping after sync.

**Cases**: See `op_mmap_msync.c` header.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `data lost after munmap without msync` | Expected failure mode on NFS — the test asserts this is NOT the case when `msync(MS_SYNC)` is called. Failure means msync didn't actually flush. | Check server's COMMIT handling after msync; check client `msync` → WRITE+COMMIT path. |
| `data visible to fresh open before msync` | Unexpected — dirty pages are visible across fds before flush. Not a bug, but suspicious. | Record the mount options; likely `sync`-mode mount. |

**False positives**: On local FS all cases pass trivially. Real findings are NFS-specific.

**Environmental gates**: None.

---

### <a id="op_close_to_open"></a>op_close_to_open

**Tier**: CLIENT (NFS close-to-open coherence contract)

**Asserts**: After `close(fd)`, a fresh `open()` on the same path sees the latest data — the CTO contract. If this fails, basically every NFS application is in trouble.

**Cases**: See `op_close_to_open.c` header.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `fresh open saw stale data` | CTO broken. Either client didn't flush on close, or server didn't commit, or GETATTR on open returned cached pre-close attrs. | This is a red-alert NFS bug. `rpcdebug -m nfs -s all` + retest. Check client for retries, cache configuration. |
| Any `data mismatch after close+reopen` | Same class. | Same diagnosis. |

**False positives**: None — CTO is a contract.

**Environmental gates**: None; this is always on.

---

### <a id="op_noac"></a>op_noac

**Tier**: CLIENT (mount option)

**Asserts**: When mounted `-o noac`, attribute changes are visible immediately without waiting for the attribute cache TTL.

**Cases**: See `op_noac.c` header.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `attr change not immediately visible (attrcache still active?)` | Client did not disable attrcache despite noac in mount options. | `cat /proc/self/mountinfo | grep noac` — verify the option reached the client. Check kernel version; some older clients ignored noac. |

**False positives**: None when noac is actually set.

**Environmental gates**: **REQUIRES** the mount to have `noac`. Auto-skips otherwise with `NOTE:`. Force-run with `-f`.

---

### <a id="op_root_squash"></a>op_root_squash

**Tier**: CLIENT (server export setting)

**Asserts**: When the export has `root_squash`, uid-0 operations are mapped to the anonymous uid (typically nobody/65534).

**Cases**: See `op_root_squash.c` header.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `file created as root retained uid 0 (no_root_squash?)` | Export is actually `no_root_squash`; the test doesn't know. | Check `exportfs -v` on the server. If no_root_squash, this "failure" is just wrong test configuration. |
| `file created as root has unexpected uid %u` (not 0, not 65534) | Export uses `anonuid=...` with a different value. | Record the mount; adjust the comparison base. |

**False positives**: If the server actually runs no_root_squash, every case will "FAIL" in a way that's really "you enabled the wrong thing."

**Environmental gates**: **REQUIRES** running as root. Skips otherwise. Export must be set up with root_squash.

---

### <a id="op_soft_timeout"></a>op_soft_timeout

**Tier**: CLIENT (mount option: `-o soft`)

**Asserts**: Soft-mounted operations fail cleanly (EIO / ETIMEDOUT) rather than hanging indefinitely.

**Cases**: See `op_soft_timeout.c` header.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `operation hung past timeout` | Soft timeout didn't fire, or client didn't honor `timeo=` param. | Inspect `/proc/self/mountstats`; check timeout counters. |

**False positives**: None when soft is actually set.

**Environmental gates**: **REQUIRES** `soft`/`softerr`/`softreval` mount option. Skips otherwise.

---

### <a id="op_rsize_wsize"></a>op_rsize_wsize

**Tier**: CLIENT (mount option boundary I/O)

**Asserts**: Reads and writes that are larger than the mount's `rsize`/`wsize` are correctly fragmented into multiple RPCs and reassembled.

**Cases**: See `op_rsize_wsize.c` header.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `data at boundary (offset %lld) corrupted` | Client fragmentation bug: adjacent chunks overlap or have a gap. | Tcpdump; inspect RPC offsets and lengths. |
| `short read at boundary: %zd < expected` | Client didn't re-request the missing tail. | Retry logic in client's read path. |

**False positives**: None.

**Environmental gates**: Auto-detects `rsize`/`wsize` from `/proc/self/mountinfo`. Requires Linux for detection; on other platforms runs but with unknown boundary.

---

### <a id="op_direct_io"></a>op_direct_io

**Tier**: CLIENT (O_DIRECT per-open cache bypass)

**Asserts**: `O_DIRECT` opens bypass the client page cache; writes land on the server immediately; a separate buffered reader sees the written bytes.

**Cases**: `case_direct_open`, `case_direct_round_trip`, `case_direct_cross_visibility`, `case_direct_unaligned`, `case_direct_large`, `case_failed_write_no_stale_data` (generic/250).

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `NOTE: case1 server/client refuses O_DIRECT (EINVAL)` | Some NFS configurations reject O_DIRECT. Not a bug — informational. | Record the mount options; possibly `nocto`/`sync` settings interact. |
| `case3: reader saw stale data (O_DIRECT write not reflected server-side)` | O_DIRECT write didn't reach the server before the fresh reader's GETATTR-then-READ. | Client O_DIRECT path didn't force WRITE+COMMIT. Check client's O_DIRECT implementation. |
| `case3: reader saw short read` | Similar: server size attribute hadn't updated. | Same as above. |
| `case2: data mismatch after O_DIRECT write + buffered read` | Round-trip corruption via O_DIRECT. | Very suspicious — check alignment, check cache coherence. |
| `case6: pattern A corrupted at byte %zu after pwrite returned -1/%s` | pwrite returned -1 yet the file content changed — rejected writes must be all-or-nothing, never a partial update. | Real integrity bug: capture both wire traces (the rejected WRITE and the subsequent READ) and compare. |

**False positives**: O_DIRECT rejection (EINVAL) is reported as NOTE, not FAIL — expected on some servers.

**Environmental gates**: Linux-only. macOS skips (uses `F_NOCACHE` with different semantics).

---

### <a id="op_lock"></a>op_lock

**Tier**: SPEC (NFSv4 LOCK/LOCKU, RFC 7530 §18.10-12 via POSIX fcntl)

**Asserts**: POSIX byte-range locks via `fcntl(F_SETLK/F_GETLK)` work correctly over NFS.

**Cases**: See `op_lock.c` header (7 cases covering write lock, read lock, conflict, non-overlapping, shared reader, upgrade, F_SETLKW blocking).

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `F_SETLK ... ENOLCK` | NFS lock manager (lockd / nfslockd) not running on client. Auto-skipped in case 1. | Start lockd/nfslockd and remount. |
| `F_SETLK failed: %s` | Server rejected the lock. | Check server `rpcinfo -p | grep nlock` (v3) or NFSv4 session state. |
| `F_GETLK on own lock expected F_UNLCK, got type=%d` | Server reporting the owner's own lock as conflicting — broken. | Server's LOCKT op is mis-attributing owners. |
| `F_SETLK succeeded despite child lock` (case 3) | Lock isolation broken between processes. | Real server bug. |
| `expected EAGAIN/EACCES, got %s` | Server returning wrong errno on conflict. | Not fatal to functionality; POSIX strict. |

**False positives**: ENOLCK causes SKIP, not FAIL.

**Environmental gates**: NFS lock manager must be running. Skips if ENOLCK on first lock attempt.

---

### <a id="op_lock_posix"></a>op_lock_posix

**Tier**: POSIX (byte-range lock semantics: close catastrophe, coalescing, splitting)

**Asserts**: Three subtle POSIX lock semantics that often trip up NFS servers:

1. Close-releases-all-locks catastrophe: closing any fd to a file releases all POSIX locks the process holds.
2. Coalescing: adjacent same-type locks merge.
3. Splitting: partial unlock splits the lock range.

**Cases**: `case_close_catastrophe`, `case_ofd_contrast`, `case_coalescing`, `case_splitting`, `case_conflict_pid`, `case_unlock_unheld`.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `POSIX close-releases-all-locks not honoured` | Server/client violating the POSIX "catastrophe" semantic. Rare but real — some implementations track locks per-fd instead of per-process. | If reproducible, file as conformance bug. |
| `OFD lock released by closing unrelated fd` | OFD lock wrongly subjected to the close-catastrophe. Client/server didn't distinguish POSIX from OFD owner semantics. | Real bug; check kernel version (F_OFD_* is Linux 3.15+). |
| `child acquired [10,20) after parent held [0,25)` | Lock splitting broken; server lost track of the split ranges. | Server-side lock-manager bug. |
| `child could not acquire [40,50) after parent's partial unlock` | Same class — split didn't happen. | Server bug. |
| `unlock [0,15) after coalesce: ...` | Adjacent locks didn't merge. | Server's lock coalescing algorithm off. |
| `F_UNLCK on unheld range: ...` | Server rejected a no-op unlock. Spec says success. | Non-conformance. |
| `F_GETLK reported wrong pid` | Server's LOCKT reply carries wrong owner. | Server-side bug. |

**False positives**: None.

**Environmental gates**: Case 2 (OFD) requires Linux 3.15+; auto-NOTE otherwise.

---

### <a id="op_ofd_lock"></a>op_ofd_lock

**Tier**: SPEC (NFSv4 LOCK with per-open-file-description owner)

**Asserts**: F_OFD_SETLK / F_OFD_GETLK / F_OFD_SETLKW have per-fd owner semantics (don't suffer the POSIX close catastrophe).

**Failure patterns**: Similar shape to op_lock; distinguishing feature is that a second fd in the same process should NOT conflict with an OFD lock on fd1.

**Environmental gates**: Linux 3.15+ only.

---

### <a id="op_append"></a>op_append

**Tier**: POSIX (O_APPEND atomicity)

**Asserts**: O_APPEND writes are atomic seek-to-end + write. Concurrent appenders from two processes cannot lose each other's data.

**Cases**: See `op_append.c` header (7 cases; case 5 is known to NOTE on Linux NFS due to pwrite+O_APPEND behavior).

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `case 4 concurrent fork: lost N records` | O_APPEND atomicity broken in concurrent path. Server or client didn't serialize appends at EOF. | Real bug. Reproduce with more workers. |
| `case 6 O_TRUNC didn't reset size` | Open with O_TRUNC followed by O_APPEND write didn't start at 0. | Client or server open-path bug. |
| `NOTE: case 5 pwrite+O_APPEND ...` | Informational — Linux NFS client applies O_APPEND to pwrite in violation of POSIX. | Not a failure; known Linux behavior. |

**False positives**: Case 5 on Linux is a known NOTE, not FAIL.

**Environmental gates**: None.

---

### <a id="op_sync_dsync"></a>op_sync_dsync

**Tier**: SPEC (durability contract: O_SYNC, O_DSYNC)

**Asserts**: After `write()` returns on a fd opened with O_SYNC/O_DSYNC, the data is durably on the server — a crash then would not lose the write.

**Cases**: 6 cases covering round-trip, child-exit durability, large writes, fsync after close.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `child write not durable: read %zd (server did not honor FILE_SYNC)` | Server replied to WRITE with stable=UNSTABLE instead of FILE_SYNC. | Server bug. Tcpdump and inspect WRITE reply's stable_how. |
| `durable read mismatch` | Data reached server but corrupted in transit. | Very rare — check NIC offloads. |

**False positives**: None.

**Environmental gates**: None.

---

### <a id="op_commit"></a>op_commit

**Tier**: SPEC (NFSv4 COMMIT)

**Asserts**: fsync(2) / fdatasync(2) trigger a COMMIT op that forces server write-back. Subsequent operations see the committed data, and fsync also persists parent-directory mutations and fallocate allocations.

**Cases**: `case_fsync_roundtrip`, `case_fdatasync_roundtrip`, `case_log_style`, `case_fsync_ronly_fd`, `case_fsync_empty`, `case_fsync_after_unlink_hardlink` (generic/039), `case_fsync_after_fallocate` (generic/042).

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `data mismatch at byte %zu after fsync` | Server COMMIT did not persist writes before returning, or client returned from fsync before receiving the COMMIT reply. | Server-side COMMIT handling; capture wire trace. |
| `case6: b still present after fsync + reopen (unlink not persisted)` | Parent-directory unlink did not survive fsync on the sibling file. Server fsync scope too narrow, or client cached stale dirent. | Server: check whether fsync covers parent dir entry updates. Client: drop kernel NFS cache and retry. |
| `case6: a.nlink=%ld after unlink of b (expected 1)` | nlink attribute stale on fresh fd. Server GETATTR returned old count. | Server change-attribute semantics; check whether unlink bumps the directory's change attr and inode attrs. |
| `case7: stale content in fallocate-but-never-written range` | ALLOCATE exposed uninitialised backing bytes. Real integrity bug — server must zero-fill or reserve without exposing. | Capture a READ of the range via wire trace; compare what the server returns with the inode's allocated block state. |
| `case7 posix_fallocate ... - skipping` | Environmental: macOS, or NFS server refuses ALLOCATE. | Not a failure. |

**Environmental gates**: Case 7 skipped on macOS (no posix_fallocate) or when server rejects ALLOCATE.

---

### <a id="op_rename_nlink"></a>op_rename_nlink

**Tier**: POSIX (rename semantics)

**Asserts**: Cross-parent directory rename and rename-replace correctly update nlink and parent timestamps.

**Cases**: `case_cross_parent_dir`, `case_rename_replace_dir`, `case_file_no_nlink_change`, `case_parent_timestamps`.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `case3: src nlink changed from %lu to %lu (regular file rename must not change parent nlink)` | File rename changing parent nlink — indicates the server counts files in directory nlink (APFS quirk; not POSIX-conformant but not universally rejected). | On macOS: known quirk; expected FAIL. On NFS against ext4/xfs: real bug. |
| `case4: src parent mtime did not advance` | POSIX requires rename() to advance the src + dst parent mtime. Server didn't. | Real conformance bug. |
| `NOTE: case1/2 ... nlink %lu -> %lu (traditional Unix expects ...)` | Server reports constant st_nlink for directories — not traditional but POSIX-legal. | Not a failure. |

**False positives**: Case 3 on macOS/APFS is a known local-FS quirk.

**Environmental gates**: None.

---

### <a id="op_rename_open_target"></a>op_rename_open_target

**Tier**: POSIX (rename of held-open file)

**Asserts**: Renaming over an open target leaves the open fd valid (POSIX silly-rename contract).

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `open fd on renamed-over target returned ESTALE` | Server didn't preserve the orphaned inode. NFS silly-rename should keep the open-but-unlinked inode accessible. | Server-side silly-rename implementation missing or broken. |
| `data mismatch after rename+read` | Reads from the open fd hit the wrong inode. | Real bug — check client's silly-rename path. |

**Environmental gates**: None.

---

### <a id="op_readdir_mutation"></a>op_readdir_mutation

**Tier**: POSIX (readdir + directory mutation)

**Asserts**: Concurrent mutation and readdir produce sane results: the remaining entries are surfaced, telldir/seekdir cookies work, rewinddir sees the current state.

**Cases**: `case_read_delete_continue`, `case_rewinddir_after_mutation`, `case_telldir_seekdir_survival`, `case_empty_after_delete`, `case_two_streams`.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `readdir skipped N extant entries after mid-iteration deletions` | Client directory cookie invalidation broken — entries lost from view after an unrelated delete. | Server-side cookie-stability issue, or client cookie-cache eviction bug. |
| `rewinddir showed deleted entry (stale snapshot across rewinddir)` | Client cached directory snapshot at open time and didn't refresh on rewinddir. | Client bug. |
| `rewinddir missed N of M newly-added entries` | Same class. | Same. |
| `NOTE: seekdir revisited N already-consumed entries after mid-stream delete` | Informational only — NFS cookie-stability semantic varies by server; pro-LIT spec-permitted. | None. |
| `two DIR* streams show interference` | Opening the same directory twice should yield independent iterators. If one affects the other, client bug. | Client-side: check DIR* state management. |

**Environmental gates**: None.

---

### <a id="op_readdir_many"></a>op_readdir_many

**Tier**: SPEC (NFSv4 READDIR cookie continuation)

**Asserts**: Large directories (default 256 entries, `-N` override) readdir correctly across multiple READDIR RPCs without losing or duplicating entries.

**Failure patterns**: "continuation dropped N entries" → server cookie validity expired; "duplicate entry" → cookie replay bug.

**Environmental gates**: None.

---

### <a id="op_timestamps"></a>op_timestamps

**Tier**: POSIX (atime/mtime/ctime cascades)

**Asserts**: Specific syscalls advance specific timestamps per POSIX (write → mtime+ctime; read → atime; chmod → ctime only; etc.).

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `case1: mtime did not advance after write` | Server didn't stamp mtime on WRITE, OR client's attrcache is stale. | Check mount options for `nodiratime`/`noatime`; check server's SETATTR on WRITE path. |
| `case3: ctime did not advance after chmod` | Server's chmod path doesn't update ctime. | Real conformance bug. |
| `case8: mtime nsec truncated to 0` (NOTE) | Server has second-granularity timestamps. | Known on many filesystems; informational. |
| `NOTE: case2 atime did not advance after read — mount is likely noatime/relatime/nodiratime` | Expected on mount-option-tuned systems. | None. |

**False positives**: `atime` advancement is frequently disabled by mount options; that's a NOTE.

**Environmental gates**: None.

---

### <a id="op_errno_rename"></a>op_errno_rename

**Tier**: POSIX (rename errno paths)

**Asserts**: `rename()` returns the correct errno for each failure case (EINVAL on `.`/`..`, ENOTDIR, EISDIR, ENOTEMPTY, EINVAL on parent-into-child, ENOENT on missing).

**Failure patterns**: Each case emits `case%d: got %s (%d); expected one of the allowed errnos`. The likely cause is server returning the wrong errno — often a direct NFSv4 → POSIX errno mapping bug.

**Environmental gates**: None.

---

### <a id="op_errno_open"></a>op_errno_open

**Tier**: POSIX (open errno paths)

**Asserts**: `open()` returns the correct errno (ENOENT, ENOTDIR, EISDIR, ENXIO on FIFO, EEXIST).

**Failure patterns**: Similar to op_errno_rename. Root cause almost always an NFSv4 → errno mapping bug in the client.

**Environmental gates**: Case 6 (FIFO) skips if mkfifo is rejected by the FS.

---

### <a id="op_errno_link"></a>op_errno_link

**Tier**: POSIX (link errno paths)

**Asserts**: `link()` returns ENOENT, EEXIST, EPERM/EACCES on directory, ENOTDIR on bad path prefix.

**Failure patterns**: Errno mismatches. Real fix is client's errno mapping.

**Environmental gates**: None.

---

### <a id="op_path_limits"></a>op_path_limits

**Tier**: POSIX (ENAMETOOLONG)

**Asserts**: Path components > NAME_MAX and paths > PATH_MAX return ENAMETOOLONG.

**Failure patterns**: Case succeeding where it should fail, or returning wrong errno. Probably NFS server has different limits than client advertises.

**Environmental gates**: None.

---

### <a id="op_symlink_loop"></a>op_symlink_loop

**Tier**: POSIX (ELOOP / symlink chain depth)

**Asserts**: `open()` on a symlink cycle or a chain exceeding SYMLOOP_MAX returns ELOOP.

**Failure patterns**: "open(N-cycle) succeeded" → client or server symlink-loop detector broken; infinite chain follows → kernel bug territory.

**Environmental gates**: None.

---

### <a id="op_sticky_bit"></a>op_sticky_bit

**Tier**: POSIX (S_ISVTX)

**Asserts**: Sticky bit (01000) propagates to server and is preserved; owner can always unlink/rename their own files in a sticky dir. Cross-uid enforcement explicitly not tested here.

**Failure patterns**: "S_ISVTX not set" → server masked the bit; "owner cannot unlink own file in sticky dir" → client/server wrongly applying sticky enforcement to owner.

**Environmental gates**: None. Cross-uid testing needs pjdfstest.

---

### <a id="op_deleg_attr"></a>op_deleg_attr

**Tier**: SPEC (NFSv4 CB_GETATTR, write delegation attribute path)

**Asserts**: Attribute delegation via GETATTR → CB_GETATTR path works. Uses `cb_getattr_probe` as a second client to hold a conflicting state.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `case 8 -m: GETATTR count rose by N during thread stat` | Client issued unnecessary wire GETATTR despite holding a delegation. | Check client's delegation-cache logic. Only reported when `-m` is passed (mountstats strict). |
| `probe not found / not executable` | `cb_getattr_probe` wasn't built or not in PATH. | `make` and `export PATH=.:$PATH`. |

**Environmental gates**: Requires the probe to be running on a separate client.

---

### <a id="op_deleg_recall"></a>op_deleg_recall

**Tier**: SPEC (NFSv4 CB_RECALL)

**Asserts**: Server successfully recalls a write delegation when a conflicting OPEN arrives from another client.

**Failure patterns**: Delegation not recalled → server's callback channel broken.

**Environmental gates**: Needs `cb_recall_probe`.

---

### <a id="op_deleg_read"></a>op_deleg_read

**Tier**: SPEC (NFSv4 read delegation + recall on write)

**Asserts**: Read delegation is granted; a conflicting write from another client recalls the delegation.

**Failure patterns**: Similar to op_deleg_recall.

**Environmental gates**: Needs `cb_recall_probe`.

---

### <a id="op_delegation_write"></a>op_delegation_write

**Tier**: SPEC (NFSv4 OPEN_DELEGATE_WRITE)

**Asserts**: Write delegation granted; write-through-delegation works; recall happens on conflicting open.

**Failure patterns**: Delegation not granted (server never offers) → informational, some servers don't grant write delegations by default. Delegation granted but recall fails → server callback issue.

**Environmental gates**: None required; but skips informatively if server never grants delegations.

---

### <a id="op_copy"></a>op_copy

**Tier**: SPEC (NFSv4.2 COPY, RFC 7862 §7)

**Asserts**: `copy_file_range(2)` maps to NFSv4.2 intra-server COPY. Data is transferred server-side (no round-trip through client memory) when source and destination are on the same server.

**Cases**: `case_simple`, `case_offset`, `case_sparse_preservation`, `case_matrix_api` (generic/430).

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `copy_file_range: %s` | Syscall error — most commonly EXDEV (cross-filesystem) or EOPNOTSUPP (client doesn't map to COPY). | Check `statfs` — are src and dst on same mount? Check mount is NFSv4.2. |
| `copy_file_range short (got %zu of %zu)` | Partial copy. POSIX allows but unusual on NFSv4.2 COPY. | Retry logic expected; record as NOTE or investigate if persistent. |
| `case1: dst mismatch at byte %zu` | COPY corrupted data. Real server bug. | Extract the bad byte; compare with op_read_write case 3 for baseline data integrity. |
| `case3: hole region in dst not zero-filled` | COPY didn't preserve sparse layout — or the hole was materialized as garbage. | Compare with `op_read_plus_sparse case_punch_middle`; if that passes, COPY-specific hole-handling bug. |
| `case4a: copy_file_range(len=0) returned %zd (expected 0)` | Zero-length call doesn't short-circuit to 0. Kernel bug. | Check syscall entry, usually a missing `if (!len) return 0`. |
| `case4b: unexpected errno ... (expected EINVAL)` | Non-zero flags argument not rejected. | Some older kernels accept unknown flags; if persistent on recent kernels, server/client API contract violation. |
| `case4c: over-copy %zd > src %zu` | Returned more bytes than src holds. Really a bug. | Capture wire trace of COPY; check server's src-EOF handling. |
| `case4c: EOF call returned %zd (expected 0)` | Second call past EOF should return 0; returned something else. | Server advances soff past EOF; should stop cleanly. |

**False positives**: `copy_file_range` may fall back to a read/write loop on the client — all-zero hole preservation still required but may behave differently. Not a failure.

**Environmental gates**: Linux 4.5+, FreeBSD 13+, same-filesystem mount. Skips otherwise.

---

### <a id="op_clone"></a>op_clone

**Tier**: SPEC (NFSv4.2 CLONE, RFC 7862 §5)

**Asserts**: `ioctl(FICLONE)` creates a copy-on-write clone. Modifications to src do not affect dst.

**Cases**: `case_basic_clone`, `case_cow_semantics`.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `ioctl(FICLONE): %s` | Filesystem doesn't support reflink. Common errors: EOPNOTSUPP, EINVAL, EXDEV. | Check backend FS (`mount | grep <fs>`); reflink requires btrfs, xfs with reflink=1, ZFS, or an NFSv4.2 server that supports CLONE over such a backend. |
| `case2: dst was affected by src mutation` | COW broken — dst shares storage with src AND isn't marked CoW on write. Real bug; clones must isolate writes. | Inspect server-side reflink handling. Check kernel version. |
| `clone content mismatch at byte %zu` | Initial clone didn't copy all bytes. | Server CLONE op implementation bug. |

**False positives**: FICLONE skip on non-reflink FS is expected and self-documents.

**Environmental gates**: Linux + reflink FS (btrfs / xfs-reflink / zfs) required.

---

### <a id="op_truncate_grow"></a>op_truncate_grow

**Tier**: POSIX (SETATTR(size) hole-creating grow, RFC 7530 §5.8.1.5)

**Asserts**: `ftruncate(fd, size)` where new size > current size grows the file, fills the extension with zeros, and preserves existing data.

**Cases**: `case_grow_from_empty`, `case_grow_with_prefix`, `case_grow_and_seek_hole`.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `case1: grown region not all zero` | Grow extension contains garbage. Classic NFS bug on some servers that don't zero-fill the extension. | Real conformance failure. Check server's SETATTR(size) grow path. |
| `case2: prefix corrupted by grow` | Existing data changed after grow. | Serious — server or client wrote past EOF. |
| `case2: grown tail not all zero` | Same class as case 1, but with non-empty prefix. | Same. |
| `case3: SEEK_HOLE returned %lld` | After grow, SEEK_HOLE didn't find the new hole at the old EOF. | Server didn't mark the extension as a hole; allocated zero-fill. Not a conformance failure per se, but suspicious if the server advertises sparse-file support. |

**False positives**: None on a POSIX fs.

**Environmental gates**: None; uses POSIX `ftruncate`.

---

### <a id="op_unicode_names"></a>op_unicode_names

**Tier**: SPEC (NFSv4 name encoding, RFC 7530 §1.4.2)

**Asserts**: UTF-8 names round-trip correctly through create, readdir, stat, rename, unlink. Covers ASCII (1-byte), Latin-1 (2-byte), CJK (3-byte), emoji (4-byte), and rename-across-byte-widths.

**Cases**: `case_ascii`, `case_latin1`, `case_cjk`, `case_emoji`, `case_rename_across_widths`.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `create(%s): %s` | Server refused a valid UTF-8 name. Commonly EILSEQ (server enforces a charset) or EINVAL. | Check server config — NFS servers often have a name charset policy (utf8mb3 vs utf8mb4 — emoji rejection). |
| `readdir did not return %s` | Name created but not visible in readdir. Server normalized the name on store but not on lookup. | Unicode normalization bug: check for NFKC vs NFD mismatches. |
| `rename(XB->YB) ...: %s` | Rename across UTF-8 byte widths failed. Some servers reject such renames as a heuristic against charset confusion. | Server name-encoding validation too strict. |
| `%s not visible after rename` | Rename succeeded but the target name can't be looked up. | Normalization applied on write but not on lookup path. |

**False positives**: Some NFSv3 servers only accept ASCII; they return EILSEQ for non-ASCII. Skip/FAIL depending on server config.

**Environmental gates**: UTF-8 locale required; test does not set LC_ALL itself.

---

### <a id="op_verify"></a>op_verify

**Tier**: SPEC (NFSv4 VERIFY / NVERIFY, RFC 7530 §18.28 / §18.19)

**Asserts**: Attribute consistency across back-to-back stat calls plus mode / mtime / uid-gid round-trip.  (Change-attr monotonicity is covered separately by `op_change_attr`, which uses the typed kernel header rather than raw byte offsets.)

**Cases**: `case_stat_consistency`, `case_size_after_write`, `case_mode_after_chmod`, `case_mtime_after_write`, `case_uid_gid_preserved`.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `st_ino changed between two stats` | Inode number changed — serious. Either client recycled the inode cache between stats or server changed the handle. | Inspect client attrcache; check for deferred OPEN/OPEN_CONFIRM churn. |
| `st_mode / st_uid / st_gid / st_size changed` | Attribute flipped without corresponding operation. Two calls to stat with no intervening modification must agree. | Client attrcache inconsistency. |
| `short write (%zd)` | Write didn't transfer full buffer. Environmental (ENOSPC, quota) or client buffer exhaustion. | Check server free space and export permissions. |

**False positives**: None on a quiet mount. On a mount with concurrent activity, attribute flips are possible and expected; run this test on a quiescent mount.

**Environmental gates**: None.

---

### <a id="op_unlink"></a>op_unlink

**Tier**: POSIX (REMOVE, silly-rename)

**Asserts**: `unlink(2)` removes the name; open-then-unlink-then-read works (silly-rename contract on NFS); unlink vs open-count interaction.

**Cases**: See `op_unlink.c` header.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| Open fd gets ESTALE after unlink | Silly-rename not implemented — server reaped the inode while client held an open. | Check `/proc/self/mountstats` for silly-rename counters; check client NFS version. |
| `unlink of nonexistent succeeded` | Client cached a "deleted" entry and returned success instead of ENOENT. | Client directory cache coherence bug. |
| `stat after unlink succeeded` | Same class — client returning stale positive lookup. | Check client dentry cache. |

**False positives**: None on a clean mount.

**Environmental gates**: None.

---

### <a id="op_read_write_large"></a>op_read_write_large

**Tier**: POSIX (large / unaligned I/O stress)

**Asserts**: `pread`/`pwrite` at offsets >4 GiB, in 1-4 MiB chunks, unaligned. Exercises the client's fragmentation path across large transfers.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| Data mismatch at offset >4 GiB | 32-bit truncation somewhere in the I/O path — client, server, or tcpdump tool. | Verify file size with `ls -l` (not `ls -sh`) and `stat`. Small first — try 2 GiB and bisect. |
| Short write / short read on large transfer | Client didn't retry the tail of a partial transfer. | POSIX permits shortness but should be rare on a healthy mount. |
| Data mismatch on unaligned I/O | Client's read-modify-write path corrupted an adjacent region. | Bisect to an aligned transfer; isolate the alignment. |

**False positives**: None.

**Environmental gates**: Requires enough free space for the large files (several GiB).

---

### <a id="op_rename_atomic"></a>op_rename_atomic

**Tier**: SPEC (renameat2 / NFSv4 RENAME with atomic flags)

**Asserts**: `renameat2(2)` with `RENAME_NOREPLACE` fails if target exists; with `RENAME_EXCHANGE` swaps two existing paths atomically. Client must pass these flags through to the server's RENAME op.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `RENAME_NOREPLACE not supported (returned Invalid argument)` | Client ≤6.0 does not pass renameat2 flags through to NFS; returns EINVAL. Auto-SKIPs. | Upgrade client to Linux 6.1+ and retest. |
| `RENAME_NOREPLACE: target replaced despite flag` | Client accepted the flag but didn't enforce; or server silently ignored the atomicity flag. | Real conformance bug. |
| `RENAME_EXCHANGE: paths not swapped atomically` | Exchange produced intermediate state; observer saw one path empty momentarily. | Server doesn't implement exchange atomically. |

**Environmental gates**: Linux 6.1+ client + server that supports NFSv4 RENAME with flag passthrough.

---

### <a id="op_symlink_nofollow"></a>op_symlink_nofollow

**Tier**: POSIX (AT_SYMLINK_NOFOLLOW + O_NOFOLLOW)

**Asserts**: Syscalls that take `AT_SYMLINK_NOFOLLOW` (or the file descriptor equivalent `O_NOFOLLOW`) operate on the link itself, not the target. `fstatat`, `utimensat`, `fchownat`, `linkat` all must honor the flag. The most NFS-conformance-sensitive tests in this file are utimensat-nofollow (classic NFS server bug: timestamp change follows to target) and fchownat-nofollow (tar/rsync depend on this).

**Cases**: See `op_symlink_nofollow.c` header.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `utimensat with AT_SYMLINK_NOFOLLOW advanced target mtime` | Server ignored the nofollow flag and modified the symlink target instead of the link. Classic NFSv4 SETATTR-on-link bug. | Real server bug. Verify against symlink inode via `lstat`. |
| `fchownat with AT_SYMLINK_NOFOLLOW changed target ownership` | Same class. `tar -xp` and `rsync -l` rely on this. | Real server bug. |
| `fstatat nofollow returned target mode` | Server returned the target's stat instead of the symlink's. | Server-side `AT_SYMLINK_NOFOLLOW` not honored. |
| `linkat ... AT_SYMLINK_FOLLOW ...` | Hardlink to target vs to symlink distinction broken. | Server link path bug. |

**Environmental gates**: None. Classic test — well-worth running first against any new server.

---

### <a id="op_chmod_chown"></a>op_chmod_chown

**Tier**: POSIX (SETATTR with uid/gid mapping, setuid/setgid clearing)

**Asserts**: chmod/chown round-trip; setuid/setgid bits are cleared when file ownership changes (POSIX security rule).

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `NOTE: case5/case6 chown(self) returned EINVAL (client-side idmap cannot resolve uid %u)` | Linux NFSv4 idmap sends owner as string `user@domain`; if rpc.idmapd can't resolve or domain mismatches, server returns NFS4ERR_BADOWNER → EINVAL. Handled as NOTE, not FAIL. | Start `rpc.idmapd` or `echo Y > /sys/module/nfs/parameters/nfs4_disable_idmapping` and remount. See README "Interpreting environmental NOTEs". |
| `setuid/setgid not cleared after chown` | POSIX security rule violated. Server should strip S_ISUID/S_ISGID when chown changes the file owner. | Server bug. |
| `chmod did not advance ctime` | ctime must advance per POSIX. | See op_timestamps for similar. |

**Environmental gates**: idmap-related NOTEs are common and expected on Linux clients without idmapd.

---

### <a id="op_seek"></a>op_seek

**Tier**: SPEC (NFSv4.2 SEEK, RFC 7862 §6; READ_PLUS §8 coverage shared with op_read_plus_sparse)

**Asserts**: `lseek(SEEK_HOLE)` and `lseek(SEEK_DATA)` find the next hole/data boundary on a sparse file. Reads through holes return zeros.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `SEEK_HOLE at island0 reports premature hole` | Server returned a hole offset inside the data extent. | Server-side SEEK op returns wrong boundary. |
| `SEEK_DATA past EOF: expected -1/ENXIO or %lld, got ...` | NFSv4.2 SEEK past EOF semantic: some servers set sr_eof=TRUE and return the file size; Linux client typically returns ENXIO via lseek. Both are accepted; third outcomes are bugs. | Inspect. |
| `hole N not all zero` | Read through a hole returned garbage bytes. | Client or server sparse-read path broken. Cross-check with `op_read_plus_sparse`. |

**Environmental gates**: `SEEK_HOLE`/`SEEK_DATA` required. macOS 10.15+ / Linux / FreeBSD 10+ / Solaris. Not set on FreeBSD under `_XOPEN_SOURCE=700` — Makefile guards with `#ifndef __FreeBSD__`.

---

### <a id="op_allocate"></a>op_allocate

**Tier**: SPEC (NFSv4.2 ALLOCATE, RFC 7862 §4)

**Asserts**: `posix_fallocate(3)` preallocates disk blocks, extends the file if needed, and fills the extension with zeros.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `SKIP: posix_fallocate returned EINVAL -- NFS client does not support ALLOCATE on this mount` | Client (e.g., FreeBSD) doesn't map posix_fallocate → ALLOCATE. Not a conformance failure; informational. | Upgrade client or accept the gap. |
| `case1: allocated region not all zero` | ALLOCATE extended the file but the new bytes are garbage. | Server bug — ALLOCATE must zero-fill. |
| `case1: size %lld != expected` | ALLOCATE didn't extend the file size. | Server handled ALLOCATE as a no-op; not compliant with RFC 7862. |
| `NOTE: st_blocks == 0 after ALLOCATE -- suspicious` | Informational: the server may have treated ALLOCATE as a promise without actually allocating. Not a conformance failure per se. | None — record the server backend. |

**Environmental gates**: Linux + server supporting NFSv4.2 ALLOCATE. Auto-skips on FreeBSD via EINVAL detection.

---

### <a id="op_access"></a>op_access

**Tier**: POSIX (access / faccessat)

**Asserts**: `access(2)` and `faccessat(2)` return 0 for permitted modes, -1/ENOENT for missing files, -1/EACCES for denied modes.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `access(%s, F_OK): %s` | F_OK on an existing file failed. Basic lookup broken. | Check with `stat`; inspect client dcache. |
| `case2: expected ENOENT, got %s` | access() on missing file returned wrong errno. | Client-side errno mapping. |
| `access(W_OK) on 0444 unexpectedly` / `NOTE: case4 W_OK on 0444 succeeded` | POSIX says non-root W_OK on read-only mode fails EACCES; some systems (Linux with CAP_DAC_OVERRIDE, running as root) allow. NOTE only when running as root. | Expected when effective uid is 0. |

**Environmental gates**: Running as root widens access checks — cases 4 and beyond report NOTE.

---

### <a id="op_at_variants"></a>op_at_variants

**Tier**: POSIX.1-2008 (`*at()` family with real dirfds)

**Asserts**: `openat`, `mkdirat`, `mknodat`, `fchmodat`, `fchownat`, `renameat`, `unlinkat` operate relative to a directory fd correctly, including when paths traverse NFS directory handles.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `openat: %s` / `mkdirat: %s` / etc. | Operation via dirfd failed. Could be stale dirfd or server doesn't handle the equivalent LOOKUP-via-handle path. | Verify with non-at variant. |
| `fstatat after openat: mode not regular file` | openat created a non-regular-file object; server CREATE op mis-typed. | Real server bug. |
| `fchownat: %s` (not EINVAL-idmap) | ownership update via dirfd failed. | Check idmap behavior (same NOTE path as op_chmod_chown). |

**Environmental gates**: POSIX.1-2008. Linux idmap NOTE applies to fchownat case.

---

### <a id="op_change_attr"></a>op_change_attr

**Tier**: SPEC (NFSv4 change attribute, RFC 7530 §5.8.1.4; Linux statx STATX_CHANGE_COOKIE)

**Asserts**: Every metadata- or data-modifying operation advances the change attribute. Clients (and applications like rsync) rely on this for caching.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `change cookie did not advance across %s` | Operation didn't bump the server's change attribute. Real conformance bug. | Look at server's change-attribute implementation; knfsd vs Ganesha vs vendor. |
| `STATX_CHANGE_COOKIE not defined in this glibc/kernel header set` | Build-time guard; requires Linux 6.5+ headers. SKIPs. | Upgrade kernel headers. |

**Environmental gates**: Linux 6.5+ for STATX_CHANGE_COOKIE. SKIPs otherwise.

---

### <a id="op_deallocate"></a>op_deallocate

**Tier**: SPEC (NFSv4.2 DEALLOCATE, RFC 7862 §10)

**Asserts**: `fallocate(FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE)` punches a hole in an existing file. Size unchanged, `st_blocks` may drop, reads from the hole return zeros.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `punch: %s` | Client or server rejects PUNCH_HOLE. EOPNOTSUPP is common — server backend doesn't support it. | Check server backend type. |
| `size changed across PUNCH_HOLE` | PUNCH_HOLE must not change file size (with KEEP_SIZE). If it did, server misimplemented the op. | Real bug. |
| `st_blocks grew across PUNCH_HOLE` | Hole punch shouldn't add blocks. | Server side — possibly server emulated PUNCH_HOLE with write-of-zeros. |
| `hole region post-punch not zero` | Read after punch returned non-zero bytes. | Real bug. |

**Environmental gates**: Linux only. NFSv4.2 server support required.

---

### <a id="op_directory"></a>op_directory

**Tier**: POSIX.1-2008 (O_DIRECTORY open flag)

**Asserts**: `open()` with `O_DIRECTORY` succeeds on directories and fails ENOTDIR on regular files, via NFS file-type reporting.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `case2: O_DIRECTORY on regular file succeeded` | Server misreported file type or client didn't enforce O_DIRECTORY. | Check LOOKUP reply's file_type; client kernel version. |
| `case4: O_DIRECTORY via symlink-to-file succeeded` | Symlink target file-type check didn't fire. | Client's symlink resolution path. |
| `NOTE: case6 O_CREAT \| O_DIRECTORY accepted` | Behavior is implementation-defined for that combo; informational. | None. |

**Environmental gates**: None.

---

### <a id="op_fd_sharing"></a>op_fd_sharing

**Tier**: POSIX (dup / dup2 / fork / O_CLOEXEC)

**Asserts**: `dup()`/`dup2()`/`F_DUPFD`/`fork()` share the open file description; independent `open()` calls have independent offsets; `O_CLOEXEC` is inherited across fork but not exec; `F_DUPFD_CLOEXEC` sets the flag without modifying source.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `case1: dup'd fd offset = %lld, expected 3 (offset sharing broken)` | dup'd fds don't share file offset. POSIX requires the shared open-file-description semantic. | Client kernel-level bug; not NFS-specific. Re-run locally to confirm. |
| `case4: fd2 offset %lld, expected 0 (independent open should have its own offset)` | Two open() calls returning fds that share offset. Client-side bug. | Same. |
| `case5: parent offset %lld after child write, expected 3 (fork offset sharing broken)` | Fork inheritance broken. | Same. |
| `case6: O_CLOEXEC fd not inherited across fork` | CLOEXEC fired on fork instead of exec. | Kernel bug. |

**Environmental gates**: None. Failures here are almost always local-FS regressions, not NFS.

---

### <a id="op_fdopendir"></a>op_fdopendir

**Tier**: POSIX.1-2008

**Asserts**: `fdopendir(3)` converts a dirfd obtained from `openat` into a DIR* usable by readdir. Essential for `*at()`-style directory walking.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `fdopendir: %s` | Call failed. EBADF suggests the dirfd was closed; EINVAL suggests the fd isn't a directory. | Check state of the fd before calling. |
| `'alpha'/'beta'/'gamma' not found in readdir` | Created entries not visible through the fdopendir DIR*. Cache coherence or readdir-cookie issue. | Compare with `op_readdir` for basic readdir path. |

**Environmental gates**: None.

---

### <a id="op_io_advise"></a>op_io_advise

**Tier**: SPEC (NFSv4.2 IO_ADVISE, RFC 7862 §9)

**Asserts**: `posix_fadvise(2)` succeeds without side effects visible to POSIX syscalls. IO_ADVISE is a hint only; it must not corrupt data or alter observable metadata.

**Failure patterns**: Mostly none — this test is a sanity check that fadvise doesn't blow up. If it emits any FAIL, the client translated the hint into a destructive op.

**Environmental gates**: POSIX fadvise available. Not all backends actually consult the hint; they just accept it.

---

### <a id="op_linkat"></a>op_linkat

**Tier**: POSIX (hard links, LINK op RFC 7530 §18.14)

**Asserts**: `link(2)` and `linkat(2)` create hard links; both paths resolve to same inode; link count increments; modifications via either path are visible through the other.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `link does not share inode` | Created "link" is actually a copy. Server LINK op bug; client may have silently made a copy. | Compare with `stat`; very rare. |
| `st_nlink after link = %lu, expected 2` | Link count wrong after link — server didn't increment or client attrcache stale. | Check server LINK handling. |
| `writing via b did not affect a` | Paths don't share data — same class as the first. | Real bug. |

**Environmental gates**: None. Linkat case 6 is Linux-only.

---

### <a id="op_lookup"></a>op_lookup

**Tier**: SPEC (NFSv4 LOOKUP, RFC 7530 §18.14)

**Asserts**: `stat` on existing names resolves correctly; deep paths work; fstat and stat agree on the inode.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `stat ino %lu != fstat ino %lu` | Path lookup returns a different inode than an fd on the same file. Very serious — path resolution bug. | Client name cache returning stale inode. |
| `stat(%s) succeeded on nonexistent file` | Negative dentry cache returning positive result. | Client dcache bug. |
| `case2: expected ENOENT, got %s` | Wrong errno on missing file. | Client errno mapping. |

**Environmental gates**: None.

---

### <a id="op_lookupp"></a>op_lookupp

**Tier**: SPEC (NFSv4 LOOKUPP, RFC 7530 §18.15)

**Asserts**: `stat("..")` and `openat(dirfd, "..")` resolve to the parent directory. On NFS, LOOKUPP takes a filehandle and returns the parent's handle.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `ino of '..' (%lu) != ino of parent (%lu)` | LOOKUPP returned wrong handle. Server doesn't track directory parents correctly (common in server backends that use hash-based filehandles). | Real server bug. |
| `mkdir chain: %s` | Setup failure creating the directory chain. | Environmental. |

**Environmental gates**: None.

---

### <a id="op_mkdir"></a>op_mkdir

**Tier**: POSIX / SPEC (CREATE(NF4DIR), RFC 7530 §18.4)

**Asserts**: `mkdir(2)` and `mkdirat(2)` create directories with correct mode and type.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `created object is not a directory` | Server CREATE returned a non-dir object for NF4DIR. Very rare. | Real server bug. |
| `chmod mode %o != expected` | Created directory mode didn't reflect `mkdir(mode)` or a following chmod. | Check umask; check SETATTR path. |

**Environmental gates**: None.

---

### <a id="op_rmdir"></a>op_rmdir

**Tier**: POSIX (REMOVE on dir, RFC 7530 §18.25)

**Asserts**: `rmdir(2)` and `unlinkat(AT_REMOVEDIR)` remove empty directories; fail ENOTEMPTY on non-empty.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `%s still accessible after rmdir` | Client's negative-dentry cache isn't updated after rmdir. | Client dcache invalidation bug. |
| `rmdir on non-empty dir unexpectedly succeeded` | Server or client dropped the non-empty check. | Real bug. |

**Environmental gates**: None.

---

### <a id="op_mknod_fifo"></a>op_mknod_fifo

**Tier**: SPEC (CREATE(NF4FIFO), RFC 7530 §18.4)

**Asserts**: `mkfifo(3)` creates a FIFO (named pipe); lstat returns `S_IFIFO`.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `lstat mode 0%o is not S_IFIFO` | Server stored the FIFO as wrong type. | Real server bug. |
| `mkfifo: EOPNOTSUPP` | Some NFS server backends refuse FIFO creation. | Server backend limitation. |

**Environmental gates**: None.

---

### <a id="op_open_downgrade"></a>op_open_downgrade

**Tier**: SPEC (NFSv4 OPEN_DOWNGRADE, RFC 7530 §18.18)

**Asserts**: When the process holds multiple OPENs with overlapping share-access bits and closes one, the server's share-access state tracks the downgrade correctly.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `data mismatch at byte %zu via dup'd fd` | State degraded incorrectly across dup/close sequence. | Client's OPEN_DOWNGRADE generation logic. |
| `write via dup'd fd: %s` | After downgrade, a still-valid fd can no longer write. | Server OPEN_DOWNGRADE tracking bug. |

**Environmental gates**: None.

---

### <a id="op_open_excl"></a>op_open_excl

**Tier**: POSIX / SPEC (OPEN createmode=EXCLUSIVE4_1, RFC 7530 §18.16)

**Asserts**: `open(O_CREAT | O_EXCL)` on a nonexistent file succeeds; on an existing file fails EEXIST.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `O_CREAT \| O_EXCL on existing file succeeded` | Server dropped the EXCL check. Classic NFS race bug. | Real server bug. |
| `expected EEXIST, got %s` | Wrong errno. | Errno mapping. |

**Environmental gates**: None.

---

### <a id="op_owner_override"></a>op_owner_override

**Tier**: POSIX + Linux-specific (file owner ACL overrides)

**Asserts**: On Linux, the file owner can chmod/unlink/rename a 0444 file they own — a common `git gc` path. POSIX-strict says EACCES; Linux says OK. Test has `-P` (POSIX-strict) and `-L` (Linux-permissive) modes.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `[POSIX] case1: owner chmod 0444->0644: %s` | Owner couldn't chmod their own file. Most servers permit this. | Check server's ACL model. |
| `[LINUX] case... succeeded, but POSIX compliance mode (-P) expects failure` | Running in -P mode against a Linux-behavior server. | Expected; switch to -L mode for Linux NFS. |

**Environmental gates**: None. Mode flag: `-P` strict / `-L` Linux (default).

---

### <a id="op_readdir"></a>op_readdir

**Tier**: POSIX / SPEC (READDIR, RFC 7530 §18.23)

**Asserts**: Basic readdir round-trip — created entries appear, once each.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `entry '%s' seen twice` | Server readdir reply has duplicate entries or client readdir-cookie cache replayed. | Server or client readdir bug. |
| `entry '%s' missing from readdir` | Entry created but not in reply. | Check server; check read-dir-plus variants. |

**Environmental gates**: None.

---

### <a id="op_rename_self"></a>op_rename_self

**Tier**: POSIX.1-2024 (rename same-inode no-op)

**Asserts**: `rename(a, b)` where `a` and `b` are hard links to the same file (or `a == b`) is a successful no-op per POSIX.1-2024; older POSIX allowed either success or removing `a`.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `rename(a, a) failed: %s` | rename-self returned an error. | Server doesn't honor POSIX.1-2024 no-op semantic. |
| `file vanished after rename(a, a)` | Server removed the file on rename-self. Pre-POSIX.1-2024 behavior. | Recorded as FAIL; some servers still behave this way. |
| `inode changed after rename(a, a)` | Server recreated the inode. Very unusual. | Real bug. |

**Environmental gates**: None.

---

### <a id="op_setattr"></a>op_setattr

**Tier**: POSIX / SPEC (SETATTR umbrella, RFC 7530 §18.30)

**Asserts**: chmod / chown / truncate / utimensat round-trip. Overlaps with op_chmod_chown, op_truncate_grow, op_utimensat but exercises SETATTR as one combined op.

**Failure patterns**: See per-op specifics in the dedicated tests.

**Environmental gates**: None.

---

### <a id="op_statx_btime"></a>op_statx_btime

**Tier**: SPEC (NFSv4.2 time_create, RFC 7862 §12.2)

**Asserts**: Birth time (creation time) is present, plausible, stable under utimensat, stable across close/open.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `SKIP: server did not return time_create` | Server doesn't advertise the attribute. Expected on many servers. | Informational. |
| `btime %lld is %lld s from wall %lld (> 60s window)` | Server clock skew or btime recording a different event. | Check NTP. |
| `btime > mtime at creation` | btime set later than mtime — impossible unless server is inconsistent. | Real server bug. |
| `btime shifted under utimensat` | Backdating mtime via utimensat shifted btime too — btime must be immutable. | Real bug. The whole point of btime is immutability. |

**Environmental gates**: Linux 4.11+ (statx) or FreeBSD 10+ (st_birthtimespec). SKIP elsewhere.

---

### <a id="op_symlink"></a>op_symlink

**Tier**: POSIX / SPEC (SYMLINK, READLINK, RFC 7530 §18.22, §18.26)

**Asserts**: Basic symlink + readlink round-trip; lstat vs stat distinction; dangling symlinks; long targets; unlink removes the link not the target.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `readlink returned %zd bytes = '%s'` | Byte count wrong or content differs from what was symlink'd. | Server symlink storage bug. |
| `readlinkat failed on dangling symlink: %s` | Server required target to exist for readlink. Wrong — readlink operates on the link itself. | Real bug. |

**Environmental gates**: None.

---

### <a id="op_tmpfile"></a>op_tmpfile

**Tier**: CLIENT + SPEC (O_TMPFILE, Linux 3.11+ / NFSv4.2 CLAIM_TEMPORARY)

**Asserts**: `open(dir, O_TMPFILE)` creates an unnamed file usable via the fd; unvisible in readdir; becomes permanent via `linkat`.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `NOTE: case1 O_TMPFILE not supported here` | Server doesn't implement NFSv4.2 O_TMPFILE support. SKIP with NOTE. | Informational. |
| `linkat materialize failed` | linkat couldn't promote the O_TMPFILE to a named file. | Check AT_EMPTY_PATH support; fallback /proc path used by the test. |
| `file visible via readdir while still O_TMPFILE` | Server leaked the intermediate name. | Server bug. |

**Environmental gates**: Linux client + server with NFSv4.2 O_TMPFILE support.

---

### <a id="op_utimensat"></a>op_utimensat

**Tier**: POSIX.1-2008 (utimensat with UTIME_NOW, UTIME_OMIT, nsec precision)

**Asserts**: utimensat correctly sets atime/mtime to specified values, honors UTIME_NOW (use current time) and UTIME_OMIT (leave alone), and preserves nanosecond precision where supported.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `mtime nsec = 0 after nsec-level utimensat` | Server truncated to second granularity. | Server-side limitation; inspect the backend. |
| `atime changed when UTIME_OMIT was specified for atime` | Server ignored UTIME_OMIT. | Real bug. |
| `utimensat with UTIME_NOW did not update mtime to current time` | Server ignored UTIME_NOW; stored the raw value. | Real bug. |

**Environmental gates**: None.

---

### <a id="op_xattr"></a>op_xattr

**Tier**: SPEC (NFSv4.2 XATTR extension, RFC 8276)

**Asserts**: `setxattr`/`getxattr`/`listxattr`/`removexattr` on the `user.*` namespace round-trip. Tests GETXATTR, SETXATTR, LISTXATTRS, REMOVEXATTR NFSv4.2 ops.

**Failure patterns**

| Signature | Likely cause | Diagnose |
|---|---|---|
| `setxattr: EOPNOTSUPP` or similar | Server or backend doesn't support user xattrs. | Check server config; some backends require explicit enable. |
| `getxattr returned wrong value` | Data not round-tripping. | Real bug; NFSv4.2 xattr path. |
| `xattr not in listxattr` | setxattr succeeded but listxattr doesn't show it. | Server xattr index inconsistency. |
| `removexattr: %s` | Can't remove a xattr just set. | Server xattr tracking bug. |

**Environmental gates**: Linux `user.*` xattrs + NFSv4.2 server. Non-Linux platforms have different xattr APIs; test SKIPs.

---

## <a id="by-symptom"></a>§ 2 — By Symptom

Searchable lookup when you have a failure substring and don't yet know what fired.

| Substring | Tests | Meaning |
|---|---|---|
| `cross-region contamination` | op_concurrent_writes | Concurrent WRITE RPCs on shared TCP socket interleaved (FreeBSD 39d96e08 class) |
| `ELOOP` | op_symlink_loop, op_symlink_nofollow | Symlink chain too long or client loop-detector mis-triggered |
| `ENAMETOOLONG` | op_path_limits | Path component or full path exceeds limit; client/server disagree |
| `ENOLCK` | op_lock | NFS lock manager not running — skip, not fail |
| `ESTALE` | op_stale_handle, op_rename_open_target | File handle expired server-side while client held it |
| `EINVAL` after posix_fallocate | op_allocate | FreeBSD: client doesn't map to ALLOCATE — skip |
| `stale data`, `stale snapshot` | op_close_to_open, op_readdir_mutation | Client cache returned pre-update state |
| `mtime did not advance` | op_timestamps, op_rename_nlink | Server didn't update mtime on the relevant op |
| `ctime did not advance` | op_timestamps | Same for ctime |
| `nlink %lu -> %lu` | op_rename_nlink | Traditional Unix nlink convention; NOTE only (POSIX.1-2008 doesn't require it) |
| `hole ... nonzero` | op_read_plus_sparse, op_zero_to_hole, op_read_write | Sparse region read returned data bytes |
| `multi-extent stitch lost data` | op_read_plus_sparse | READ_PLUS reply with many alternations had an off-by-one stitching error |
| `lock type=%d still held on [0,100) after closing second fd` | op_lock_posix | POSIX close-releases-all-locks not honored |
| `OFD lock released by closing unrelated fd` | op_lock_posix | OFD owner-per-fd semantics violated |
| `server did not honor FILE_SYNC` | op_sync_dsync | O_SYNC/O_DSYNC write returned before server committed |
| `O_DIRECT write not reflected server-side` | op_direct_io | Client O_DIRECT path didn't force WRITE+COMMIT |
| `pattern A corrupted at byte %zu after pwrite returned -1` | op_direct_io | Rejected O_DIRECT pwrite left torn content on disk (generic/250 shape) |
| `b still present after fsync + reopen` | op_commit | Parent-directory unlink not persisted by fsync on the sibling file (generic/039) |
| `stale content in fallocate-but-never-written range` | op_commit | Server exposed uninitialised disk bytes from an ALLOCATE-extended range (generic/042) |
| `illegal size ... torn write / partial truncate` | op_aio_races | pwrite vs ftruncate race left file in an illegal mixed state (generic/114) |
| `pwrite won but content differs from pattern` | op_aio_races | pwrite vs ftruncate race produced torn content (generic/114) |
| `head [0..X) not zero after write-extend` | op_aio_races | Sparse-hole-after-truncate exposed stale bytes before write offset |
| `non-zero flag accepted` | op_copy | copy_file_range unknown flag not rejected with EINVAL (generic/430) |
| `over-copy ... > src` | op_copy | copy_file_range returned more bytes than source holds (generic/430) |
| `EOF call returned ... (expected 0)` | op_copy | copy_file_range past EOF did not short-circuit to 0 (generic/430) |
| `iovec ... ordering broken` | op_writev | Client writev fragmentation reordered iovec elements |
| `overwrite lost` | op_overwrite | Client write-coalescing or server ordering dropped the overwrite |
| `zero overwrite was dropped; original ... survived` | op_overwrite | Server dedup path mis-handling zero over allocated block |
| `worker N exited 0x##` | op_concurrent_writes | Worker pwrite failed — test harness; not a data finding |
| `client-side idmap cannot resolve uid` | op_chmod_chown, op_verify, op_at_variants, op_timestamps | Linux NFS idmap returned EINVAL on chown; NOTE only |
| `NFS lock manager not running on this client` | op_lock | SKIP; start lockd/nfslockd |
| `SKIP ... mount does not have noac` | op_noac | SKIP; mount with `-o noac` to run |
| `SKIP ... requires root` | op_root_squash | SKIP; run as root |
| `renameat2 ... not supported` | op_rename_atomic | Client ≤6.0 doesn't passthrough renameat2 flags |
| `utimensat backdate failed` | op_timestamps, op_statx_btime | utimensat returned an error; inspect errno |
| `grown region not all zero` | op_truncate_grow | ftruncate-grow returned garbage in the extension |
| `dst was affected by src mutation` | op_clone | CoW broken; clone shares storage with source |
| `hole region in dst not zero-filled` | op_copy | COPY lost sparse layout |
| `readdir did not return %s` | op_unicode_names | UTF-8 name stored but not findable — normalization mismatch |
| `st_ino changed between two stats` | op_verify | Attribute cache inconsistency / inode recycled |
| `utimensat with AT_SYMLINK_NOFOLLOW advanced target mtime` | op_symlink_nofollow | Server ignored nofollow; modified target instead of link (classic NFS bug) |
| `fchownat with AT_SYMLINK_NOFOLLOW changed target ownership` | op_symlink_nofollow | Same class — tar/rsync rely on this |
| `RENAME_NOREPLACE not supported` | op_rename_atomic | Client < Linux 6.1 doesn't passthrough renameat2 flags — SKIP |
| `setuid/setgid not cleared after chown` | op_chmod_chown | POSIX security rule: chown must clear S_ISUID/S_ISGID |
| `SEEK_HOLE at island0 reports premature hole` | op_seek | Server returned a hole offset inside the data extent |
| `allocated region not all zero` | op_allocate | ALLOCATE extended the file but didn't zero-fill the extension |
| `change cookie did not advance` | op_change_attr | Server didn't bump the NFSv4 change attribute on the op |
| `st_blocks grew across PUNCH_HOLE` | op_deallocate | Server emulated punch-hole with zero-writes |
| `link does not share inode` | op_linkat | LINK op stored as copy instead of hard link |
| `ino of '..' (%lu) != ino of parent` | op_lookupp | Server doesn't track parent correctly |
| `entry '%s' seen twice` | op_readdir, op_readdir_many | Duplicate from readdir — cookie replay or reply duplication |
| `btime shifted under utimensat` | op_statx_btime | Server treats btime as mutable — defeats its purpose |
| `file vanished after rename(a, a)` | op_rename_self | Pre-POSIX.1-2024 rename-self semantic |
| `32-bit offset truncation` | op_read_write_large | I/O at offset > 4 GiB returned data from a 32-bit-truncated offset |
| `linkat appears to have followed the symlink` | op_linkat | linkat(AT_SYMLINK_FOLLOW off) still resolved through the symlink — server bug |
| `NFS server followed the symlink on SETATTR` | op_symlink_nofollow | utimensat/fchownat on symlink modified target despite AT_SYMLINK_NOFOLLOW |
| `parent nlink changed from %lu to %lu (regular-file unlink must not change parent nlink)` | op_unlink | Server reports file entries in directory nlink (APFS quirk; fails cleanly on POSIX fs) |
| `case6: byte %zu = 0x%02x (expected 0x00) -- zero overwrite was dropped` | op_overwrite | Server dropped explicit-zero write over already-allocated block — buggy dedup path |

---

## <a id="probes"></a>§ 3 — Probes (second-client helpers)

Per the charter (see README), these are not conformance tests. They exist to induce server-side state that a single syscall-driven client cannot produce on its own. Their failure modes are diagnostic, not conformance findings.

### cb_getattr_probe

Hold a write delegation on a separate client so the main test (op_deleg_attr) can exercise the GETATTR → CB_GETATTR path. Called from op_deleg_attr; not invoked standalone by `make check`.

### cb_recall_probe

Hold a delegation then trigger a conflicting OPEN from a second client, inducing the server to emit CB_RECALL. Used by op_deleg_recall and op_deleg_read.

### server_caps_probe

Directly probes server NFSv4.1 capabilities (EXCHANGE_ID, SECINFO_NO_NAME) via a hand-rolled TCP session on port 2049. Goes BELOW the syscall layer — the only binary in the repo that does. Useful for "what does this server advertise?" during diagnostic work. Not part of `make check`.

Invoke manually: `./server_caps_probe -S <server_ip>`

Output interpretation:

| Output | Meaning |
|---|---|
| `EXCHANGE_ID ... exchange_id` | Server accepted session establishment; capability flags follow. |
| `SECINFO_NO_NAME ... flavors` | Server listed its supported security flavors (sys / krb5 / krb5i / krb5p). |
| Connection refused / timeout | Server unreachable or port blocked. Test the connection with `nc -v <server> 2049`. |

---

## Maintenance contract

- **New test**: the PR must add a subsection here with at least a charter tier, one-line assertion, and table entries for every `complain()` string in the test. A linked entry in § 2 (By Symptom) is encouraged but not required.
- **Changed failure messages**: updating a `complain()` string without updating the matching TRIAGE entry is a bug. Reviewers must flag it.
- **Deleting a test**: the subsection here must be deleted in the same commit.

See [docs/REVIEWER-RULES.md](REVIEWER-RULES.md) for the PR-review rubric that enforces the contract.

---

*Last updated: 2026-04-17 (initial Phase 1 covering top-priority tests).*
