<!--
SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com>
SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only
-->

# cthon26 xfstests bridge

Thin shell wrappers that expose every cthon26/nfsv42-tests binary to
[xfstests](https://github.com/kdave/xfstests) (a.k.a. `fstests`), the
de-facto filesystem conformance suite that the Linux filesystem and
NFS communities run every day.

**This file is the quick-start.**  Deep-dive guide with `local.config`
examples, Kerberos / TLS mounts, debugging failures via `.out.bad`,
contributing new wrappers, and the upstream submission plan:
[`../docs/xfstests.md`](../docs/xfstests.md).

Each cthon26 binary becomes one xfstests test under the `nfs` group.
xfstests' standard machinery (`./check -nfs`, per-test `.out` golden
comparison, `_notrun` for environmental skips, `auto`/`quick`/`stress`
group tags) drives everything.

## Structure

```
xfstests-bridge/
  README.md             ← this file
  install.sh            ← helper that copies wrappers into an xfstests tree
  common/
    cthon26             ← shared helpers sourced by every wrapper
  tests/
    nfs/
      900               ← wrapper for nfsv42-tests/op_access
      900.out           ← golden output
      901 / 901.out     ← op_allocate
      ...
```

Tests are numbered starting at 900.  xfstests reserves 000-599 for
upstream and leaves the 900-range for downstream / out-of-tree tests.

## Prerequisites

- A working `xfstests` checkout: `git clone https://github.com/kdave/xfstests`
- A built cthon26/nfsv42-tests: `cd cthon26/nfsv42-tests && make`
- An NFSv4.2 mount you can write to
- `local.config` in your xfstests tree with `TEST_DEV`, `TEST_DIR`,
  `FSTYP=nfs` pointing at the NFSv4.2 mount

## Installation

Two options:

**Copy (simplest, read-only install):**

```
./xfstests-bridge/install.sh /path/to/xfstests
```

Copies `common/cthon26` and `tests/nfs/*` into the xfstests tree.
Safe and idempotent; re-run after `git pull` on cthon26.

**Symlink (for cthon26 developers):**

```
./xfstests-bridge/install.sh --symlink /path/to/xfstests
```

Creates symlinks from xfstests' tree into `cthon26/xfstests-bridge/`
so cthon26 edits take effect without re-copying.

Either way, set `CTHON26_BIN` in your environment (or in
`xfstests/local.config`) to the directory containing the built
`op_*` binaries:

```
export CTHON26_BIN=/path/to/cthon26/nfsv42-tests
```

## Running

```
cd /path/to/xfstests
./check -nfs nfs/900           # just op_access
./check -nfs -g nfs            # every cthon26 wrapper in the nfs group
./check -nfs -g auto           # auto group (excludes long/stress tests)
./check -nfs -g nfs,quick      # fast subset
```

xfstests' standard output follows:

```
FSTYP         -- nfs
PLATFORM      -- Linux/x86_64 hs-124 6.8.0-fc39
MKFS_OPTIONS  -- ...
MOUNT_OPTIONS -- -o vers=4.2,sec=sys

nfs/900 2s ...
nfs/901 3s ...
...
Ran: nfs/900 nfs/901 nfs/902
Passed all 3 tests
```

## What each wrapper does

Every wrapper runs exactly one cthon26 binary with `-d "$TEST_DIR" -s`,
interprets the exit code, and produces xfstests-standard output:

| exit | cthon26 meaning | xfstests behaviour |
|------|-----------------|---------------------|
| 0    | PASS            | print `Silence is golden.` — matches `.out` → pass |
| 77   | SKIP            | call `_notrun` with the SKIP reason → skip |
| other | FAIL / BUG     | echo captured output; golden-diff fails → fail |

## Group tags

All cthon26 wrappers are tagged `auto nfs`, which means they're
included by default in `./check -g auto` and `./check -g nfs`.

Tests that may take several seconds (e.g. `op_readdir_many` creates
1024 files, `op_allocate` writes 4 MiB) are NOT tagged `quick`.
Tests that complete in well under a second are tagged `auto nfs
quick` so `./check -g quick` stays fast.

## Contributing

The wrappers are nearly boilerplate; most logic lives in
`common/cthon26`.  To add a new wrapper for a new cthon26 binary:

1. Pick the next free test number in `tests/nfs/`.
2. Copy an existing wrapper (e.g. `900`) and `900.out` as a template.
3. Update the SPDX header, the "FS QA Test No.", the short
   description, and the `_require_cthon26_binary` / `_cthon26_run`
   calls.
4. If the test needs special flags, use `_cthon26_run_args` instead
   of the default `_cthon26_run`.
5. Run `install.sh` to sync, then `./check nfs/NNN` to verify.

## Submitting upstream

Once the wrappers have shaken out, the intent is to propose the NFS
additions directly to xfstests' `tests/nfs/` tree.  Until that
lands, installing via `install.sh` into your own xfstests clone is
the supported path.  The wrappers are under the same
`BSD-2-Clause OR GPL-2.0-only` dual license as the rest of cthon26.
