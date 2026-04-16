<!--
SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com>
SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only
-->

# nfs-conformance xfstests bridge

Thin shell wrappers that expose every nfs-conformance binary to
[xfstests](https://github.com/kdave/xfstests) (a.k.a. `fstests`), the
de-facto filesystem conformance suite that the Linux filesystem and
NFS communities run every day.

**This file is the quick-start.**  Deep-dive guide with `local.config`
examples, Kerberos / TLS mounts, debugging failures via `.out.bad`,
contributing new wrappers, and the upstream submission plan:
[`../docs/xfstests.md`](../docs/xfstests.md).

Each nfs-conformance binary becomes one xfstests test under the `nfs` group.
xfstests' standard machinery (`./check -nfs`, per-test `.out` golden
comparison, `_notrun` for environmental skips, `auto`/`quick`/`stress`
group tags) drives everything.

## Structure

```
xfstests-bridge/
  README.md             ← this file
  install.sh            ← helper that copies wrappers into an xfstests tree
  common/
    nfs-conformance             ← shared helpers sourced by every wrapper
  tests/
    nfs/
      900               ← wrapper for nfs-conformance/op_access
      900.out           ← golden output
      901 / 901.out     ← op_allocate
      ...
```

Tests are numbered starting at 900.  xfstests reserves 000-599 for
upstream and leaves the 900-range for downstream / out-of-tree tests.

## Prerequisites

- A working `xfstests` checkout: `git clone https://github.com/kdave/xfstests`
- A built nfs-conformance: `cd nfs-conformance && make`
- An NFSv4.2 mount you can write to
- `local.config` in your xfstests tree with `TEST_DEV`, `TEST_DIR`,
  `FSTYP=nfs` pointing at the NFSv4.2 mount

## Installation

Two options:

**Copy (simplest, read-only install):**

```
./xfstests-bridge/install.sh /path/to/xfstests
```

Copies `common/nfs-conformance` and `tests/nfs/*` into the xfstests tree.
Safe and idempotent; re-run after `git pull` on nfs-conformance.

**Symlink (for nfs-conformance developers):**

```
./xfstests-bridge/install.sh --symlink /path/to/xfstests
```

Creates symlinks from xfstests' tree into `nfs-conformance/xfstests-bridge/`
so nfs-conformance edits take effect without re-copying.

Either way, set `NFS_CONFORMANCE_BIN` in your environment (or in
`xfstests/local.config`) to the directory containing the built
`op_*` binaries:

```
export NFS_CONFORMANCE_BIN=/path/to/nfs-conformance
```

After installing (or adding new wrappers later), rebuild xfstests so
it regenerates `tests/nfs/group.list`:

```
cd /path/to/xfstests && make
```

`install.sh` auto-registers the `nfs-conformance` group in
`doc/group-names.txt` so that rebuild succeeds; without it xfstests
refuses to build a `group.list` that references undocumented groups.

## Running

```
cd /path/to/xfstests

# Canonical: only nfs-conformance wrappers, nothing else
./check -nfs -g nfs-conformance

# Fast subset: nfs-conformance tests that complete in under a second
./check -nfs -g nfs-conformance,quick

# Single wrapper by number
./check -nfs nfs/904           # op_commit

# Every NFS test in tests/nfs/, including all upstream xfstests
# tests AND nfs-conformance wrappers.  Expect several minutes of wall time.
./check -nfs -g nfs
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

Every wrapper runs exactly one nfs-conformance binary with `-d "$TEST_DIR" -s`,
interprets the exit code, and produces xfstests-standard output:

| exit | nfs-conformance meaning | xfstests behaviour |
|------|-----------------|---------------------|
| 0    | PASS            | print `Silence is golden.` — matches `.out` → pass |
| 77   | SKIP            | call `_notrun` with the SKIP reason → skip |
| other | FAIL / BUG     | echo captured output; golden-diff fails → fail |

## Group tags

Every nfs-conformance wrapper is tagged `auto nfs nfs-conformance`, plus `quick`
when the test reliably completes in under a second.  Four ways to
select them:

- **`-g nfs-conformance`** — only nfs-conformance wrappers.  Canonical invocation.
- **`-g nfs-conformance,quick`** — fast subset (quick wrappers only).
- **`-g nfs`** — nfs-conformance wrappers AND every upstream xfstests NFS
  test.  Expect dozens of tests and several minutes of wall time.
- **`-g auto`** — the default xfstests "reasonable workload" group;
  includes nfs-conformance plus upstream auto-tagged tests across every
  filesystem.  Combine with `-nfs` to limit to NFS.

Tests that may take several seconds (e.g. `op_readdir_many` creates
1024 files, `op_allocate` writes 4 MiB) omit `quick` but keep
`nfs-conformance`, so `-g nfs-conformance` still selects them.

## Contributing

The wrappers are nearly boilerplate; most logic lives in
`common/nfs-conformance`.  To add a new wrapper for a new nfs-conformance binary:

1. Pick the next free test number in `tests/nfs/`.
2. Copy an existing wrapper (e.g. `900`) and `900.out` as a template.
3. Update the SPDX header, the "FS QA Test No.", the short
   description, and the `_require_nfs_conformance_binary` / `_nfs_conformance_run`
   calls.
4. If the test needs special flags, use `_nfs_conformance_run_args` instead
   of the default `_nfs_conformance_run`.
5. Run `install.sh` to sync, then `./check nfs/NNN` to verify.

## Submitting upstream

Once the wrappers have shaken out, the intent is to propose the NFS
additions directly to xfstests' `tests/nfs/` tree.  Until that
lands, installing via `install.sh` into your own xfstests clone is
the supported path.  The wrappers are under the same
`BSD-2-Clause OR GPL-2.0-only` dual license as the rest of nfs-conformance.
