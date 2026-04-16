# SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only
#
# Makefile -- build the nfs-conformance suite.
#
# Plain Make, no autotools.  Each test is a single .c file linked
# against subr.o, compiles to a standalone binary, and emits TAP13
# when NFS_CONFORMANCE_TAP=1 is set in the environment.
#
# Targets:
#   all      build every op_* binary and the cb_* probe tools
#   clean    remove binaries, objects, debug bundles
#   check    build then run every test via `prove` (TAP aggregator)
#   check-j  parallel run via `prove -j $(JOBS)`; see caveat below
#   install  copy binaries into $(DESTDIR)$(libexecdir)/nfs-conformance/
#   xfstests copy xfstests wrappers into $(XFSTESTS_DIR)
#
# Common variables you may override on the command line:
#   CC, CFLAGS, LDFLAGS, PREFIX, DESTDIR, CHECK_DIR, JOBS, XFSTESTS_DIR
#
#   CHECK_DIR     directory the test suite runs under; default "."
#                 (cwd).  Set to an NFS mount to test over NFS:
#                   make check CHECK_DIR=/mnt/nfs
#
#   JOBS          `check-j` parallelism; default 4.  Parallel runs on
#                 the SAME mount are unsafe (tests share scratch-file
#                 prefixes).  Use parallel only across independent
#                 mounts, one process per mount.
#
#   XFSTESTS_DIR  destination xfstests tree for `make xfstests`
#                 (e.g. /usr/src/xfstests-dev).

CC         ?= cc
CFLAGS     ?= -O2 -g -Wall -Wextra -Wno-unused-parameter -std=gnu11
LDFLAGS    ?=
PREFIX     ?= /usr/local
libexecdir ?= $(PREFIX)/libexec

TESTS = op_allocate op_io_advise op_seek op_copy op_deallocate op_clone \
        op_xattr op_statx_btime op_ofd_lock op_lock \
        op_change_attr op_rename_atomic op_symlink op_linkat \
        op_access op_setattr op_mkdir op_rmdir op_lookup op_lookupp \
        op_owner_override op_unlink op_chmod_chown op_utimensat \
        op_rename_nlink \
        op_readdir op_open_excl op_mknod_fifo \
        op_commit op_truncate_grow op_unicode_names op_readdir_many op_append \
        op_read_plus_sparse op_verify op_open_downgrade \
        op_symlink_nofollow op_rename_self op_at_variants \
        op_fdopendir op_read_write_large \
        op_stale_handle op_mmap_msync op_close_to_open \
        op_noac op_root_squash op_rsize_wsize op_soft_timeout \
        op_direct_io op_directory op_sync_dsync op_tmpfile \
        op_deleg_attr op_deleg_recall op_deleg_read op_delegation_write \
        op_server_caps

# Auxiliary probe tools (not invoked by `prove`; used by individual
# tests as helpers and available for manual debugging).
PROBES = cb_getattr_probe cb_recall_probe

CHECK_DIR ?= .
JOBS      ?= 4

.PHONY: all clean check check-j install xfstests

all: $(TESTS) $(PROBES)

subr.o: subr.c tests.h
	$(CC) $(CFLAGS) -c $< -o $@

# Pattern rule: build each op_<name> from op_<name>.c + subr.o
op_%: op_%.c subr.o tests.h
	$(CC) $(CFLAGS) $(LDFLAGS) $< subr.o -o $@

# Probe tools: standalone binaries, no test harness dependency.
cb_getattr_probe: cb_getattr_probe.c rpc_wire.h
	$(CC) $(CFLAGS) $(LDFLAGS) cb_getattr_probe.c -o cb_getattr_probe

cb_recall_probe: cb_recall_probe.c rpc_wire.h
	$(CC) $(CFLAGS) $(LDFLAGS) cb_recall_probe.c -o cb_recall_probe

# op_server_caps uses rpc_wire.h directly (in addition to the standard deps)
op_server_caps: rpc_wire.h

# op_deleg_attr uses pthreads for case 8 (thread-stat-no-callback); override
# the pattern rule so the link line adds -pthread.
op_deleg_attr: op_deleg_attr.c subr.o tests.h
	$(CC) $(CFLAGS) $(LDFLAGS) -pthread $< subr.o -o $@

clean:
	rm -f $(TESTS) $(PROBES) subr.o
	rm -rf *.dSYM

# Run every op_* via `prove` with TAP mode enabled.  Each binary
# emits its own `1..N` plan; prove aggregates, surfacing ok / not ok
# / skip counts.  Tests receive `-d $(CHECK_DIR)` via PROVE_ARGS so
# they drive the chosen mount point.
check: all
	NFS_CONFORMANCE_TAP=1 prove -e '' $(addprefix ./,$(TESTS)) :: -d $(CHECK_DIR)

# Parallel variant.  Safe only across independent -d mounts; on a
# single mount, tests collide on scratch-file prefixes.  Override:
#   make check-j JOBS=8
check-j: all
	NFS_CONFORMANCE_TAP=1 prove -j $(JOBS) -e '' $(addprefix ./,$(TESTS)) :: -d $(CHECK_DIR)

install: all
	install -d $(DESTDIR)$(libexecdir)/nfs-conformance
	install -m 755 $(TESTS) $(PROBES) \
	        $(DESTDIR)$(libexecdir)/nfs-conformance/

# Install xfstests wrappers into an xfstests source tree.
#   make xfstests XFSTESTS_DIR=/usr/src/xfstests-dev
xfstests:
	@test -n "$(XFSTESTS_DIR)" || { echo "error: set XFSTESTS_DIR" >&2; exit 1; }
	./xfstests/install.sh "$(XFSTESTS_DIR)"
