# SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only
#
# Makefile -- build the NFSv4.2 extension tests.
#
# Plain Make, no autotools.  Each test is a single .c file linked
# against subr.o.
#
# Targets:
#   all      build every op_* binary
#   clean    remove binaries, objects, debug bundles
#   check    build then ./runtests
#   install  copy binaries into $(DESTDIR)$(libexecdir)/nfsv42-tests/
#
# Common variables you may override on the command line:
#   CC, CFLAGS, LDFLAGS, PREFIX, DESTDIR, CHECK_DIR
#
#   CHECK_DIR  directory the test suite runs under; default "." (cwd).
#              Set to an NFS mount path to test over NFS:
#                 make check CHECK_DIR=/mnt/nfsv42

CC        ?= cc
CFLAGS    ?= -O2 -g -Wall -Wextra -Wno-unused-parameter -std=gnu11
LDFLAGS   ?=
PREFIX    ?= /usr/local
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
        op_direct_io op_directory \
        op_deleg_attr op_deleg_recall op_deleg_read op_delegation_write \
        op_server_caps

# Auxiliary probe tools (not run by runtests; used by individual tests).
PROBES = cb_getattr_probe cb_recall_probe

CHECK_DIR ?= .

.PHONY: all clean check install

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

check: all
	./runtests -d $(CHECK_DIR)

# Emit TAP13 aggregate output; pipe to prove or tappy for structured
# reporting.  Sequential (same -d mount) by design.
check-tap: all
	./runtests --tap -d $(CHECK_DIR)

# Parallel runs via prove.  Assumes prove is installed and the caller
# has enough independent -d mounts that tests do not collide on scratch
# files; see runtests header for the single-mount caveat.
# Override JOBS on the command line: `make check-prove JOBS=4`.
JOBS ?= 4
check-prove: all
	NFSV42_TESTS_TAP=1 prove -j $(JOBS) -e '' ./op_*

install: all
	install -d $(DESTDIR)$(libexecdir)/nfsv42-tests
	install -m 755 $(TESTS) $(PROBES) runtests \
	        $(DESTDIR)$(libexecdir)/nfsv42-tests/
