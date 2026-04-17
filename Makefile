# SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only
#
# Makefile -- build the nfs-conformance suite.
#
# Written to be portable between GNU make and BSD make (bmake).  No
# pattern-rule syntax (%), no GNU-only functions (addprefix, patsubst).
# Uses a single-suffix `.c:' rule that both implementations honour.
#
# Each test is a single .c file linked against subr.o, compiles to a
# standalone binary, and emits TAP13 when NFS_CONFORMANCE_TAP=1 is set
# in the environment.
#
# Targets:
#   all      build every op_* binary and the cb_* probe tools
#   clean    remove binaries, objects, debug bundles
#   check    build then run every test via `prove` (TAP aggregator)
#   check-j  parallel run via `prove -j $(JOBS)`; see caveat below
#   install  copy binaries into $(DESTDIR)$(libexecdir)/nfs-conformance/
#   xfstests copy xfstests wrappers into $(XFSTESTS_DIR)
#
# Variables you may override on the command line:
#   CC, CFLAGS, LDFLAGS, PREFIX, DESTDIR, CHECK_DIR, JOBS, XFSTESTS_DIR
#
#   CHECK_DIR     directory the test suite runs under; default "."
#   JOBS          `check-j` parallelism; default 4.  Safe only across
#                 INDEPENDENT -d mounts (tests share scratch-file
#                 prefixes on a single mount).
#   XFSTESTS_DIR  destination xfstests tree for `make xfstests`

CC         ?= cc
# Append our warnings/flags so users can still set CFLAGS externally;
# BSD make's default CFLAGS ("-O2 -pipe") is preserved, GNU make's
# default (empty) gets a sensible set.
CFLAGS     += -g -Wall -Wextra -Wno-unused-parameter -std=gnu11
LDFLAGS    +=
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
        op_readdir_mutation op_rename_open_target op_lock_posix \
        op_timestamps op_fd_sharing \
        op_deleg_attr op_deleg_recall op_deleg_read op_delegation_write \
        op_server_caps

# Auxiliary probe tools (not invoked by `prove`; helpers for a few
# tests and available for manual debugging).
PROBES = cb_getattr_probe cb_recall_probe

CHECK_DIR ?= .
JOBS      ?= 4

.PHONY: all clean check check-j install xfstests

.SUFFIXES:
.SUFFIXES: .c .o

all: $(TESTS) $(PROBES)

subr.o: subr.c tests.h
	$(CC) $(CFLAGS) -c subr.c -o subr.o

# Single-suffix rule: build `foo' from `foo.c', linking subr.o.
# Honoured by both GNU make and BSD make.  Applies to every op_*
# target; probes and op_deleg_attr have explicit rules below that
# override it.  Using $*.c rather than $< because BSD make's $<
# in a single-suffix rule points to a transformation intermediate,
# not the .c source.
.c:
	$(CC) $(CFLAGS) $(LDFLAGS) $*.c subr.o -o $@

# Every test has subr.o as an extra prerequisite (the .c: recipe
# links it in).  The prerequisite declaration itself is rule-less;
# the recipe is supplied by .c: above.  Both GNU make and BSD make
# combine the prerequisites correctly.
$(TESTS): subr.o tests.h

# Probe tools: standalone binaries, no subr.o dependency.
cb_getattr_probe: cb_getattr_probe.c rpc_wire.h
	$(CC) $(CFLAGS) $(LDFLAGS) cb_getattr_probe.c -o cb_getattr_probe

cb_recall_probe: cb_recall_probe.c rpc_wire.h
	$(CC) $(CFLAGS) $(LDFLAGS) cb_recall_probe.c -o cb_recall_probe

# op_deleg_attr uses pthreads for case 8 (thread-stat-no-callback).
op_deleg_attr: op_deleg_attr.c subr.o tests.h
	$(CC) $(CFLAGS) $(LDFLAGS) -pthread op_deleg_attr.c subr.o -o op_deleg_attr

# op_server_caps pulls in rpc_wire.h directly.
op_server_caps: op_server_caps.c subr.o tests.h rpc_wire.h
	$(CC) $(CFLAGS) $(LDFLAGS) op_server_caps.c subr.o -o op_server_caps

clean:
	rm -f $(TESTS) $(PROBES) subr.o
	rm -rf *.dSYM

# Run every op_* via `prove` with TAP mode enabled.  Tests get
# `-d $(CHECK_DIR)` via prove's `::' argument passthrough.  Shell
# printf prefixes `./' to each element of $(TESTS) so prove executes
# the local binary rather than a PATH lookup.
check: all
	NFS_CONFORMANCE_TAP=1 prove -e '' `printf './%s ' $(TESTS)` :: -d $(CHECK_DIR)

# Parallel variant.  Safe only across independent -d mounts.
check-j: all
	NFS_CONFORMANCE_TAP=1 prove -j $(JOBS) -e '' `printf './%s ' $(TESTS)` :: -d $(CHECK_DIR)

install: all
	install -d $(DESTDIR)$(libexecdir)/nfs-conformance
	install -m 755 $(TESTS) $(PROBES) \
	        $(DESTDIR)$(libexecdir)/nfs-conformance/

# Install xfstests wrappers into an xfstests source tree.
#   make xfstests XFSTESTS_DIR=/usr/src/xfstests-dev
xfstests:
	@test -n "$(XFSTESTS_DIR)" || { echo "error: set XFSTESTS_DIR" >&2; exit 1; }
	./xfstests/install.sh "$(XFSTESTS_DIR)"
