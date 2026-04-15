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
        op_xattr op_statx_btime op_ofd_lock \
        op_change_attr op_rename_atomic op_symlink op_linkat \
        op_access op_setattr op_mkdir op_rmdir \
        op_readdir op_open_excl op_mknod_fifo \
        op_deleg_attr op_deleg_recall op_server_caps

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

clean:
	rm -f $(TESTS) $(PROBES) subr.o
	rm -rf *.dSYM

check: all
	./runtests -d $(CHECK_DIR)

install: all
	install -d $(DESTDIR)$(libexecdir)/nfsv42-tests
	install -m 755 $(TESTS) $(PROBES) runtests \
	        $(DESTDIR)$(libexecdir)/nfsv42-tests/
