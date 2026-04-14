# SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com>
# SPDX-License-Identifier: Apache-2.0
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
        op_change_attr op_rename_atomic op_symlink op_linkat

CHECK_DIR ?= .

.PHONY: all clean check install

all: $(TESTS)

subr.o: subr.c tests.h
	$(CC) $(CFLAGS) -c $< -o $@

# Pattern rule: build each op_<name> from op_<name>.c + subr.o
op_%: op_%.c subr.o tests.h
	$(CC) $(CFLAGS) $(LDFLAGS) $< subr.o -o $@

clean:
	rm -f $(TESTS) subr.o
	rm -rf *.dSYM

check: all
	./runtests -d $(CHECK_DIR)

install: all
	install -d $(DESTDIR)$(libexecdir)/nfsv42-tests
	install -m 755 $(TESTS) runtests \
	        $(DESTDIR)$(libexecdir)/nfsv42-tests/
