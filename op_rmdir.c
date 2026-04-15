/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_rmdir.c -- exercise NFSv4 REMOVE on a directory (RFC 7530
 * S18.25) via rmdir(2) / unlinkat(AT_REMOVEDIR).
 *
 * Cases:
 *
 *   1. Basic rmdir of an empty directory succeeds; the name is
 *      gone afterwards.
 *
 *   2. rmdir of a non-empty directory returns -1/ENOTEMPTY.  A few
 *      stacks historically returned EEXIST here; POSIX mandates
 *      ENOTEMPTY (or EEXIST per an older spec revision).  Accept
 *      either with a NOTE but prefer ENOTEMPTY.
 *
 *   3. rmdir of a nonexistent name returns -1/ENOENT.
 *
 *   4. rmdir on a regular file returns -1/ENOTDIR.  Distinguishes
 *      REMOVE-for-dir from REMOVE-for-file in the server.
 *
 *   5. unlinkat(AT_FDCWD, d, AT_REMOVEDIR) -- same op, *at variant.
 *
 * Portable: POSIX across Linux / FreeBSD / macOS / Solaris.
 *
 * Diagnostic value over TLS: rmdir is REMOVE on a directory target.
 * Along with op_rename_atomic, op_linkat case3, and op_symlink case6,
 * these are the ops observed to fail with EPERM under xprtsec=tls on
 * at least one server while passing under AUTH_SYS.  op_rmdir is the
 * cleanest of the set because it doesn't need any setup
 * (no create+link+unlink race), so a server-side trace will show
 * exactly one REMOVE compound in the failing run.
 */

#define _POSIX_C_SOURCE 200809L

#include "tests.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

int Hflag = 0;
int Sflag = 0;
int Tflag = 0;
int Fflag = 0;
int Nflag = 0;

static const char *myname = "op_rmdir";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise rmdir/unlinkat -> NFSv4 REMOVE on dir "
		"(RFC 7530 S18.25)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static void case_basic(void)
{
	char d[64];
	snprintf(d, sizeof(d), "t_rd.b.%ld", (long)getpid());
	rmdir(d);

	if (mkdir(d, 0755) != 0) {
		complain("case1: mkdir setup: %s", strerror(errno));
		return;
	}
	if (rmdir(d) != 0) {
		complain("case1: rmdir(%s): %s", d, strerror(errno));
		return;
	}
	if (access(d, F_OK) == 0)
		complain("case1: %s still accessible after rmdir", d);
}

static void case_non_empty(void)
{
	char d[64], child[128];
	snprintf(d, sizeof(d), "t_rd.ne.%ld", (long)getpid());
	snprintf(child, sizeof(child), "%s/f", d);
	rmdir(d);

	if (mkdir(d, 0755) != 0) {
		complain("case2: mkdir: %s", strerror(errno));
		return;
	}
	int fd = open(child, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case2: open child: %s", strerror(errno));
		rmdir(d);
		return;
	}
	close(fd);

	errno = 0;
	int rc = rmdir(d);
	if (rc == 0) {
		complain("case2: rmdir on non-empty dir unexpectedly "
			 "succeeded");
	} else if (errno == ENOTEMPTY) {
		/* expected */
	} else if (errno == EEXIST) {
		/* POSIX historically allowed EEXIST; NOTE it. */
		if (!Sflag)
			printf("NOTE: %s: case2 rmdir non-empty returned "
			       "EEXIST (POSIX-legacy); ENOTEMPTY preferred\n",
			       myname);
	} else {
		complain("case2: expected ENOTEMPTY, got %s",
			 strerror(errno));
	}

	unlink(child);
	rmdir(d);
}

static void case_missing(void)
{
	char d[64];
	snprintf(d, sizeof(d), "t_rd.m.%ld", (long)getpid());
	rmdir(d);

	errno = 0;
	if (rmdir(d) == 0)
		complain("case3: rmdir on missing name unexpectedly "
			 "succeeded");
	else if (errno != ENOENT)
		complain("case3: expected ENOENT, got %s", strerror(errno));
}

static void case_regular_file(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_rd.f.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case4: open: %s", strerror(errno));
		return;
	}
	close(fd);

	errno = 0;
	int rc = rmdir(f);
	if (rc == 0)
		complain("case4: rmdir on regular file unexpectedly "
			 "succeeded");
	else if (errno != ENOTDIR)
		complain("case4: expected ENOTDIR, got %s", strerror(errno));

	unlink(f);
}

static void case_unlinkat(void)
{
	char d[64];
	snprintf(d, sizeof(d), "t_rd.at.%ld", (long)getpid());
	rmdir(d);

	if (mkdir(d, 0755) != 0) {
		complain("case5: mkdir: %s", strerror(errno));
		return;
	}
	if (unlinkat(AT_FDCWD, d, AT_REMOVEDIR) != 0) {
		complain("case5: unlinkat(AT_REMOVEDIR, %s): %s",
			 d, strerror(errno));
		rmdir(d);
		return;
	}
	if (access(d, F_OK) == 0) {
		complain("case5: %s still accessible after unlinkat", d);
		rmdir(d);
	}
}

int main(int argc, char **argv)
{
	const char *dir = ".";
	struct timespec t0, t1;

	while (--argc > 0 && argv[1][0] == '-') {
		argv++;
		for (const char *p = &argv[0][1]; *p; p++) {
			switch (*p) {
			case 'h': Hflag = 1; break;
			case 's': Sflag = 1; break;
			case 't': Tflag = 1; break;
			case 'f': Fflag = 1; break;
			case 'n': Nflag = 1; break;
			case 'd':
				if (argc < 2) { usage(); return TEST_FAIL; }
				dir = argv[1];
				argv++;
				argc--;
				goto next;
			default: usage(); return TEST_FAIL;
			}
		}
next:
		;
	}
	if (Hflag) { usage(); return TEST_PASS; }

	prelude(myname,
		"rmdir/unlinkat -> NFSv4 REMOVE on dir (RFC 7530 S18.25)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_basic", case_basic());
	RUN_CASE("case_non_empty", case_non_empty());
	RUN_CASE("case_missing", case_missing());
	RUN_CASE("case_regular_file", case_regular_file());
	RUN_CASE("case_unlinkat", case_unlinkat());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
