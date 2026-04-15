/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_mkdir.c -- exercise NFSv4 CREATE(NF4DIR) (RFC 7530 S18.4) via
 * mkdir(2) / mkdirat(2).
 *
 * Cases:
 *
 *   1. Basic mkdir succeeds, stat(d).st_mode has S_IFDIR.
 *
 *   2. mkdir with 0755 mode, verify the directory ends up with
 *      exactly those permission bits (subject to umask).  Use
 *      chmod() afterwards to force the mode we want independent of
 *      umask, then verify.
 *
 *   3. mkdir over an existing directory returns -1/EEXIST.
 *
 *   4. mkdir with a missing parent component returns -1/ENOENT.
 *
 *   5. mkdirat(AT_FDCWD, ..., 0755) equivalent round-trip, to
 *      exercise the *at variant.
 *
 * Portable: POSIX across Linux / FreeBSD / macOS / Solaris.
 *
 * Diagnostic value over TLS: CREATE(NF4DIR) is a mutating
 * directory op -- same authorization path as REMOVE and RENAME.
 * If op_mkdir passes under TLS but op_rmdir / op_rename_atomic
 * fail, the bug is narrower than "all mutating dir ops."
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

static const char *myname = "op_mkdir";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise mkdir/mkdirat -> NFSv4 CREATE(NF4DIR) (RFC 7530 S18.4)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static void case_basic(void)
{
	char d[64];
	snprintf(d, sizeof(d), "t_md.b.%ld", (long)getpid());
	rmdir(d);

	if (mkdir(d, 0755) != 0) {
		complain("case1: mkdir(%s): %s", d, strerror(errno));
		return;
	}
	struct stat st;
	if (stat(d, &st) != 0) {
		complain("case1: stat: %s", strerror(errno));
	} else if (!S_ISDIR(st.st_mode)) {
		complain("case1: created object is not a directory "
			 "(mode 0%o)",
			 st.st_mode & S_IFMT);
	}
	rmdir(d);
}

static void case_mode(void)
{
	char d[64];
	snprintf(d, sizeof(d), "t_md.m.%ld", (long)getpid());
	rmdir(d);

	/*
	 * umask() varies by caller.  Rather than assume 022, force the
	 * mode bits we want with an explicit chmod after mkdir, then
	 * verify.  This isolates "server honours SETATTR of mode after
	 * CREATE(NF4DIR)" from "the client's umask was something odd."
	 */
	if (mkdir(d, 0777) != 0) {
		complain("case2: mkdir: %s", strerror(errno));
		return;
	}
	if (chmod(d, 0755) != 0) {
		complain("case2: chmod(0755): %s", strerror(errno));
		rmdir(d);
		return;
	}
	struct stat st;
	if (stat(d, &st) != 0) {
		complain("case2: stat: %s", strerror(errno));
	} else if ((st.st_mode & 0777) != 0755) {
		complain("case2: dir mode & 0777 = 0%o, expected 0755",
			 st.st_mode & 0777);
	}
	rmdir(d);
}

static void case_exists(void)
{
	char d[64];
	snprintf(d, sizeof(d), "t_md.e.%ld", (long)getpid());
	rmdir(d);

	if (mkdir(d, 0755) != 0) {
		complain("case3: mkdir setup: %s", strerror(errno));
		return;
	}
	errno = 0;
	if (mkdir(d, 0755) == 0)
		complain("case3: mkdir on existing dir unexpectedly succeeded");
	else if (errno != EEXIST)
		complain("case3: expected EEXIST, got %s", strerror(errno));

	rmdir(d);
}

static void case_missing_parent(void)
{
	char path[128];
	snprintf(path, sizeof(path),
		 "t_md.nope.%ld/inner", (long)getpid());

	errno = 0;
	if (mkdir(path, 0755) == 0) {
		complain("case4: mkdir under missing parent succeeded");
		rmdir(path);
	} else if (errno != ENOENT) {
		complain("case4: expected ENOENT, got %s", strerror(errno));
	}
}

static void case_mkdirat(void)
{
	char d[64];
	snprintf(d, sizeof(d), "t_md.at.%ld", (long)getpid());
	rmdir(d);

	if (mkdirat(AT_FDCWD, d, 0755) != 0) {
		complain("case5: mkdirat: %s", strerror(errno));
		return;
	}
	struct stat st;
	if (stat(d, &st) != 0 || !S_ISDIR(st.st_mode))
		complain("case5: mkdirat result not a directory");
	rmdir(d);
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
		"mkdir/mkdirat -> NFSv4 CREATE(NF4DIR) (RFC 7530 S18.4)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_basic", case_basic());
	RUN_CASE("case_mode", case_mode());
	RUN_CASE("case_exists", case_exists());
	RUN_CASE("case_missing_parent", case_missing_parent());
	RUN_CASE("case_mkdirat", case_mkdirat());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
