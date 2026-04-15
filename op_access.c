/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_access.c -- exercise NFSv4 ACCESS op (RFC 7530 S18.1) via the
 * POSIX access(2) / faccessat(2) surface.
 *
 * Cases:
 *
 *   1. F_OK on an existing regular file: returns 0.
 *
 *   2. F_OK on a nonexistent name: returns -1/ENOENT.  Verifies
 *      that ACCESS against a missing object is distinguished from
 *      "present but denied."
 *
 *   3. R_OK|W_OK on a 0644 file owned by the current uid: returns 0.
 *
 *   4. W_OK on a 0444 (read-only) file: returns -1/EACCES.  Tests
 *      that the server computes the per-user access bitmask and
 *      reports "not writable" correctly.
 *
 *   5. X_OK on a 0644 regular file: returns -1/EACCES.  The execute
 *      bit is clear so the server must refuse.
 *
 *   6. F_OK via faccessat(AT_FDCWD, ..., AT_EACCESS): identical
 *      answer to plain access() for an uncomplicated case, exercising
 *      the *at variant.
 *
 * Portable: POSIX across Linux / FreeBSD / macOS / Solaris.
 *
 * Diagnostic value over TLS: ACCESS is a read-side op and is expected
 * to succeed under every auth flavor the export accepts.  If op_access
 * fails under xprtsec=tls but passes under sys, the bug is in the
 * ACCESS-over-TLS path.  If op_access passes but REMOVE/RENAME fail
 * (op_rmdir, op_rename_atomic), the bug is specifically in the
 * mutating-op authorization path.
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

static const char *myname = "op_access";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise access/faccessat -> NFSv4 ACCESS (RFC 7530 S18.1)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static int touch_mode(const char *path, mode_t mode)
{
	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, mode);
	if (fd < 0) {
		complain("open(%s, 0%o): %s", path, mode, strerror(errno));
		return -1;
	}
	close(fd);
	/*
	 * open() honours umask; force the mode we actually want via
	 * explicit chmod so cases 4 and 5 see the bits they need.
	 */
	if (chmod(path, mode) != 0) {
		complain("chmod(%s, 0%o): %s", path, mode, strerror(errno));
		unlink(path);
		return -1;
	}
	return 0;
}

static void case_exists(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_ax.e.%ld", (long)getpid());
	unlink(a);

	if (touch_mode(a, 0644) < 0) return;
	if (access(a, F_OK) != 0)
		complain("case1: access(%s, F_OK): %s", a, strerror(errno));
	unlink(a);
}

static void case_missing(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_ax.m.%ld", (long)getpid());
	unlink(a);

	errno = 0;
	if (access(a, F_OK) == 0)
		complain("case2: access() on missing file unexpectedly "
			 "succeeded");
	else if (errno != ENOENT)
		complain("case2: expected ENOENT, got %s", strerror(errno));
}

static void case_rw(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_ax.rw.%ld", (long)getpid());
	unlink(a);

	if (touch_mode(a, 0644) < 0) return;
	if (access(a, R_OK | W_OK) != 0)
		complain("case3: access(R_OK|W_OK) on 0644 file: %s",
			 strerror(errno));
	unlink(a);
}

static void case_readonly_w(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_ax.ro.%ld", (long)getpid());
	unlink(a);

	if (touch_mode(a, 0444) < 0) return;
	/*
	 * Root bypasses DAC on most filesystems.  When running as uid 0
	 * the server is allowed to answer "writable" for a 0444 file.
	 * NOTE rather than FAIL in that case so the test is meaningful
	 * when run as both root and non-root.
	 */
	errno = 0;
	int rc = access(a, W_OK);
	if (rc == 0) {
		if (getuid() != 0) {
			complain("case4: access(W_OK) on 0444 unexpectedly "
				 "succeeded (uid %u)",
				 (unsigned)getuid());
		} else if (!Sflag) {
			printf("NOTE: %s: case4 W_OK on 0444 succeeded "
			       "(running as root; DAC bypass expected)\n",
			       myname);
		}
	} else if (errno != EACCES) {
		complain("case4: expected EACCES, got %s", strerror(errno));
	}
	unlink(a);
}

static void case_nonexec(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_ax.x.%ld", (long)getpid());
	unlink(a);

	if (touch_mode(a, 0644) < 0) return;
	errno = 0;
	int rc = access(a, X_OK);
	if (rc == 0) {
		/*
		 * Same root caveat as case 4: a root uid may be told
		 * "executable" on a 0644 file by a server that
		 * correctly implements the Linux "root can exec any
		 * file with at least one x bit" rule.  But here there
		 * are no x bits set at all, so a well-behaved server
		 * should still refuse even for root.  Complain.
		 */
		complain("case5: access(X_OK) on 0644 (no x bits) "
			 "unexpectedly succeeded");
	} else if (errno != EACCES) {
		complain("case5: expected EACCES, got %s", strerror(errno));
	}
	unlink(a);
}

static void case_faccessat(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_ax.at.%ld", (long)getpid());
	unlink(a);

	if (touch_mode(a, 0644) < 0) return;
	if (faccessat(AT_FDCWD, a, F_OK, 0) != 0)
		complain("case6: faccessat(AT_FDCWD, %s, F_OK): %s",
			 a, strerror(errno));
	unlink(a);
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
		"access/faccessat -> NFSv4 ACCESS (RFC 7530 S18.1)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_exists", case_exists());
	RUN_CASE("case_missing", case_missing());
	RUN_CASE("case_rw", case_rw());
	RUN_CASE("case_readonly_w", case_readonly_w());
	RUN_CASE("case_nonexec", case_nonexec());
	RUN_CASE("case_faccessat", case_faccessat());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
