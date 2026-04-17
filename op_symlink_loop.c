/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_symlink_loop.c -- exercise ELOOP / symbolic-link-chain depth.
 *
 * POSIX.1-2008 requires the implementation to detect excessively
 * long symlink chains during pathname resolution and return ELOOP.
 * The exact depth threshold is implementation-defined (SYMLOOP_MAX,
 * typically 8-40).  NFSv4 servers may perform loop detection either
 * at the client or on the server via LOOKUP step limits; bugs in
 * either side show up as "path traversal hangs" or "server returns
 * wrong errno."
 *
 * Cases:
 *
 *   1. Two-link cycle: A -> B, B -> A.  Any path resolution through
 *      A or B must fail with ELOOP.
 *
 *   2. Three-link cycle: A -> B, B -> C, C -> A.  Same expectation.
 *
 *   3. Long non-cyclic chain: link_0 -> link_1 -> ... -> link_40
 *      with link_40 missing.  Resolution through link_0 should fail
 *      with ELOOP (exceeds SYMLOOP_MAX) on most platforms; ENOENT
 *      is an acceptable alternative on platforms that walk all the
 *      way to the dangling tail.
 *
 *   4. Self-loop: A -> A.  Should fail with ELOOP.
 *
 * Portable: POSIX across Linux / FreeBSD / macOS.
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

static const char *myname = "op_symlink_loop";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise ELOOP / symlink chain depth\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static void case_two_cycle(void)
{
	char a[64], b[64];
	snprintf(a, sizeof(a), "t_sll.2a.%ld", (long)getpid());
	snprintf(b, sizeof(b), "t_sll.2b.%ld", (long)getpid());
	unlink(a); unlink(b);

	if (symlink(b, a) != 0 || symlink(a, b) != 0) {
		complain("case1: symlink: %s", strerror(errno));
		unlink(a); unlink(b);
		return;
	}

	errno = 0;
	int fd = open(a, O_RDONLY);
	if (fd >= 0) {
		complain("case1: open(A in A<->B cycle) succeeded "
			 "(expected ELOOP)");
		close(fd);
	} else if (errno != ELOOP) {
		complain("case1: got %s; expected ELOOP", strerror(errno));
	}

	unlink(a); unlink(b);
}

static void case_three_cycle(void)
{
	char a[64], b[64], c[64];
	snprintf(a, sizeof(a), "t_sll.3a.%ld", (long)getpid());
	snprintf(b, sizeof(b), "t_sll.3b.%ld", (long)getpid());
	snprintf(c, sizeof(c), "t_sll.3c.%ld", (long)getpid());
	unlink(a); unlink(b); unlink(c);

	if (symlink(b, a) != 0 || symlink(c, b) != 0 ||
	    symlink(a, c) != 0) {
		complain("case2: symlink: %s", strerror(errno));
		unlink(a); unlink(b); unlink(c);
		return;
	}

	errno = 0;
	int fd = open(a, O_RDONLY);
	if (fd >= 0) {
		complain("case2: open(A in A->B->C->A cycle) succeeded");
		close(fd);
	} else if (errno != ELOOP) {
		complain("case2: got %s; expected ELOOP", strerror(errno));
	}

	unlink(a); unlink(b); unlink(c);
}

static void case_long_chain(void)
{
	/* Create links link_0 -> link_1 -> ... -> link_40.
	 * link_40 does not exist -> resolution exceeds SYMLOOP_MAX on
	 * the way there, returning ELOOP, or completes and returns
	 * ENOENT on platforms that count all 40 as within budget. */
	const int N = 40;
	char name[64], next[64];
	long pid = (long)getpid();

	/* Clean up from prior aborted run. */
	for (int i = 0; i <= N; i++) {
		snprintf(name, sizeof(name), "t_sll.c%02d.%ld", i, pid);
		unlink(name);
	}

	for (int i = 0; i < N; i++) {
		snprintf(name, sizeof(name), "t_sll.c%02d.%ld", i, pid);
		snprintf(next, sizeof(next), "t_sll.c%02d.%ld", i + 1, pid);
		if (symlink(next, name) != 0) {
			complain("case3: symlink chain at %d: %s",
				 i, strerror(errno));
			goto cleanup;
		}
	}

	errno = 0;
	snprintf(name, sizeof(name), "t_sll.c00.%ld", pid);
	int fd = open(name, O_RDONLY);
	if (fd >= 0) {
		complain("case3: open(long chain head) succeeded");
		close(fd);
	} else if (errno != ELOOP && errno != ENOENT) {
		complain("case3: got %s; expected ELOOP or ENOENT",
			 strerror(errno));
	}

cleanup:
	for (int i = 0; i <= N; i++) {
		snprintf(name, sizeof(name), "t_sll.c%02d.%ld", i, pid);
		unlink(name);
	}
}

static void case_self_loop(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_sll.s.%ld", (long)getpid());
	unlink(a);

	if (symlink(a, a) != 0) {
		complain("case4: symlink: %s", strerror(errno));
		unlink(a);
		return;
	}

	errno = 0;
	int fd = open(a, O_RDONLY);
	if (fd >= 0) {
		complain("case4: open(self-loop) succeeded");
		close(fd);
	} else if (errno != ELOOP) {
		complain("case4: got %s; expected ELOOP", strerror(errno));
	}

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

	prelude(myname, "ELOOP: symlink chains and cycles");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_two_cycle", case_two_cycle());
	RUN_CASE("case_three_cycle", case_three_cycle());
	RUN_CASE("case_long_chain", case_long_chain());
	RUN_CASE("case_self_loop", case_self_loop());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
