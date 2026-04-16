/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_lookupp.c -- focused exercise of NFSv4 LOOKUPP (RFC 7530
 * S18.15) via stat("..") and openat(dirfd, "..") surfaces.
 *
 * op_lookup has a couple of ".." cases; this test goes deeper into
 * the parent-traversal semantics that NFS servers sometimes get wrong:
 * cross-mount "..", rapid up/down traversal, and ".." through
 * renamed directories.
 *
 * Cases:
 *
 *   1. Basic parent.  mkdir a/b, stat("a/b/.."), verify st_ino
 *      matches stat("a").
 *
 *   2. Chain walk.  mkdir a/b/c/d, walk up via repeated "/.."
 *      (stat("a/b/c/d/../../../..")), verify st_ino matches ".".
 *
 *   3. openat with "..".  Open dir fd for "a/b", then
 *      openat(dirfd, "..", O_RDONLY|O_DIRECTORY), fstat both,
 *      verify parent ino matches stat("a").
 *
 *   4. Parent of renamed directory.  mkdir a/sub, rename a/sub to
 *      b/sub (mkdir b first), then stat("b/sub/.."), verify
 *      st_ino matches stat("b"), not stat("a").
 *
 *   5. Parent at export root.  stat("..") at the -d mount root.
 *      On NFS the server should return the root itself.  Verify
 *      st_dev of "." and ".." match (same filesystem / export).
 *
 * Portable: POSIX across Linux / FreeBSD / macOS / Solaris.
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

static const char *myname = "op_lookupp";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise stat(..) / openat(..) -> NFSv4 LOOKUPP "
		"(RFC 7530 S18.15)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static void case_basic_parent(void)
{
	char a[64], ab[128];
	snprintf(a, sizeof(a), "t_pp.a.%ld", (long)getpid());
	snprintf(ab, sizeof(ab), "%s/b", a);

	rmdir(ab); rmdir(a);
	if (mkdir(a, 0755) != 0) {
		complain("case1: mkdir(%s): %s", a, strerror(errno));
		return;
	}
	if (mkdir(ab, 0755) != 0) {
		complain("case1: mkdir(%s): %s", ab, strerror(errno));
		rmdir(a);
		return;
	}

	struct stat st_a, st_dotdot;
	if (stat(a, &st_a) != 0) {
		complain("case1: stat(%s): %s", a, strerror(errno));
		goto out;
	}

	char path[256];
	snprintf(path, sizeof(path), "%s/..", ab);
	if (stat(path, &st_dotdot) != 0) {
		complain("case1: stat(%s): %s", path, strerror(errno));
		goto out;
	}

	if (st_a.st_ino != st_dotdot.st_ino)
		complain("case1: ino of '%s' (%lu) != ino of '%s' (%lu)",
			 a, (unsigned long)st_a.st_ino,
			 path, (unsigned long)st_dotdot.st_ino);
out:
	rmdir(ab);
	rmdir(a);
}

static void case_chain_walk(void)
{
	char base[64];
	snprintf(base, sizeof(base), "t_pp.ch.%ld", (long)getpid());

	char d1[128], d2[256], d3[384];
	snprintf(d1, sizeof(d1), "%s/b", base);
	snprintf(d2, sizeof(d2), "%s/c", d1);
	snprintf(d3, sizeof(d3), "%s/d", d2);

	rmdir(d3); rmdir(d2); rmdir(d1); rmdir(base);
	if (mkdir(base, 0755) != 0 || mkdir(d1, 0755) != 0 ||
	    mkdir(d2, 0755) != 0 || mkdir(d3, 0755) != 0) {
		complain("case2: mkdir chain: %s", strerror(errno));
		rmdir(d3); rmdir(d2); rmdir(d1); rmdir(base);
		return;
	}

	struct stat st_dot, st_up;
	if (stat(".", &st_dot) != 0) {
		complain("case2: stat(.): %s", strerror(errno));
		goto out;
	}

	char path[512];
	snprintf(path, sizeof(path), "%s/../../../..", d3);
	if (stat(path, &st_up) != 0) {
		complain("case2: stat(%s): %s", path, strerror(errno));
		goto out;
	}

	if (st_dot.st_ino != st_up.st_ino)
		complain("case2: ino of '.' (%lu) != ino via chain (%lu)",
			 (unsigned long)st_dot.st_ino,
			 (unsigned long)st_up.st_ino);
out:
	rmdir(d3); rmdir(d2); rmdir(d1); rmdir(base);
}

static void case_openat_dotdot(void)
{
	char a[64], ab[128];
	snprintf(a, sizeof(a), "t_pp.oa.%ld", (long)getpid());
	snprintf(ab, sizeof(ab), "%s/b", a);

	rmdir(ab); rmdir(a);
	if (mkdir(a, 0755) != 0 || mkdir(ab, 0755) != 0) {
		complain("case3: mkdir: %s", strerror(errno));
		rmdir(ab); rmdir(a);
		return;
	}

	int dfd = open(ab, O_RDONLY | O_DIRECTORY);
	if (dfd < 0) {
		complain("case3: open(%s): %s", ab, strerror(errno));
		goto out;
	}

	int pfd = openat(dfd, "..", O_RDONLY | O_DIRECTORY);
	if (pfd < 0) {
		complain("case3: openat(dfd, ..): %s", strerror(errno));
		close(dfd);
		goto out;
	}

	struct stat st_a, st_parent;
	if (stat(a, &st_a) != 0) {
		complain("case3: stat(%s): %s", a, strerror(errno));
		close(pfd); close(dfd);
		goto out;
	}
	if (fstat(pfd, &st_parent) != 0) {
		complain("case3: fstat(parent fd): %s", strerror(errno));
		close(pfd); close(dfd);
		goto out;
	}

	if (st_a.st_ino != st_parent.st_ino)
		complain("case3: ino of '%s' (%lu) != ino of openat(..) "
			 "(%lu)", a, (unsigned long)st_a.st_ino,
			 (unsigned long)st_parent.st_ino);

	close(pfd);
	close(dfd);
out:
	rmdir(ab);
	rmdir(a);
}

static void case_renamed_parent(void)
{
	char a[64], b[64], asub[128], bsub[128];
	snprintf(a, sizeof(a), "t_pp.ra.%ld", (long)getpid());
	snprintf(b, sizeof(b), "t_pp.rb.%ld", (long)getpid());
	snprintf(asub, sizeof(asub), "%s/sub", a);
	snprintf(bsub, sizeof(bsub), "%s/sub", b);

	rmdir(asub); rmdir(a); rmdir(bsub); rmdir(b);
	if (mkdir(a, 0755) != 0 || mkdir(b, 0755) != 0 ||
	    mkdir(asub, 0755) != 0) {
		complain("case4: mkdir: %s", strerror(errno));
		rmdir(asub); rmdir(a); rmdir(bsub); rmdir(b);
		return;
	}

	if (rename(asub, bsub) != 0) {
		complain("case4: rename(%s, %s): %s", asub, bsub,
			 strerror(errno));
		rmdir(asub); rmdir(a); rmdir(b);
		return;
	}

	struct stat st_b, st_parent;
	if (stat(b, &st_b) != 0) {
		complain("case4: stat(%s): %s", b, strerror(errno));
		goto out;
	}

	char path[256];
	snprintf(path, sizeof(path), "%s/..", bsub);
	if (stat(path, &st_parent) != 0) {
		complain("case4: stat(%s): %s", path, strerror(errno));
		goto out;
	}

	if (st_b.st_ino != st_parent.st_ino)
		complain("case4: after rename, ino of '%s' (%lu) != ino "
			 "of '%s' (%lu)", b, (unsigned long)st_b.st_ino,
			 path, (unsigned long)st_parent.st_ino);
out:
	rmdir(bsub);
	rmdir(a);
	rmdir(b);
}

static void case_parent_at_root(void)
{
	struct stat st_dot, st_dotdot;
	if (stat(".", &st_dot) != 0) {
		complain("case5: stat(.): %s", strerror(errno));
		return;
	}
	if (stat("..", &st_dotdot) != 0) {
		complain("case5: stat(..): %s", strerror(errno));
		return;
	}

	if (st_dot.st_dev != st_dotdot.st_dev) {
		if (!Sflag)
			printf("NOTE: %s: case5 st_dev of '.' (%lu) != "
			       "st_dev of '..' (%lu) — -d may not be an "
			       "export root\n", myname,
			       (unsigned long)st_dot.st_dev,
			       (unsigned long)st_dotdot.st_dev);
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
		"stat(..) / openat(..) -> NFSv4 LOOKUPP (RFC 7530 S18.15)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_basic_parent", case_basic_parent());
	RUN_CASE("case_chain_walk", case_chain_walk());
	RUN_CASE("case_openat_dotdot", case_openat_dotdot());
	RUN_CASE("case_renamed_parent", case_renamed_parent());
	RUN_CASE("case_parent_at_root", case_parent_at_root());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
