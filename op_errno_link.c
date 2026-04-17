/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_errno_link.c -- exercise link(2) error paths.
 *
 * Cases:
 *
 *   1. link(missing, new) -> ENOENT.
 *
 *   2. link(old, existing) -> EEXIST.
 *
 *   3. link(dir, new) -> EPERM.  Most POSIX systems forbid
 *      hard-linking directories (only root on some ancient BSDs
 *      could do it, and even then it is historically discouraged).
 *      Accept EACCES on a small number of servers that prefer it.
 *
 *   4. link(old, missing-prefix/new) -> ENOENT.
 *
 *   5. link(path-through-file/x, new) -> ENOTDIR.
 *
 * Portable: POSIX.1-2008.
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

static const char *myname = "op_errno_link";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise link(2) error paths\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static int touch(const char *path)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) return -1;
	close(fd);
	return 0;
}

static void expect_errno(int rc, int expected, const char *label)
{
	if (rc == 0) {
		complain("%s: unexpectedly succeeded", label);
		return;
	}
	if (errno != expected)
		complain("%s: got %s (%d); expected %s (%d)",
			 label, strerror(errno), errno,
			 strerror(expected), expected);
}

static void case_missing_source(void)
{
	char a[64], b[64];
	snprintf(a, sizeof(a), "t_el.ms.a.%ld", (long)getpid());
	snprintf(b, sizeof(b), "t_el.ms.b.%ld", (long)getpid());
	unlink(a); unlink(b);

	errno = 0;
	expect_errno(link(a, b), ENOENT,
		     "case1: link(missing, new)");
}

static void case_target_exists(void)
{
	char a[64], b[64];
	snprintf(a, sizeof(a), "t_el.te.a.%ld", (long)getpid());
	snprintf(b, sizeof(b), "t_el.te.b.%ld", (long)getpid());
	unlink(a); unlink(b);

	if (touch(a) != 0 || touch(b) != 0) {
		complain("case2: setup: %s", strerror(errno));
		unlink(a); unlink(b);
		return;
	}

	errno = 0;
	expect_errno(link(a, b), EEXIST,
		     "case2: link(old, existing)");

	unlink(a);
	unlink(b);
}

static void case_link_directory(void)
{
	char d[64], n[64];
	snprintf(d, sizeof(d), "t_el.ld.d.%ld", (long)getpid());
	snprintf(n, sizeof(n), "t_el.ld.n.%ld", (long)getpid());
	rmdir(d); unlink(n);

	if (mkdir(d, 0755) != 0) {
		complain("case3: mkdir: %s", strerror(errno));
		return;
	}

	errno = 0;
	int rc = link(d, n);
	if (rc == 0) {
		complain("case3: link(dir, new) succeeded "
			 "(expected EPERM)");
		unlink(n);
	} else if (errno != EPERM && errno != EACCES) {
		complain("case3: got %s; expected EPERM or EACCES",
			 strerror(errno));
	}

	rmdir(d);
}

static void case_missing_prefix(void)
{
	char a[64], b[128];
	snprintf(a, sizeof(a), "t_el.mp.%ld", (long)getpid());
	snprintf(b, sizeof(b), "t_el.mp.nonexistent.%ld/x",
		 (long)getpid());
	unlink(a);

	if (touch(a) != 0) {
		complain("case4: touch: %s", strerror(errno));
		return;
	}

	errno = 0;
	expect_errno(link(a, b), ENOENT,
		     "case4: link(old, missing-prefix/new)");

	unlink(a);
}

static void case_prefix_not_dir(void)
{
	char f[64], through[128], n[64];
	snprintf(f, sizeof(f), "t_el.pd.f.%ld", (long)getpid());
	snprintf(through, sizeof(through), "%s/x", f);
	snprintf(n, sizeof(n), "t_el.pd.n.%ld", (long)getpid());
	unlink(f); unlink(n);

	if (touch(f) != 0) {
		complain("case5: touch: %s", strerror(errno));
		return;
	}
	/* Create a valid source file to link FROM, so the only error
	 * is that the TARGET path has a non-directory component. */
	char src[64];
	snprintf(src, sizeof(src), "t_el.pd.s.%ld", (long)getpid());
	unlink(src);
	if (touch(src) != 0) {
		complain("case5: touch src: %s", strerror(errno));
		unlink(f); return;
	}

	errno = 0;
	expect_errno(link(src, through), ENOTDIR,
		     "case5: link(old, file-as-prefix/new)");

	unlink(src);
	unlink(f);
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
		"link(2) error-path coverage (pjdfstest link/)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_missing_source", case_missing_source());
	RUN_CASE("case_target_exists", case_target_exists());
	RUN_CASE("case_link_directory", case_link_directory());
	RUN_CASE("case_missing_prefix", case_missing_prefix());
	RUN_CASE("case_prefix_not_dir", case_prefix_not_dir());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
