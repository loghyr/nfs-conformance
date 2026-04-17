/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_errno_open.c -- exercise open(2) error paths.
 *
 * Cases:
 *
 *   1. open(missing, O_RDONLY) -> ENOENT.
 *
 *   2. open(missing-prefix/file, O_RDONLY) -> ENOENT.
 *
 *   3. open(file-as-prefix/x, O_RDONLY) -> ENOTDIR.  A path
 *      component is a regular file, not a directory.
 *
 *   4. open(dir, O_WRONLY) -> EISDIR.  Opening a directory for
 *      write is always invalid.
 *
 *   5. open(dir, O_RDWR) -> EISDIR.  Same as case 4 for read-write.
 *
 *   6. open(fifo, O_WRONLY | O_NONBLOCK) with no reader -> ENXIO.
 *
 *   7. open(new, O_CREAT | O_EXCL) on a file that already exists
 *      -> EEXIST.  (op_open_excl also covers this; kept here for
 *      completeness of the errno matrix.)
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

static const char *myname = "op_errno_open";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise open(2) error paths\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static int expect_errno(int rc, int expected, const char *label)
{
	if (rc >= 0) {
		complain("%s: unexpectedly succeeded (fd=%d)", label, rc);
		if (rc >= 0) close(rc);
		return 0;
	}
	if (errno != expected) {
		complain("%s: got %s (%d); expected %s (%d)",
			 label, strerror(errno), errno,
			 strerror(expected), expected);
		return 0;
	}
	return 1;
}

/*
 * expect_errno_set -- accept any of a small allowlist.  Used where
 * POSIX is permissive about which specific errno applies (e.g.,
 * open(dir, O_WRONLY) -> EISDIR or EACCES per implementation).
 */
static int expect_errno_set(int rc, const int *allowed, int n_allowed,
			    const char *label)
{
	if (rc >= 0) {
		complain("%s: unexpectedly succeeded (fd=%d)", label, rc);
		close(rc);
		return 0;
	}
	for (int i = 0; i < n_allowed; i++)
		if (errno == allowed[i]) return 1;
	complain("%s: got %s (%d); expected one of the allowed errnos",
		 label, strerror(errno), errno);
	return 0;
}

static void case_missing_enoent(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_eo.mi.%ld", (long)getpid());
	unlink(a);
	errno = 0;
	expect_errno(open(a, O_RDONLY), ENOENT,
		     "case1: open missing, O_RDONLY");
}

static void case_missing_prefix_enoent(void)
{
	char a[128];
	snprintf(a, sizeof(a), "t_eo.mp.nonexistent.%ld/x",
		 (long)getpid());
	errno = 0;
	expect_errno(open(a, O_RDONLY), ENOENT,
		     "case2: open missing-prefix/file, O_RDONLY");
}

static void case_file_as_prefix_enotdir(void)
{
	char f[64], path[128];
	snprintf(f, sizeof(f), "t_eo.fp.%ld", (long)getpid());
	snprintf(path, sizeof(path), "%s/x", f);
	unlink(f);

	int fd = open(f, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case3: setup: %s", strerror(errno));
		return;
	}
	close(fd);

	errno = 0;
	expect_errno(open(path, O_RDONLY), ENOTDIR,
		     "case3: open file-as-prefix/x, O_RDONLY");

	unlink(f);
}

static void case_dir_wronly_eisdir(void)
{
	char d[64];
	snprintf(d, sizeof(d), "t_eo.dw.%ld", (long)getpid());
	rmdir(d);
	if (mkdir(d, 0755) != 0) {
		complain("case4: mkdir: %s", strerror(errno));
		return;
	}
	errno = 0;
	/* POSIX allows EISDIR; some older Unixes and NFS servers
	 * return EACCES (permission model fires first). */
	int allowed_w[] = { EISDIR, EACCES };
	expect_errno_set(open(d, O_WRONLY), allowed_w, 2,
			 "case4: open directory, O_WRONLY");
	rmdir(d);
}

static void case_dir_rdwr_eisdir(void)
{
	char d[64];
	snprintf(d, sizeof(d), "t_eo.dr.%ld", (long)getpid());
	rmdir(d);
	if (mkdir(d, 0755) != 0) {
		complain("case5: mkdir: %s", strerror(errno));
		return;
	}
	errno = 0;
	int allowed_rw[] = { EISDIR, EACCES };
	expect_errno_set(open(d, O_RDWR), allowed_rw, 2,
		     "case5: open directory, O_RDWR");
	rmdir(d);
}

static void case_fifo_wronly_nonblock_enxio(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_eo.fn.%ld", (long)getpid());
	unlink(f);
	if (mkfifo(f, 0644) != 0) {
		if (errno == EOPNOTSUPP || errno == ENOSYS) {
			if (!Sflag)
				printf("NOTE: %s: case6 mkfifo not supported "
				       "on this fs (%s); skipping\n",
				       myname, strerror(errno));
			return;
		}
		complain("case6: mkfifo: %s", strerror(errno));
		return;
	}

	errno = 0;
	int fd = open(f, O_WRONLY | O_NONBLOCK);
	if (fd >= 0) {
		complain("case6: open fifo O_WRONLY|O_NONBLOCK without "
			 "reader succeeded (expected ENXIO)");
		close(fd);
	} else if (errno != ENXIO) {
		complain("case6: got %s; expected ENXIO",
			 strerror(errno));
	}

	unlink(f);
}

static void case_creat_excl_eexist(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_eo.ce.%ld", (long)getpid());
	unlink(a);

	int fd = open(a, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case7: setup: %s", strerror(errno));
		return;
	}
	close(fd);

	errno = 0;
	expect_errno(open(a, O_WRONLY | O_CREAT | O_EXCL, 0644), EEXIST,
		     "case7: open existing, O_CREAT|O_EXCL");

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
		"open(2) error-path coverage (pjdfstest open/)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_missing_enoent", case_missing_enoent());
	RUN_CASE("case_missing_prefix_enoent",
		 case_missing_prefix_enoent());
	RUN_CASE("case_file_as_prefix_enotdir",
		 case_file_as_prefix_enotdir());
	RUN_CASE("case_dir_wronly_eisdir", case_dir_wronly_eisdir());
	RUN_CASE("case_dir_rdwr_eisdir", case_dir_rdwr_eisdir());
	RUN_CASE("case_fifo_wronly_nonblock_enxio",
		 case_fifo_wronly_nonblock_enxio());
	RUN_CASE("case_creat_excl_eexist",
		 case_creat_excl_eexist());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
