/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_directory.c -- exercise O_DIRECTORY open flag (POSIX.1-2008).
 *
 * O_DIRECTORY requires the path to resolve to a directory.  If the
 * final target is a non-directory, open() fails with ENOTDIR.  This
 * exercises the server's file-type reporting via NFSv4 OPEN/LOOKUP
 * on different object types.
 *
 * Cases:
 *
 *   1. O_DIRECTORY on a directory succeeds.
 *
 *   2. O_DIRECTORY on a regular file fails ENOTDIR.
 *
 *   3. O_DIRECTORY on a symlink pointing to a directory succeeds
 *      (symlink is followed, target is a dir).
 *
 *   4. O_DIRECTORY on a symlink pointing to a regular file fails
 *      ENOTDIR.
 *
 *   5. O_DIRECTORY on a nonexistent path fails ENOENT.
 *
 *   6. O_DIRECTORY | O_CREAT is invalid (cannot create a directory
 *      via open).  POSIX leaves behavior undefined; Linux returns
 *      EISDIR on existing dir, EEXIST on existing file, and with
 *      no target it tries to create a file and then rejects because
 *      the fresh file is not a directory (ENOTDIR).  Record the
 *      errno without asserting a specific value.
 *
 * Portable: POSIX.1-2008 on Linux / macOS / FreeBSD.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

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

static const char *myname = "op_directory";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise O_DIRECTORY open flag (POSIX.1-2008)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static void case_dir_on_dir(void)
{
	char d[64];
	snprintf(d, sizeof(d), "t_od.dd.%ld", (long)getpid());
	rmdir(d);
	if (mkdir(d, 0755) != 0) {
		complain("case1: mkdir: %s", strerror(errno));
		return;
	}

	int fd = open(d, O_RDONLY | O_DIRECTORY);
	if (fd < 0)
		complain("case1: O_DIRECTORY on dir: %s", strerror(errno));
	else
		close(fd);
	rmdir(d);
}

static void case_dir_on_file(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_od.df.%ld", (long)getpid());
	unlink(a);

	int fd = open(a, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case2: create: %s", strerror(errno)); return; }
	close(fd);

	errno = 0;
	fd = open(a, O_RDONLY | O_DIRECTORY);
	if (fd >= 0) {
		complain("case2: O_DIRECTORY on regular file succeeded");
		close(fd);
	} else if (errno != ENOTDIR) {
		complain("case2: expected ENOTDIR, got %s", strerror(errno));
	}
	unlink(a);
}

static void case_dir_on_symlink_to_dir(void)
{
	char d[64], sl[64];
	snprintf(d, sizeof(d), "t_od.sdd.%ld", (long)getpid());
	snprintf(sl, sizeof(sl), "t_od.sdl.%ld", (long)getpid());
	unlink(sl);
	rmdir(d);

	if (mkdir(d, 0755) != 0) {
		complain("case3: mkdir: %s", strerror(errno));
		return;
	}
	if (symlink(d, sl) != 0) {
		complain("case3: symlink: %s", strerror(errno));
		rmdir(d);
		return;
	}

	int fd = open(sl, O_RDONLY | O_DIRECTORY);
	if (fd < 0)
		complain("case3: O_DIRECTORY via symlink-to-dir: %s",
			 strerror(errno));
	else
		close(fd);

	unlink(sl);
	rmdir(d);
}

static void case_dir_on_symlink_to_file(void)
{
	char a[64], sl[64];
	snprintf(a, sizeof(a), "t_od.sff.%ld", (long)getpid());
	snprintf(sl, sizeof(sl), "t_od.sfl.%ld", (long)getpid());
	unlink(sl);
	unlink(a);

	int fd = open(a, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case4: create: %s", strerror(errno)); return; }
	close(fd);
	if (symlink(a, sl) != 0) {
		complain("case4: symlink: %s", strerror(errno));
		unlink(a);
		return;
	}

	errno = 0;
	fd = open(sl, O_RDONLY | O_DIRECTORY);
	if (fd >= 0) {
		complain("case4: O_DIRECTORY via symlink-to-file succeeded");
		close(fd);
	} else if (errno != ENOTDIR) {
		complain("case4: expected ENOTDIR, got %s", strerror(errno));
	}

	unlink(sl);
	unlink(a);
}

static void case_dir_on_missing(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_od.ne.%ld", (long)getpid());
	unlink(a);

	errno = 0;
	int fd = open(a, O_RDONLY | O_DIRECTORY);
	if (fd >= 0) {
		complain("case5: O_DIRECTORY on missing path succeeded");
		close(fd);
	} else if (errno != ENOENT) {
		complain("case5: expected ENOENT, got %s", strerror(errno));
	}
}

static void case_dir_with_creat(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_od.dc.%ld", (long)getpid());
	unlink(a);

	errno = 0;
	int fd = open(a, O_RDWR | O_CREAT | O_DIRECTORY, 0644);
	if (fd >= 0) {
		/* Platform allowed it; verify the result is sane and clean
		 * up.  Linux historically closes/unlinks in this path. */
		close(fd);
		if (!Sflag)
			printf("NOTE: %s: case6 O_CREAT|O_DIRECTORY accepted "
			       "on this platform (errno behavior is not "
			       "portable)\n", myname);
	} else if (!Sflag) {
		printf("NOTE: %s: case6 O_CREAT|O_DIRECTORY rejected with "
		       "%s (expected — cannot create directory via open)\n",
		       myname, strerror(errno));
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

	prelude(myname,
		"O_DIRECTORY open flag (POSIX.1-2008)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_dir_on_dir", case_dir_on_dir());
	RUN_CASE("case_dir_on_file", case_dir_on_file());
	RUN_CASE("case_dir_on_symlink_to_dir", case_dir_on_symlink_to_dir());
	RUN_CASE("case_dir_on_symlink_to_file", case_dir_on_symlink_to_file());
	RUN_CASE("case_dir_on_missing", case_dir_on_missing());
	RUN_CASE("case_dir_with_creat", case_dir_with_creat());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
