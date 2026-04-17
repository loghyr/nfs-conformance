/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_path_limits.c -- exercise ENAMETOOLONG across syscalls.
 *
 * POSIX.1-2008 lets an implementation reject paths whose single
 * component exceeds NAME_MAX or whose total exceeds PATH_MAX.  NFSv4
 * servers enforce their own limits on both -- sometimes tighter than
 * the client reports.  Probe each common syscall and report either
 * the expected ENAMETOOLONG or the server-observed behaviour.
 *
 * Cases:
 *
 *   1. open(NAME_MAX+1-byte component, O_CREAT) -> ENAMETOOLONG.
 *
 *   2. mkdir(NAME_MAX+1-byte component) -> ENAMETOOLONG.
 *
 *   3. stat(NAME_MAX+1-byte component) -> ENAMETOOLONG.
 *
 *   4. rename(NAME_MAX+1-byte, anything) -> ENAMETOOLONG.
 *
 *   5. Path > PATH_MAX.  Build a long path by concatenating
 *      many max-NAME_MAX-length directories; try open on it.
 *      Expect ENAMETOOLONG or ENOENT (since the path is also
 *      missing).  Just a sanity check that the client doesn't
 *      crash.
 *
 * Portable: POSIX.1-2008.  Linux NAME_MAX is 255; BSD has NAME_MAX
 * as a per-filesystem limit -- we probe with _PC_NAME_MAX where
 * available, fall back to 255.
 */

#define _POSIX_C_SOURCE 200809L

#include "tests.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
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

static const char *myname = "op_path_limits";

static long scratch_name_max(void)
{
#ifdef _PC_NAME_MAX
	long v = pathconf(".", _PC_NAME_MAX);
	if (v > 0 && v < 4096) return v;
#endif
	return 255;
}

static long scratch_path_max(void)
{
#ifdef _PC_PATH_MAX
	long v = pathconf(".", _PC_PATH_MAX);
	if (v > 0 && v < 65536) return v;
#endif
#ifdef PATH_MAX
	return PATH_MAX;
#else
	return 4096;
#endif
}

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise ENAMETOOLONG across syscalls\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

/* Fill buf with 'a' repeated n times + NUL.  Returns buf. */
static char *fill_a(char *buf, size_t n)
{
	for (size_t i = 0; i < n; i++) buf[i] = 'a';
	buf[n] = '\0';
	return buf;
}

static void case_open_enametoolong(void)
{
	long nm = scratch_name_max();
	char *name = malloc((size_t)nm + 2);
	if (!name) { complain("case1: malloc"); return; }
	fill_a(name, (size_t)nm + 1);

	errno = 0;
	int fd = open(name, O_WRONLY | O_CREAT, 0644);
	if (fd >= 0) {
		if (!Sflag)
			printf("NOTE: %s: case1 open(NAME_MAX+1) unexpectedly "
			       "succeeded (server/client allows longer "
			       "components than NAME_MAX=%ld)\n",
			       myname, nm);
		close(fd);
		unlink(name);
	} else if (errno != ENAMETOOLONG) {
		complain("case1: got %s; expected ENAMETOOLONG",
			 strerror(errno));
	}
	free(name);
}

static void case_mkdir_enametoolong(void)
{
	long nm = scratch_name_max();
	char *name = malloc((size_t)nm + 2);
	if (!name) { complain("case2: malloc"); return; }
	fill_a(name, (size_t)nm + 1);

	errno = 0;
	int rc = mkdir(name, 0755);
	if (rc == 0) {
		if (!Sflag)
			printf("NOTE: %s: case2 mkdir(NAME_MAX+1) unexpectedly "
			       "succeeded\n", myname);
		rmdir(name);
	} else if (errno != ENAMETOOLONG) {
		complain("case2: got %s; expected ENAMETOOLONG",
			 strerror(errno));
	}
	free(name);
}

static void case_stat_enametoolong(void)
{
	long nm = scratch_name_max();
	char *name = malloc((size_t)nm + 2);
	if (!name) { complain("case3: malloc"); return; }
	fill_a(name, (size_t)nm + 1);

	errno = 0;
	struct stat st;
	int rc = stat(name, &st);
	if (rc == 0) {
		if (!Sflag)
			printf("NOTE: %s: case3 stat(NAME_MAX+1) unexpectedly "
			       "succeeded\n", myname);
	} else if (errno != ENAMETOOLONG && errno != ENOENT) {
		complain("case3: got %s; expected ENAMETOOLONG or ENOENT",
			 strerror(errno));
	}
	/* Some platforms do component-length check at open/stat time
	 * and return ENAMETOOLONG even for a missing file; others
	 * return ENOENT first.  Accept both as POSIX-valid. */
	free(name);
}

static void case_rename_enametoolong(void)
{
	long nm = scratch_name_max();
	char *name = malloc((size_t)nm + 2);
	if (!name) { complain("case4: malloc"); return; }
	fill_a(name, (size_t)nm + 1);

	errno = 0;
	int rc = rename(name, "t_pl.dst");
	if (rc == 0) {
		if (!Sflag)
			printf("NOTE: %s: case4 rename(NAME_MAX+1) "
			       "unexpectedly succeeded\n", myname);
	} else if (errno != ENAMETOOLONG && errno != ENOENT) {
		complain("case4: got %s; expected ENAMETOOLONG or ENOENT",
			 strerror(errno));
	}
	free(name);
}

static void case_path_max(void)
{
	long pm = scratch_path_max();
	/* Build a path longer than PATH_MAX by chaining segments
	 * with a / separator.  Don't actually mkdir each component;
	 * we just want a path that exceeds the limit. */
	size_t total = (size_t)pm + 16;
	char *path = malloc(total + 1);
	if (!path) { complain("case5: malloc"); return; }

	size_t seg = 16;
	size_t pos = 0;
	while (pos < total) {
		size_t room = total - pos;
		if (room < seg + 1) {
			fill_a(path + pos, room);
			pos += room;
			break;
		}
		fill_a(path + pos, seg);
		path[pos + seg] = '/';
		pos += seg + 1;
	}
	path[total] = '\0';

	errno = 0;
	int fd = open(path, O_RDONLY);
	if (fd >= 0) {
		close(fd);
		if (!Sflag)
			printf("NOTE: %s: case5 open(>PATH_MAX=%ld) "
			       "unexpectedly succeeded\n", myname, pm);
	} else if (errno != ENAMETOOLONG && errno != ENOENT) {
		complain("case5: got %s; expected ENAMETOOLONG or ENOENT",
			 strerror(errno));
	}
	free(path);
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
		"ENAMETOOLONG across syscalls (pjdfstest path-limit cases)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_open_enametoolong", case_open_enametoolong());
	RUN_CASE("case_mkdir_enametoolong", case_mkdir_enametoolong());
	RUN_CASE("case_stat_enametoolong", case_stat_enametoolong());
	RUN_CASE("case_rename_enametoolong",
		 case_rename_enametoolong());
	RUN_CASE("case_path_max", case_path_max());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
