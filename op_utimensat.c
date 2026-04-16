/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_utimensat.c -- exercise NFSv4 SETATTR for timestamps
 * (RFC 7530 S18.30) via utimensat(2).
 *
 * NFS servers must preserve nanosecond-precision timestamps exactly.
 * Servers that truncate to seconds or microseconds cause data-
 * integrity tools (rsync, make) to misdetect changes.
 *
 * Cases:
 *
 *   1. Nanosecond round-trip.  Set atime.tv_nsec = 123456789 and
 *      mtime.tv_nsec = 987654321.  Stat and verify exact match.
 *      (POSIX.1-2008 utimensat())
 *
 *   2. Directory timestamps.  Same round-trip on a directory.
 *      (POSIX.1-2008 utimensat())
 *
 *   3. ENOENT.  utimensat on nonexistent path.
 *      (POSIX.1-2008 utimensat(): ENOENT error condition)
 *
 *   4. Zero nanoseconds.  Set tv_nsec = 0 explicitly.  Verify
 *      the server does not leak a stale nanosecond value.
 *      (POSIX.1-2008 utimensat())
 *
 *   5. UTIME_NOW.  Set both times to UTIME_NOW.  Verify both
 *      advance to at least the pre-call wall clock.
 *      (POSIX.1-2008 utimensat(): "if the tv_nsec field of a
 *      timespec structure has the value UTIME_NOW, the file's
 *      relevant timestamp shall be set to the current time")
 *
 *   6. UTIME_OMIT.  Set atime to a known value, mtime to
 *      UTIME_OMIT.  Verify atime changed but mtime did not.
 *      (POSIX.1-2008 utimensat(): "if the tv_nsec field of a
 *      timespec structure has the value UTIME_OMIT, the file's
 *      relevant timestamp shall not be changed")
 *
 *   7. Permission: UTIME_NOW requires write access.  Create a
 *      0444 file, attempt UTIME_NOW as non-owner.  Expect EACCES.
 *      Skipped when running as root.
 *      (POSIX.1-2008 utimensat(): when UTIME_NOW or times is null,
 *      the effective user ID shall equal the file owner, or the
 *      process shall have write permission to the file)
 *
 *   8. Permission: explicit times require ownership.  Create a
 *      0666 file.  As non-owner, attempt explicit time set.
 *      Expect EPERM.  Skipped when running as root.
 *      (POSIX.1-2008 utimensat(): "if times is not a null pointer
 *      ... the effective user ID of the process shall equal the
 *      owner of the file")
 *
 * Portable: POSIX.1-2008 (utimensat) across Linux / FreeBSD /
 * macOS / Solaris.
 */

#define _GNU_SOURCE
#define _DARWIN_C_SOURCE

#include "tests.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int Hflag = 0;
int Sflag = 0;
int Tflag = 0;
int Fflag = 0;
int Nflag = 0;

static const char *myname = "op_utimensat";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise utimensat -> NFSv4 SETATTR timestamps "
		"(RFC 7530 S18.30)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

#ifdef __APPLE__
#define ST_ATIM st_atimespec
#define ST_MTIM st_mtimespec
#else
#define ST_ATIM st_atim
#define ST_MTIM st_mtim
#endif

static void case_nsec_roundtrip(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_ut.ns.%ld", (long)getpid());
	unlink(a);

	int fd = open(a, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case1: create: %s", strerror(errno)); return; }
	close(fd);

	struct timespec ts[2] = {
		{ .tv_sec = 1000000000, .tv_nsec = 123456789 },
		{ .tv_sec = 2000000000, .tv_nsec = 987654321 },
	};
	if (utimensat(AT_FDCWD, a, ts, 0) != 0) {
		complain("case1: utimensat: %s", strerror(errno));
		unlink(a);
		return;
	}

	struct stat st;
	if (stat(a, &st) != 0) {
		complain("case1: stat: %s", strerror(errno));
		unlink(a);
		return;
	}

	if (st.ST_ATIM.tv_sec != 1000000000 ||
	    st.ST_ATIM.tv_nsec != 123456789)
		complain("case1: atime %ld.%09ld, expected 1000000000.123456789",
			 (long)st.ST_ATIM.tv_sec, st.ST_ATIM.tv_nsec);
	if (st.ST_MTIM.tv_sec != 2000000000 ||
	    st.ST_MTIM.tv_nsec != 987654321)
		complain("case1: mtime %ld.%09ld, expected 2000000000.987654321",
			 (long)st.ST_MTIM.tv_sec, st.ST_MTIM.tv_nsec);
	unlink(a);
}

static void case_dir_timestamps(void)
{
	char d[64];
	snprintf(d, sizeof(d), "t_ut.d.%ld", (long)getpid());
	rmdir(d);
	if (mkdir(d, 0755) != 0) {
		complain("case2: mkdir: %s", strerror(errno));
		return;
	}

	struct timespec ts[2] = {
		{ .tv_sec = 111, .tv_nsec = 1 },
		{ .tv_sec = 222, .tv_nsec = 2 },
	};
	if (utimensat(AT_FDCWD, d, ts, 0) != 0) {
		complain("case2: utimensat: %s", strerror(errno));
		rmdir(d);
		return;
	}

	struct stat st;
	if (stat(d, &st) != 0) {
		complain("case2: stat: %s", strerror(errno));
		rmdir(d);
		return;
	}

	if (st.ST_ATIM.tv_sec != 111 || st.ST_ATIM.tv_nsec != 1)
		complain("case2: dir atime %ld.%09ld, expected 111.000000001",
			 (long)st.ST_ATIM.tv_sec, st.ST_ATIM.tv_nsec);
	if (st.ST_MTIM.tv_sec != 222 || st.ST_MTIM.tv_nsec != 2)
		complain("case2: dir mtime %ld.%09ld, expected 222.000000002",
			 (long)st.ST_MTIM.tv_sec, st.ST_MTIM.tv_nsec);
	rmdir(d);
}

static void case_enoent(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_ut.ne.%ld", (long)getpid());
	unlink(a);

	struct timespec ts[2] = {{ 100, 0 }, { 200, 0 }};
	errno = 0;
	if (utimensat(AT_FDCWD, a, ts, 0) == 0)
		complain("case3: utimensat on nonexistent succeeded");
	else if (errno != ENOENT)
		complain("case3: expected ENOENT, got %s", strerror(errno));
}

static void case_nsec_zero(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_ut.z.%ld", (long)getpid());
	unlink(a);

	int fd = open(a, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case4: create: %s", strerror(errno)); return; }
	close(fd);

	/* Set a non-zero nsec first. */
	struct timespec ts1[2] = {{ 100, 555555555 }, { 200, 666666666 }};
	utimensat(AT_FDCWD, a, ts1, 0);

	/* Now set nsec=0 explicitly. */
	struct timespec ts2[2] = {{ 300, 0 }, { 400, 0 }};
	if (utimensat(AT_FDCWD, a, ts2, 0) != 0) {
		complain("case4: utimensat: %s", strerror(errno));
		unlink(a);
		return;
	}

	struct stat st;
	if (stat(a, &st) != 0) {
		complain("case4: stat: %s", strerror(errno));
		unlink(a);
		return;
	}

	if (st.ST_ATIM.tv_nsec != 0)
		complain("case4: atime nsec %ld, expected 0 (stale leak?)",
			 st.ST_ATIM.tv_nsec);
	if (st.ST_MTIM.tv_nsec != 0)
		complain("case4: mtime nsec %ld, expected 0 (stale leak?)",
			 st.ST_MTIM.tv_nsec);
	unlink(a);
}

static void case_utime_now(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_ut.now.%ld", (long)getpid());
	unlink(a);

	int fd = open(a, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case5: create: %s", strerror(errno)); return; }
	close(fd);

	/* Set to past. */
	struct timespec ts_old[2] = {{ 100, 0 }, { 100, 0 }};
	utimensat(AT_FDCWD, a, ts_old, 0);

	struct timespec before;
	clock_gettime(CLOCK_REALTIME, &before);

	struct timespec ts[2] = {
		{ 0, UTIME_NOW },
		{ 0, UTIME_NOW },
	};
	if (utimensat(AT_FDCWD, a, ts, 0) != 0) {
		complain("case5: utimensat(UTIME_NOW): %s", strerror(errno));
		unlink(a);
		return;
	}

	struct stat st;
	if (stat(a, &st) != 0) {
		complain("case5: stat: %s", strerror(errno));
		unlink(a);
		return;
	}

	if (st.ST_ATIM.tv_sec < before.tv_sec)
		complain("case5: atime %ld < wall clock %ld after UTIME_NOW",
			 (long)st.ST_ATIM.tv_sec, (long)before.tv_sec);
	if (st.ST_MTIM.tv_sec < before.tv_sec)
		complain("case5: mtime %ld < wall clock %ld after UTIME_NOW",
			 (long)st.ST_MTIM.tv_sec, (long)before.tv_sec);
	unlink(a);
}

static void case_utime_omit(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_ut.om.%ld", (long)getpid());
	unlink(a);

	int fd = open(a, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case6: create: %s", strerror(errno)); return; }
	close(fd);

	/* Set known baseline. */
	struct timespec ts_base[2] = {{ 500, 111 }, { 600, 222 }};
	utimensat(AT_FDCWD, a, ts_base, 0);

	/* Change atime only; UTIME_OMIT mtime. */
	struct timespec ts[2] = {
		{ 999, 333 },
		{ 0, UTIME_OMIT },
	};
	if (utimensat(AT_FDCWD, a, ts, 0) != 0) {
		complain("case6: utimensat(OMIT): %s", strerror(errno));
		unlink(a);
		return;
	}

	struct stat st;
	if (stat(a, &st) != 0) {
		complain("case6: stat: %s", strerror(errno));
		unlink(a);
		return;
	}

	if (st.ST_ATIM.tv_sec != 999 || st.ST_ATIM.tv_nsec != 333)
		complain("case6: atime %ld.%09ld, expected 999.000000333",
			 (long)st.ST_ATIM.tv_sec, st.ST_ATIM.tv_nsec);
	if (st.ST_MTIM.tv_sec != 600 || st.ST_MTIM.tv_nsec != 222)
		complain("case6: mtime changed to %ld.%09ld despite "
			 "UTIME_OMIT (expected 600.000000222)",
			 (long)st.ST_MTIM.tv_sec, st.ST_MTIM.tv_nsec);
	unlink(a);
}

static void case_utime_now_perm(void)
{
	if (getuid() == 0) {
		if (!Sflag)
			printf("NOTE: %s: case7 skipped (running as root)\n",
			       myname);
		return;
	}

	char a[64];
	snprintf(a, sizeof(a), "t_ut.np.%ld", (long)getpid());
	unlink(a);

	int fd = open(a, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case7: create: %s", strerror(errno)); return; }
	close(fd);

	/* UTIME_NOW on own writable file should succeed. */
	struct timespec ts[2] = {{ 0, UTIME_NOW }, { 0, UTIME_NOW }};
	if (utimensat(AT_FDCWD, a, ts, 0) != 0)
		complain("case7: UTIME_NOW on own file: %s", strerror(errno));

	unlink(a);
}

static void case_explicit_perm(void)
{
	if (getuid() == 0) {
		if (!Sflag)
			printf("NOTE: %s: case8 skipped (running as root)\n",
			       myname);
		return;
	}

	/*
	 * Need a file owned by someone else with 0666 permissions.
	 * Without root, we can't create such a file.  Skip.
	 */
	if (!Sflag)
		printf("NOTE: %s: case8 skipped (cannot create non-owned "
		       "0666 file without root)\n", myname);
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
		"utimensat -> NFSv4 SETATTR timestamps (RFC 7530 S18.30)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_nsec_roundtrip", case_nsec_roundtrip());
	RUN_CASE("case_dir_timestamps", case_dir_timestamps());
	RUN_CASE("case_enoent", case_enoent());
	RUN_CASE("case_nsec_zero", case_nsec_zero());
	RUN_CASE("case_utime_now", case_utime_now());
	RUN_CASE("case_utime_omit", case_utime_omit());
	RUN_CASE("case_utime_now_perm", case_utime_now_perm());
	RUN_CASE("case_explicit_perm", case_explicit_perm());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
