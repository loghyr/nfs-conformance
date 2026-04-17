/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_statx_btime.c -- exercise birth-time retrieval, which surfaces
 * the NFSv4.2 `time_create` attribute (RFC 7862 S12.2).
 *
 * Cases:
 *
 *   1. Birth time present.  Create file; query birth time; verify it
 *      is non-zero / reported.  If not, the server or backing FS does
 *      not advertise time_create and we SKIP.
 *
 *   2. Birth time plausible.  btime.tv_sec is within +/- 60 seconds
 *      of CLOCK_REALTIME now.  Generous window to tolerate server
 *      clock skew.
 *
 *   3. Birth time <= m/ctime.  At creation, btime, mtime, and ctime
 *      should all be roughly equal; btime should never exceed
 *      mtime or ctime.
 *
 *   4. Birth time stable under utimensat.  Set atime/mtime to a
 *      past value via utimensat; re-query; btime unchanged.
 *
 *   5. Birth time stable across close/open.  Close the fd, open
 *      the same path, re-query; btime unchanged.
 *
 * Linux:   statx(STATX_BTIME) -- Linux-specific syscall (4.11+)
 * FreeBSD: lstat(2) -- st_birthtimespec in struct stat (FreeBSD 10+)
 * Other:   stub -- SKIP
 */

#define _GNU_SOURCE /* Linux: needed for statx */

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

static const char *myname = "op_statx_btime";

#if !defined(__linux__) && !defined(__FreeBSD__)
int main(void)
{
	skip("%s: birth-time query not available on this platform "
	     "(Linux 4.11+ statx or FreeBSD 10+ st_birthtim required)",
	     myname);
	return TEST_SKIP;
}
#elif defined(__FreeBSD__)

/*
 * FreeBSD: struct stat carries st_birthtim directly (BSD extension).
 * The NFS client stores VNOVAL (-1) in st_birthtim.tv_sec when the
 * server does not return the NFSv4.2 time_create attribute; that shows
 * up as tv_sec <= 0 below.
 *
 * FreeBSD uses st_birthtim/st_mtim/st_ctim; map the macOS-style
 * *timespec names used in the rest of this file.
 */
#define st_birthtimespec st_birthtim
#define st_mtimespec     st_mtim
#define st_ctimespec     st_ctim

/* Shared state, set by case 1 and read by cases 2-5. */
static char bt_name[64];
static struct timespec bt_wall;
static struct stat     bt_ref;

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise st_birthtimespec -> NFSv4.2 time_create "
		"(RFC 7862 S12.2)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

/* ts_le -- returns true if a <= b for struct timespec. */
static int ts_le(const struct timespec *a, const struct timespec *b)
{
	if (a->tv_sec != b->tv_sec)
		return a->tv_sec < b->tv_sec;
	return a->tv_nsec <= b->tv_nsec;
}

static void case_btime_present(void)
{
	if (lstat(bt_name, &bt_ref) != 0) {
		complain("case1: lstat: %s", strerror(errno));
		return;
	}
	if (bt_ref.st_birthtimespec.tv_sec <= 0) {
		/*
		 * Server or FS did not surface time_create.  FreeBSD's
		 * NFS client writes VNOVAL (-1) for 'not available';
		 * Linux/POSIX uses zero.  Accept either as SKIP.
		 */
		unlink(bt_name);
		skip("%s: server did not return time_create "
		     "(st_birthtimespec not available)", myname);
	}
}

static void case_btime_plausible(void)
{
	if (bt_ref.st_birthtimespec.tv_sec <= 0)
		return; /* case1 already bailed; nothing to check. */
	time_t btime = bt_ref.st_birthtimespec.tv_sec;
	time_t delta = btime >= bt_wall.tv_sec
			       ? btime - bt_wall.tv_sec
			       : bt_wall.tv_sec - btime;
	if (delta > 60)
		complain("case2: btime %lld is %lld s from wall %lld "
			 "(> 60s window)",
			 (long long)btime, (long long)delta,
			 (long long)bt_wall.tv_sec);
}

static void case_btime_le_mctime(void)
{
	if (bt_ref.st_birthtimespec.tv_sec <= 0)
		return;
	if (!ts_le(&bt_ref.st_birthtimespec, &bt_ref.st_mtimespec))
		complain("case3: btime > mtime at creation "
			 "(btime %lld.%09ld mtime %lld.%09ld)",
			 (long long)bt_ref.st_birthtimespec.tv_sec,
			 (long)bt_ref.st_birthtimespec.tv_nsec,
			 (long long)bt_ref.st_mtimespec.tv_sec,
			 (long)bt_ref.st_mtimespec.tv_nsec);
	if (!ts_le(&bt_ref.st_birthtimespec, &bt_ref.st_ctimespec))
		complain("case3: btime > ctime at creation");
}

static void case_btime_stable_utimensat(void)
{
	if (bt_ref.st_birthtimespec.tv_sec <= 0)
		return;
	struct timespec back[2] = {
		{ .tv_sec = bt_wall.tv_sec - 3600, .tv_nsec = 0 },
		{ .tv_sec = bt_wall.tv_sec - 3600, .tv_nsec = 0 },
	};
	if (utimensat(AT_FDCWD, bt_name, back, 0) != 0) {
		if (!Sflag)
			printf("NOTE: %s: utimensat backdate failed (%s); "
			       "skipping case4\n", myname, strerror(errno));
		return;
	}
	struct stat st2;
	if (lstat(bt_name, &st2) != 0) {
		complain("case4: lstat: %s", strerror(errno));
		return;
	}
	if (st2.st_birthtimespec.tv_sec <= 0) {
		complain("case4: btime missing after utimensat");
	} else if (st2.st_birthtimespec.tv_sec
			   != bt_ref.st_birthtimespec.tv_sec
		   || st2.st_birthtimespec.tv_nsec
			      != bt_ref.st_birthtimespec.tv_nsec) {
		complain("case4: btime shifted under utimensat "
			 "(%lld.%09ld -> %lld.%09ld)",
			 (long long)bt_ref.st_birthtimespec.tv_sec,
			 (long)bt_ref.st_birthtimespec.tv_nsec,
			 (long long)st2.st_birthtimespec.tv_sec,
			 (long)st2.st_birthtimespec.tv_nsec);
	}
}

static void case_btime_stable_reopen(void)
{
	if (bt_ref.st_birthtimespec.tv_sec <= 0)
		return;
	int fd2 = open(bt_name, O_RDONLY);
	if (fd2 < 0) {
		complain("case5: reopen: %s", strerror(errno));
		return;
	}
	close(fd2);
	struct stat st3;
	if (lstat(bt_name, &st3) != 0)
		return;
	if (st3.st_birthtimespec.tv_sec > 0
	    && (st3.st_birthtimespec.tv_sec
		!= bt_ref.st_birthtimespec.tv_sec
		|| st3.st_birthtimespec.tv_nsec
		   != bt_ref.st_birthtimespec.tv_nsec))
		complain("case5: btime shifted across close/open");
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
		"lstat(st_birthtim) -> NFSv4.2 time_create (RFC 7862 S12.2)");
	cd_or_skip(myname, dir, Nflag);

	int fd = scratch_open("t_btime", bt_name, sizeof(bt_name));
	close(fd); /* we just need the file to exist */

	clock_gettime(CLOCK_REALTIME, &bt_wall);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_btime_present", case_btime_present());
	RUN_CASE("case_btime_plausible", case_btime_plausible());
	RUN_CASE("case_btime_le_mctime", case_btime_le_mctime());
	RUN_CASE("case_btime_stable_utimensat",
		 case_btime_stable_utimensat());
	RUN_CASE("case_btime_stable_reopen", case_btime_stable_reopen());

	unlink(bt_name);

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}

#else /* __linux__ */

#if !defined(STATX_BTIME)
/* Very old glibc without statx support. */
int main(void)
{
	skip("%s: STATX_BTIME not defined in this glibc/kernel header",
	     myname);
	return TEST_SKIP;
}
#else

/* Shared state, set by case 1 and read by cases 2-5. */
static char       bt_name[64];
static struct timespec bt_wall;
static struct statx bt_ref;

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise statx(STATX_BTIME) -> NFSv4.2 time_create "
		"(RFC 7862 S12.2)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

/*
 * do_statx -- thin wrapper that complains on error and returns -1.
 * On success fills *out and returns 0.
 */
static int do_statx(const char *path, unsigned mask, struct statx *out,
		    const char *ctx)
{
	if (statx(AT_FDCWD, path, 0, mask, out) != 0) {
		complain("%s: statx: %s", ctx, strerror(errno));
		return -1;
	}
	return 0;
}

/*
 * ts_le -- returns true if a <= b for statx timestamps.
 */
static int ts_le(const struct statx_timestamp *a,
		 const struct statx_timestamp *b)
{
	if (a->tv_sec != b->tv_sec)
		return a->tv_sec < b->tv_sec;
	return a->tv_nsec <= b->tv_nsec;
}

static void case_btime_present(void)
{
	if (do_statx(bt_name,
		     STATX_BTIME | STATX_MTIME | STATX_CTIME,
		     &bt_ref, "case1") < 0)
		return;
	if (!(bt_ref.stx_mask & STATX_BTIME)) {
		/*
		 * Server or FS does not surface time_create.  Not a
		 * failure.  Unlink scratch before skip() (which exits)
		 * so we don't leave litter behind.
		 */
		unlink(bt_name);
		skip("%s: server did not return STATX_BTIME "
		     "(time_create not advertised)", myname);
	}
}

static void case_btime_plausible(void)
{
	if (!(bt_ref.stx_mask & STATX_BTIME))
		return;
	time_t btime = bt_ref.stx_btime.tv_sec;
	time_t delta = btime >= bt_wall.tv_sec
			       ? btime - bt_wall.tv_sec
			       : bt_wall.tv_sec - btime;
	if (delta > 60)
		complain("case2: btime %lld is %lld s from wall %lld "
			 "(> 60s window)",
			 (long long)btime, (long long)delta,
			 (long long)bt_wall.tv_sec);
}

static void case_btime_le_mctime(void)
{
	if (!(bt_ref.stx_mask & STATX_BTIME))
		return;
	if (bt_ref.stx_mask & STATX_MTIME) {
		if (!ts_le(&bt_ref.stx_btime, &bt_ref.stx_mtime))
			complain("case3: btime > mtime at creation "
				 "(btime %lld.%09u mtime %lld.%09u)",
				 (long long)bt_ref.stx_btime.tv_sec,
				 bt_ref.stx_btime.tv_nsec,
				 (long long)bt_ref.stx_mtime.tv_sec,
				 bt_ref.stx_mtime.tv_nsec);
	}
	if (bt_ref.stx_mask & STATX_CTIME) {
		if (!ts_le(&bt_ref.stx_btime, &bt_ref.stx_ctime))
			complain("case3: btime > ctime at creation");
	}
}

static void case_btime_stable_utimensat(void)
{
	if (!(bt_ref.stx_mask & STATX_BTIME))
		return;
	struct timespec back[2] = {
		{ .tv_sec = bt_wall.tv_sec - 3600, .tv_nsec = 0 },
		{ .tv_sec = bt_wall.tv_sec - 3600, .tv_nsec = 0 },
	};
	if (utimensat(AT_FDCWD, bt_name, back, 0) != 0) {
		if (!Sflag)
			printf("NOTE: %s: utimensat backdate failed (%s); "
			       "skipping case4\n", myname, strerror(errno));
		return;
	}
	struct statx st2;
	if (do_statx(bt_name, STATX_BTIME, &st2, "case4") < 0)
		return;
	if (!(st2.stx_mask & STATX_BTIME)) {
		complain("case4: btime missing after utimensat");
	} else if (st2.stx_btime.tv_sec != bt_ref.stx_btime.tv_sec
		   || st2.stx_btime.tv_nsec != bt_ref.stx_btime.tv_nsec) {
		complain("case4: btime shifted under utimensat "
			 "(%lld.%09u -> %lld.%09u)",
			 (long long)bt_ref.stx_btime.tv_sec,
			 bt_ref.stx_btime.tv_nsec,
			 (long long)st2.stx_btime.tv_sec,
			 st2.stx_btime.tv_nsec);
	}
}

static void case_btime_stable_reopen(void)
{
	if (!(bt_ref.stx_mask & STATX_BTIME))
		return;
	int fd2 = open(bt_name, O_RDONLY);
	if (fd2 < 0) {
		complain("case5: reopen: %s", strerror(errno));
		return;
	}
	close(fd2);
	struct statx st3;
	if (do_statx(bt_name, STATX_BTIME, &st3, "case5") < 0)
		return;
	if ((st3.stx_mask & STATX_BTIME)
	    && (st3.stx_btime.tv_sec != bt_ref.stx_btime.tv_sec
		|| st3.stx_btime.tv_nsec != bt_ref.stx_btime.tv_nsec))
		complain("case5: btime shifted across close/open");
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
		"statx(STATX_BTIME) -> NFSv4.2 time_create (RFC 7862 S12.2)");
	cd_or_skip(myname, dir, Nflag);

	int fd = scratch_open("t_btime", bt_name, sizeof(bt_name));
	close(fd); /* we just need the file to exist */

	clock_gettime(CLOCK_REALTIME, &bt_wall);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_btime_present", case_btime_present());
	RUN_CASE("case_btime_plausible", case_btime_plausible());
	RUN_CASE("case_btime_le_mctime", case_btime_le_mctime());
	RUN_CASE("case_btime_stable_utimensat",
		 case_btime_stable_utimensat());
	RUN_CASE("case_btime_stable_reopen", case_btime_stable_reopen());

	unlink(bt_name);

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}

#endif /* STATX_BTIME */
#endif /* __linux__ / __FreeBSD__ */
