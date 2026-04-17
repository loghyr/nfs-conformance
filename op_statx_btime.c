/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_statx_btime.c -- exercise statx(STATX_BTIME), which surfaces
 * the NFSv4.2 `time_create` attribute (RFC 7862 S12.2).
 *
 * Cases:
 *
 *   1. Birth time present.  Create file; statx with STATX_BTIME;
 *      verify stx_mask has STATX_BTIME set.  If not, the server or
 *      backing FS does not advertise time_create and we SKIP.
 *
 *   2. Birth time plausible.  stx_btime.tv_sec is within +/- 60
 *      seconds of CLOCK_REALTIME now.  Generous window to tolerate
 *      server clock skew.
 *
 *   3. Birth time <= m/ctime.  At creation, btime, mtime, and ctime
 *      should all be roughly equal; btime should never exceed
 *      mtime or ctime.
 *
 *   4. Birth time stable under utimensat.  Set atime/mtime to a
 *      past value via utimensat; statx again; btime unchanged.
 *      This is the property that makes btime useful -- if btime
 *      shifts every time the user touches the mtime, it's not a
 *      birth time.
 *
 *   5. Birth time stable across close/open.  Close the fd, open
 *      the same path, statx; btime unchanged.
 *
 * Linux-only: statx is a Linux-specific syscall (4.11+).  glibc
 * wraps it.  macOS / FreeBSD do not expose it; stub out.
 */

#define _GNU_SOURCE

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

#if !defined(__linux__)
int main(void)
{
	skip("%s: statx(STATX_BTIME) is Linux-specific (4.11+)", myname);
	return TEST_SKIP;
}
#else

#if !defined(STATX_BTIME)
/* Very old glibc without statx support. */
int main(void)
{
	skip("%s: STATX_BTIME not defined in this glibc/kernel header",
	     myname);
	return TEST_SKIP;
}
#else

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

	char name[64];
	int fd = scratch_open("t_btime", name, sizeof(name));
	close(fd); /* we just need the file to exist */

	/* Record a wall-clock snapshot right after create.  This is the
	 * reference for "plausible btime" below. */
	struct timespec wall;
	clock_gettime(CLOCK_REALTIME, &wall);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	/* Case 1: server returns STATX_BTIME in the mask. */
	struct statx st;
	if (do_statx(name, STATX_BTIME | STATX_MTIME | STATX_CTIME, &st,
		     "case1") < 0)
		goto out;

	if (!(st.stx_mask & STATX_BTIME)) {
		/*
		 * Server or FS does not surface time_create.  Not a
		 * failure -- NFSv4.2 servers are free not to track it,
		 * and the Linux client fills stx_btime only when the
		 * attribute is returned.  Unlink the scratch file before
		 * skip() (which exits) so we don't leave litter behind.
		 */
		unlink(name);
		skip("%s: server did not return STATX_BTIME (time_create "
		     "not advertised)",
		     myname);
	}

	/* Case 2: btime within +/- 60 s of wall clock at create. */
	time_t btime = st.stx_btime.tv_sec;
	time_t delta = btime >= wall.tv_sec
			       ? btime - wall.tv_sec
			       : wall.tv_sec - btime;
	if (delta > 60)
		complain("case2: btime %lld is %lld s from wall %lld "
			 "(> 60s window)",
			 (long long)btime, (long long)delta,
			 (long long)wall.tv_sec);

	/* Case 3: btime <= mtime and btime <= ctime at creation. */
	if (st.stx_mask & STATX_MTIME) {
		if (!ts_le(&st.stx_btime, &st.stx_mtime))
			complain("case3: btime > mtime at creation "
				 "(btime %lld.%09u mtime %lld.%09u)",
				 (long long)st.stx_btime.tv_sec,
				 st.stx_btime.tv_nsec,
				 (long long)st.stx_mtime.tv_sec,
				 st.stx_mtime.tv_nsec);
	}
	if (st.stx_mask & STATX_CTIME) {
		if (!ts_le(&st.stx_btime, &st.stx_ctime))
			complain("case3: btime > ctime at creation");
	}

	/* Case 4: btime stable when mtime/atime are backdated. */
	struct timespec back[2] = {
		{ .tv_sec = wall.tv_sec - 3600, .tv_nsec = 0 },
		{ .tv_sec = wall.tv_sec - 3600, .tv_nsec = 0 },
	};
	if (utimensat(AT_FDCWD, name, back, 0) != 0) {
		if (!Sflag)
			printf("NOTE: %s: utimensat backdate failed "
			       "(%s); skipping case4\n",
			       myname, strerror(errno));
	} else {
		struct statx st2;
		if (do_statx(name, STATX_BTIME, &st2, "case4") == 0) {
			if (!(st2.stx_mask & STATX_BTIME)) {
				complain("case4: btime missing after "
					 "utimensat");
			} else if (st2.stx_btime.tv_sec != st.stx_btime.tv_sec
				   || st2.stx_btime.tv_nsec
					      != st.stx_btime.tv_nsec) {
				complain("case4: btime shifted under "
					 "utimensat (%lld.%09u -> %lld.%09u)",
					 (long long)st.stx_btime.tv_sec,
					 st.stx_btime.tv_nsec,
					 (long long)st2.stx_btime.tv_sec,
					 st2.stx_btime.tv_nsec);
			}
		}
	}

	/* Case 5: btime stable across close/open. */
	int fd2 = open(name, O_RDONLY);
	if (fd2 < 0) {
		complain("case5: reopen: %s", strerror(errno));
		goto out;
	}
	close(fd2);
	struct statx st3;
	if (do_statx(name, STATX_BTIME, &st3, "case5") == 0) {
		if ((st3.stx_mask & STATX_BTIME)
		    && (st3.stx_btime.tv_sec != st.stx_btime.tv_sec
			|| st3.stx_btime.tv_nsec != st.stx_btime.tv_nsec))
			complain("case5: btime shifted across close/open");
	}

out:
	unlink(name);

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}

#endif /* STATX_BTIME */
#endif /* __linux__ */
