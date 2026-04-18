/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_change_attr.c -- exercise the observable effects of the NFSv4
 * change attribute (RFC 7530 S5.8.1.4, preserved in RFC 8881 S5.5.1).
 *
 * NFSv4 defines an opaque per-object "change" counter that advances on
 * any content or metadata mutation.  Clients use the counter as their
 * cache-coherency signal: if change_attr is unchanged since the last
 * GETATTR, cached attrs are still valid; if it has advanced, the
 * cache is stale and must be refreshed.
 *
 * Prior versions of this test tried to read the change counter
 * directly via statx(STATX_CHANGE_COOKIE).  That's impossible: the
 * STATX_CHANGE_COOKIE macro exists only in the Linux kernel's
 * internal include/linux/stat.h and is NOT surfaced through the
 * uapi; userspace never sees stx_change_attr.  Every test run on
 * every Linux version will fail a "headers missing" check because
 * no userspace headers will ever define it.  Test the observable
 * effects instead.
 *
 * Cases:
 *
 *   1. Mutation via a separate fd is visible on subsequent stat.
 *      Create and stat a file (caches attrs).  Open a second fd,
 *      pwrite, close.  Re-stat via path -- mtime must have advanced.
 *      Exercises change_attr-driven cache invalidation across the
 *      close-to-open boundary that every NFSv4 mount relies on.
 *
 *   2. Metadata mutation is visible on subsequent stat.  chmod
 *      advances change_attr per RFC 7530 S5.5; the new mode must be
 *      visible to a subsequent stat.
 *
 *   3. Pure reads do NOT appear to mutate the file.  stat, read
 *      content, stat again -- mtime must not advance on the read-only
 *      path.  Catches servers that erroneously bump change_attr or
 *      mtime on access.
 *
 * Portable POSIX; no special mount options required.  Close-to-open
 * and noac variants are covered separately by op_close_to_open and
 * op_noac.
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

/*
 * This test sleeps past a full-second boundary between each before/
 * after pair, so time_t-granularity fields are sufficient.  Using
 * st_mtime / st_ctime keeps the logic portable across POSIX
 * (st_mtim) and Darwin (st_mtimensec/st_mtimespec) layouts without
 * a per-platform shim.
 */

int Hflag = 0;
int Sflag = 0;
int Tflag = 0;
int Fflag = 0;
int Nflag = 0;

static const char *myname = "op_change_attr";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  observable effects of the NFSv4 change attribute\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}


/*
 * Many NFS server backends round timestamps to the nearest second.
 * Pre-stat the scratch file, then wait until the next wall-clock
 * second boundary so a subsequent mutation lands at a distinct
 * integer second.  Keeps case 1 and case 2 from flaking on
 * second-granular backends.
 */
static void sleep_to_next_second(void)
{
	struct timespec now;
	clock_gettime(CLOCK_REALTIME, &now);
	unsigned int ms_to_next = 1000 - (unsigned int)(now.tv_nsec / 1000000U);
	/* Add a 50 ms cushion so we are safely past the boundary. */
	sleep_ms(ms_to_next + 50);
}

static void case_mutation_visible(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_ca.mv.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case1: open: %s", strerror(errno));
		return;
	}
	unsigned char seed[128];
	fill_pattern(seed, sizeof(seed), 0x11);
	if (pwrite_all(fd, seed, sizeof(seed), 0, "case1: seed") != 0) {
		close(fd); unlink(f); return;
	}
	close(fd);

	struct stat st1;
	if (stat(f, &st1) != 0) {
		complain("case1: stat before: %s", strerror(errno));
		unlink(f); return;
	}

	sleep_to_next_second();

	/* Mutate via a SEPARATE fd -- exercises the cache-coherency path
	 * that change_attr is supposed to drive. */
	int fd2 = open(f, O_WRONLY);
	if (fd2 < 0) {
		complain("case1: open writer: %s", strerror(errno));
		unlink(f); return;
	}
	unsigned char extra[64];
	fill_pattern(extra, sizeof(extra), 0x22);
	if (pwrite_all(fd2, extra, sizeof(extra), sizeof(seed),
		       "case1: extend") != 0) {
		close(fd2); unlink(f); return;
	}
	if (close(fd2) != 0) {
		complain("case1: close writer: %s", strerror(errno));
		unlink(f); return;
	}

	struct stat st2;
	if (stat(f, &st2) != 0) {
		complain("case1: stat after: %s", strerror(errno));
		unlink(f); return;
	}

	if (st2.st_size == st1.st_size)
		complain("case1: size did not advance across the write "
			 "(was %lld, still %lld)",
			 (long long)st1.st_size, (long long)st2.st_size);
	if (st2.st_mtime <= st1.st_mtime)
		complain("case1: mtime did not advance across the write "
			 "(%lld -> %lld) -- change_attr-based cache "
			 "invalidation is broken",
			 (long long)st1.st_mtime, (long long)st2.st_mtime);

	unlink(f);
}

static void case_metadata_mutation_visible(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_ca.md.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case2: open: %s", strerror(errno));
		return;
	}
	close(fd);

	struct stat st1;
	if (stat(f, &st1) != 0) {
		complain("case2: stat before: %s", strerror(errno));
		unlink(f); return;
	}

	sleep_to_next_second();

	if (chmod(f, 0600) != 0) {
		complain("case2: chmod: %s", strerror(errno));
		unlink(f); return;
	}

	struct stat st2;
	if (stat(f, &st2) != 0) {
		complain("case2: stat after: %s", strerror(errno));
		unlink(f); return;
	}

	if ((st2.st_mode & 07777) != 0600)
		complain("case2: mode not updated (%04o != 0600)",
			 st2.st_mode & 07777);
	if (st2.st_ctime <= st1.st_ctime)
		complain("case2: ctime did not advance across chmod "
			 "(%lld -> %lld) -- metadata change_attr mutation "
			 "not visible",
			 (long long)st1.st_ctime, (long long)st2.st_ctime);

	unlink(f);
}

static void case_pure_read_no_mutation(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_ca.rd.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case3: open: %s", strerror(errno));
		return;
	}
	unsigned char seed[256];
	fill_pattern(seed, sizeof(seed), 0x33);
	if (pwrite_all(fd, seed, sizeof(seed), 0, "case3: seed") != 0) {
		close(fd); unlink(f); return;
	}
	close(fd);

	struct stat st1;
	if (stat(f, &st1) != 0) {
		complain("case3: stat before: %s", strerror(errno));
		unlink(f); return;
	}

	sleep_to_next_second();

	/* Pure reads: open O_RDONLY, read, close.  Must not advance
	 * mtime.  Atime may advance under strict-atime mounts; we don't
	 * assert on atime here. */
	int rfd = open(f, O_RDONLY);
	if (rfd < 0) {
		complain("case3: open reader: %s", strerror(errno));
		unlink(f); return;
	}
	unsigned char buf[256];
	if (pread_all(rfd, buf, sizeof(buf), 0, "case3: read") != 0) {
		close(rfd); unlink(f); return;
	}
	close(rfd);

	struct stat st2;
	if (stat(f, &st2) != 0) {
		complain("case3: stat after: %s", strerror(errno));
		unlink(f); return;
	}

	if (st2.st_mtime != st1.st_mtime)
		complain("case3: mtime advanced across a pure read "
			 "(%lld -> %lld) -- server or client bumped "
			 "change_attr on access",
			 (long long)st1.st_mtime, (long long)st2.st_mtime);
	if (st2.st_ctime != st1.st_ctime)
		complain("case3: ctime advanced across a pure read "
			 "(%lld -> %lld)",
			 (long long)st1.st_ctime, (long long)st2.st_ctime);

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
		"observable effects of NFSv4 change_attribute (RFC 7530 S5.8.1.4)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_mutation_visible", case_mutation_visible());
	RUN_CASE("case_metadata_mutation_visible",
		 case_metadata_mutation_visible());
	RUN_CASE("case_pure_read_no_mutation",
		 case_pure_read_no_mutation());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
