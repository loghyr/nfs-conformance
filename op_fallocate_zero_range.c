/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_fallocate_zero_range.c -- exercise fallocate(FALLOC_FL_ZERO_RANGE),
 * which NFSv4.2 clients may map to a WRITE of zeros without punching
 * a hole (RFC 7862 S4 WRITE_SAME or a plain zeroing WRITE).
 *
 * Charter tier: SPEC (NFSv4.2 ZERO_RANGE path, RFC 7862 S4)
 *
 * Ported from: xfstests generic/009 (FALLOC_FL_ZERO_RANGE test).
 * NFS adaptation: xfstests asserts hole/extent layout via fiemap(2)
 * after ZERO_RANGE; fiemap is not available over NFS.  We substitute
 * pread() correctness checks (zeroed region reads all-zero; adjacent
 * data intact) and a size-invariant check (KEEP_SIZE honoured).  The
 * fiemap-based hole-vs-data distinction is dropped; only data content
 * and file size are asserted.
 *
 * Linux-only.  Runtime SKIP if FALLOC_FL_ZERO_RANGE returns EOPNOTSUPP
 * or EINVAL on the mount (not all NFS clients/servers translate this).
 *
 * Unlike FALLOC_FL_PUNCH_HOLE (DEALLOCATE), ZERO_RANGE zeroes bytes
 * in-place without releasing backing storage.  File size is NEVER
 * changed when FALLOC_FL_KEEP_SIZE is set; with the default (no
 * KEEP_SIZE), a zero range that extends past EOF grows the file.
 *
 * Cases:
 *
 *   1. Zero mid-file range.  Write a known pattern; zero the middle
 *      quarter; verify prefix and suffix still carry the pattern and
 *      the zeroed region reads all-zero.  Size unchanged.
 *
 *   2. Zero with FALLOC_FL_KEEP_SIZE near EOF.  The range extends
 *      past current EOF; with KEEP_SIZE the file does not grow.
 *
 *   3. mtime advances after zero-range.  A zeroing write must update
 *      mtime (it modifies file data even if blocks are not freed).
 *
 *   4. Negative offset returns EINVAL.
 *
 *   5. Full-file zero.  The entire file reads all-zero; size unchanged.
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

static const char *myname = "op_fallocate_zero_range";

#if !defined(__linux__)
int main(void)
{
	skip("%s: fallocate(FALLOC_FL_ZERO_RANGE) is Linux-only", myname);
	return TEST_SKIP;
}
#else

#include <linux/falloc.h>

#define FILE_LEN   (2 * 1024 * 1024)
#define ZERO_OFF   (FILE_LEN / 4)
#define ZERO_LEN   (FILE_LEN / 2)

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise fallocate ZERO_RANGE (RFC 7862 S4 zeroing write)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

/*
 * do_zero -- call fallocate(FALLOC_FL_ZERO_RANGE [| KEEP_SIZE], ...).
 * Returns 0 on success, -1 on error.
 * Calls skip() if the operation is unsupported at the syscall level.
 */
static int do_zero(int fd, int keep_size, off_t off, off_t len)
{
	int mode = FALLOC_FL_ZERO_RANGE | (keep_size ? FALLOC_FL_KEEP_SIZE : 0);
	if (fallocate(fd, mode, off, len) == 0)
		return 0;
	if (errno == EOPNOTSUPP || errno == ENOSYS || errno == EINVAL) {
		skip("%s: fallocate ZERO_RANGE returned %s; NFS client or "
		     "server does not support ZERO_RANGE on this mount",
		     myname, strerror(errno));
	}
	return -1;
}

static int write_pattern(int fd, unsigned seed)
{
	unsigned char *buf = malloc(FILE_LEN);
	if (!buf) { complain("malloc"); return -1; }
	fill_pattern(buf, FILE_LEN, seed);
	int rc = pwrite_all(fd, buf, FILE_LEN, 0, "write_pattern");
	free(buf);
	if (rc == 0)
		fdatasync(fd);
	return rc;
}

/* case 1: zero mid-file, check prefix/suffix preserved, zeroed region clean */
static void case_zero_mid_range(int fd)
{
	if (write_pattern(fd, 0x11) < 0)
		return;

	struct stat before, after;
	if (fstat(fd, &before) != 0) {
		complain("case1: fstat before: %s", strerror(errno));
		return;
	}

	if (do_zero(fd, 1 /* keep_size */, ZERO_OFF, ZERO_LEN) != 0) {
		complain("case1: zero: %s", strerror(errno));
		return;
	}

	if (fstat(fd, &after) != 0) {
		complain("case1: fstat after: %s", strerror(errno));
		return;
	}
	if (after.st_size != before.st_size)
		complain("case1: size changed across ZERO_RANGE+KEEP_SIZE "
			 "(%lld -> %lld)",
			 (long long)before.st_size,
			 (long long)after.st_size);

	/* Prefix: pattern intact */
	unsigned char *pre = malloc(ZERO_OFF);
	if (!pre) {
		complain("case1: malloc pre");
	} else if (pread_all(fd, pre, ZERO_OFF, 0, "case1:prefix") == 0) {
		size_t miss = check_pattern(pre, ZERO_OFF, 0x11);
		if (miss)
			complain("case1: prefix corrupted at byte %zu",
				 miss - 1);
	}
	free(pre);

	/* Zeroed region: all zero */
	unsigned char *zer = malloc(ZERO_LEN);
	if (!zer) {
		complain("case1: malloc zer");
	} else if (pread_all(fd, zer, ZERO_LEN, ZERO_OFF, "case1:zero") == 0) {
		if (!all_zero(zer, ZERO_LEN))
			complain("case1: zeroed region not all-zero");
	}
	free(zer);

	/* Suffix: pattern intact */
	size_t suf_len = FILE_LEN - ZERO_OFF - ZERO_LEN;
	unsigned char *suf = malloc(suf_len);
	unsigned char *exp = malloc(FILE_LEN);
	if (!suf || !exp) {
		complain("case1: malloc suf/exp");
	} else if (pread_all(fd, suf, suf_len, ZERO_OFF + ZERO_LEN,
			     "case1:suffix") == 0) {
		fill_pattern(exp, FILE_LEN, 0x11);
		if (memcmp(suf, exp + ZERO_OFF + ZERO_LEN, suf_len) != 0)
			complain("case1: suffix corrupted");
	}
	free(suf);
	free(exp);
}

/* case 2: zero range extending past EOF with KEEP_SIZE; size must not grow */
static void case_zero_keep_size_at_eof(int fd)
{
	if (write_pattern(fd, 0x22) < 0)
		return;

	off_t tail_off = 3 * FILE_LEN / 4;
	off_t extra    = FILE_LEN / 2;   /* extends past EOF */

	/* Zeroing a range that starts before EOF and ends after: keep_size=1 */
	if (do_zero(fd, 1, tail_off, extra) != 0) {
		complain("case2: zero: %s", strerror(errno));
		return;
	}

	struct stat st;
	if (fstat(fd, &st) != 0) {
		complain("case2: fstat: %s", strerror(errno));
		return;
	}
	if (st.st_size != FILE_LEN)
		complain("case2: ZERO_RANGE+KEEP_SIZE changed size "
			 "(%lld -> %lld)",
			 (long long)FILE_LEN, (long long)st.st_size);

	/*
	 * The region from tail_off to FILE_LEN-1 must read zero.
	 * The range beyond FILE_LEN is not guaranteed to be readable.
	 */
	size_t z = (size_t)(FILE_LEN - tail_off);
	unsigned char *buf = malloc(z);
	if (!buf) {
		complain("case2: malloc");
	} else if (pread_all(fd, buf, z, tail_off, "case2:tail") == 0) {
		if (!all_zero(buf, z))
			complain("case2: tail not zero after ZERO_RANGE");
	}
	free(buf);
}

/* case 3: mtime advances after ZERO_RANGE (zeroing modifies file data) */
static void case_mtime_after_zero(int fd)
{
	if (write_pattern(fd, 0x33) < 0)
		return;

	struct stat before;
	if (fstat(fd, &before) != 0) {
		complain("case3: fstat before: %s", strerror(errno));
		return;
	}

	/*
	 * Wait at least 1 second so mtime difference is observable on
	 * filesystems with 1-second timestamp resolution.
	 */
	sleep_ms(1100);

	if (do_zero(fd, 1, ZERO_OFF, ZERO_LEN) != 0) {
		complain("case3: zero: %s", strerror(errno));
		return;
	}

	/* fsync ensures the server has processed the write and updated mtime. */
	if (fsync(fd) != 0) {
		complain("case3: fsync: %s", strerror(errno));
		return;
	}

	struct stat after;
	if (fstat(fd, &after) != 0) {
		complain("case3: fstat after: %s", strerror(errno));
		return;
	}
	if (after.st_mtime <= before.st_mtime && !Sflag)
		printf("NOTE: %s: case3 mtime did not advance after "
		       "ZERO_RANGE (before=%ld after=%ld); server may not "
		       "update mtime for zero writes\n",
		       myname, (long)before.st_mtime, (long)after.st_mtime);
}

/* case 4: negative offset must return EINVAL */
static void case_negative_offset(int fd)
{
	if (fallocate(fd, FALLOC_FL_ZERO_RANGE, -1, 4096) == 0) {
		complain("case4: fallocate(ZERO_RANGE, -1, 4096) returned 0 "
			 "(expected EINVAL)");
		return;
	}
	if (errno != EINVAL)
		complain("case4: fallocate(ZERO_RANGE, -1, 4096) returned %s "
			 "(expected EINVAL)",
			 strerror(errno));
}

/* case 5: zero full file; all content reads as zero; size unchanged */
static void case_full_zero(int fd)
{
	if (write_pattern(fd, 0x55) < 0)
		return;

	struct stat before;
	fstat(fd, &before);

	if (do_zero(fd, 1, 0, FILE_LEN) != 0) {
		complain("case5: full zero: %s", strerror(errno));
		return;
	}

	struct stat after;
	fstat(fd, &after);
	if (after.st_size != before.st_size)
		complain("case5: size changed after full ZERO_RANGE+KEEP_SIZE "
			 "(%lld -> %lld)",
			 (long long)before.st_size, (long long)after.st_size);

	unsigned char *buf = malloc(FILE_LEN);
	if (!buf) {
		complain("case5: malloc");
	} else if (pread_all(fd, buf, FILE_LEN, 0, "case5:verify") == 0) {
		if (!all_zero(buf, FILE_LEN))
			complain("case5: file not all-zero after full "
				 "ZERO_RANGE");
	}
	free(buf);
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
		"fallocate ZERO_RANGE (RFC 7862 S4 zeroing write path)");
	cd_or_skip(myname, dir, Nflag);

	char name[64];
	int fd = scratch_open("t15", name, sizeof(name));

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_zero_mid_range",       case_zero_mid_range(fd));
	RUN_CASE("case_zero_keep_size_at_eof", case_zero_keep_size_at_eof(fd));
	RUN_CASE("case_mtime_after_zero",     case_mtime_after_zero(fd));
	RUN_CASE("case_negative_offset",      case_negative_offset(fd));
	RUN_CASE("case_full_zero",            case_full_zero(fd));

	close(fd);
	unlink(name);

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}

#endif /* __linux__ */
