/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_deallocate.c -- exercise fallocate(FALLOC_FL_PUNCH_HOLE), which
 * NFSv4.2 servers translate into DEALLOCATE (RFC 7862 S4).
 *
 * Linux-only.  Runtime SKIP on EOPNOTSUPP (backing filesystem does
 * not support punching).
 *
 * Cases:
 *
 *   1. Basic mid-file punch.  Prefix and suffix preserved; punched
 *      region reads as zeros; size unchanged.  st_blocks should
 *      not grow (indicative server-op check).
 *
 *   2. Hole at EOF.  Size unchanged, tail reads zero.
 *
 *   3. Full-file punch.  Size unchanged.  Post-punch file reads all
 *      zero AND st_blocks should be strictly less than pre-punch
 *      (WARN-only -- some backends can't shrink; e.g. tmpfs).
 *
 *   4. Zero-length punch.  Must return 0 (no-op) or EINVAL; the
 *      POSIX fallocate spec is silent about zero length but Linux
 *      documents 0 as invalid for PUNCH_HOLE.  File content and
 *      st_blocks must be unchanged either way.
 *
 *   5. Negative offset / negative length.  Must return EINVAL.
 *      Guards against servers that translate a negative to a huge
 *      unsigned and punch the whole file.
 *
 *   6. Overlapping punches.  Punch [0..64K) then punch [32K..96K).
 *      Post-state: [0..96K) reads zero, [96K..EOF) intact, size
 *      unchanged.  Catches servers that fail the second DEALLOCATE
 *      because of the existing hole, or that incorrectly extend the
 *      first hole's bookkeeping past the second range.
 *
 * PUNCH_HOLE on Linux requires FALLOC_FL_KEEP_SIZE; this is what
 * the NFSv4.2 client translates into DEALLOCATE.
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

static const char *myname = "op_deallocate";

#if !defined(__linux__)
int main(void)
{
	skip("%s: fallocate(FALLOC_FL_PUNCH_HOLE) is Linux-only", myname);
	return TEST_SKIP;
}
#else

#include <linux/falloc.h>

#define FILE_LEN (2 * 1024 * 1024)
#define HOLE_OFF (FILE_LEN / 4)
#define HOLE_LEN (FILE_LEN / 2)

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise fallocate PUNCH_HOLE -> NFSv4.2 DEALLOCATE\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static int punch(int fd, off_t off, off_t len)
{
	int mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
	if (fallocate(fd, mode, off, len) == 0)
		return 0;
	if (errno == EOPNOTSUPP || errno == ENOSYS) {
		skip("%s: fallocate PUNCH_HOLE returned %s; backend does "
		     "not support DEALLOCATE",
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
	return rc;
}

static void case_basic_punch(int fd)
{
	if (write_pattern(fd, 0xAB) < 0)
		return;
	fdatasync(fd);

	struct stat before, after;
	if (fstat(fd, &before) != 0) {
		complain("case1: fstat before: %s", strerror(errno));
		return;
	}

	if (punch(fd, HOLE_OFF, HOLE_LEN) != 0) {
		complain("case1: punch: %s", strerror(errno));
		return;
	}

	if (fstat(fd, &after) != 0) {
		complain("case1: fstat after: %s", strerror(errno));
		return;
	}
	if (after.st_size != before.st_size)
		complain("case1: size changed across PUNCH_HOLE "
			 "(%lld -> %lld)",
			 (long long)before.st_size,
			 (long long)after.st_size);
	if (after.st_blocks > before.st_blocks)
		complain("case1: st_blocks grew across PUNCH_HOLE "
			 "(%lld -> %lld)",
			 (long long)before.st_blocks,
			 (long long)after.st_blocks);

	/* Prefix: pattern intact */
	unsigned char *pre = malloc(HOLE_OFF);
	if (!pre) {
		complain("case1: malloc pre");
	} else if (pread_all(fd, pre, HOLE_OFF, 0, "case1:prefix") == 0) {
		size_t miss = check_pattern(pre, HOLE_OFF, 0xAB);
		if (miss)
			complain("case1: prefix corrupted at byte %zu",
				 miss - 1);
	}
	free(pre);

	/* Hole region: all zero */
	unsigned char *hol = malloc(HOLE_LEN);
	if (!hol) {
		complain("case1: malloc hol");
	} else if (pread_all(fd, hol, HOLE_LEN, HOLE_OFF, "case1:hole") == 0) {
		if (!all_zero(hol, HOLE_LEN))
			complain("case1: punched region not zero");
	}
	free(hol);

	/* Suffix: pattern intact relative to full-file fill */
	size_t suf_len = FILE_LEN - HOLE_OFF - HOLE_LEN;
	unsigned char *suf = malloc(suf_len);
	unsigned char *exp = malloc(FILE_LEN);
	if (!suf || !exp) {
		complain("case1: malloc suf/exp");
	} else if (pread_all(fd, suf, suf_len, HOLE_OFF + HOLE_LEN,
			     "case1:suffix") == 0) {
		fill_pattern(exp, FILE_LEN, 0xAB);
		if (memcmp(suf, exp + HOLE_OFF + HOLE_LEN, suf_len) != 0)
			complain("case1: suffix corrupted");
	}
	free(suf);
	free(exp);
}

static void case_hole_at_eof(int fd)
{
	if (write_pattern(fd, 0x55) < 0)
		return;
	fdatasync(fd);

	off_t tail_off = 3 * FILE_LEN / 4;
	off_t tail_len = FILE_LEN - tail_off;

	if (punch(fd, tail_off, tail_len) != 0) {
		complain("case2: punch: %s", strerror(errno));
		return;
	}

	struct stat st;
	if (fstat(fd, &st) != 0) {
		complain("case2: fstat: %s", strerror(errno));
		return;
	}
	if (st.st_size != FILE_LEN)
		complain("case2: size changed (got %lld expected %lld)",
			 (long long)st.st_size, (long long)FILE_LEN);

	unsigned char *t = malloc(tail_len);
	if (!t) {
		complain("case2: malloc t");
	} else if (pread_all(fd, t, tail_len, tail_off, "case2:tail") == 0) {
		if (!all_zero(t, (size_t)tail_len))
			complain("case2: tail punch region not zero");
	}
	free(t);
}

static void case_full_punch(int fd)
{
	if (write_pattern(fd, 0xF0) < 0)
		return;
	fdatasync(fd);

	struct stat before, after;
	fstat(fd, &before);

	if (punch(fd, 0, FILE_LEN) != 0) {
		complain("case3: punch full: %s", strerror(errno));
		return;
	}

	fstat(fd, &after);
	if (after.st_size != FILE_LEN)
		complain("case3: size changed after full punch");

	/*
	 * st_blocks should shrink substantially after a full punch on
	 * backends that honour DEALLOCATE.  We can't strictly require
	 * "<" because some backends (tmpfs, some NFS servers under
	 * specific configs) don't report block shrinkage.  Emit a
	 * NOTE so operators see it in the log; don't fail.
	 */
	if (after.st_blocks >= before.st_blocks && !Sflag)
		printf("NOTE: %s: case3 full punch did not shrink st_blocks "
		       "(%lld -> %lld); server may be emulating DEALLOCATE "
		       "with WRITE of zeros\n",
		       myname, (long long)before.st_blocks,
		       (long long)after.st_blocks);

	unsigned char *buf = malloc(FILE_LEN);
	if (!buf) {
		complain("case3: malloc buf");
	} else if (pread_all(fd, buf, FILE_LEN, 0, "case3:verify") == 0) {
		if (!all_zero(buf, FILE_LEN))
			complain("case3: file not zero after full punch");
	}
	free(buf);
}

static void case_zero_length_punch(int fd)
{
	if (write_pattern(fd, 0x42) < 0)
		return;
	fdatasync(fd);

	struct stat before, after;
	if (fstat(fd, &before) != 0) {
		complain("case4: fstat before: %s", strerror(errno));
		return;
	}

	int mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
	errno = 0;
	int rc = fallocate(fd, mode, HOLE_OFF, 0);
	int saved = errno;
	if (rc != 0 && saved != EINVAL) {
		if (saved == EOPNOTSUPP || saved == ENOSYS) {
			skip("%s: fallocate returned %s", myname,
			     strerror(saved));
		}
		complain("case4: zero-length punch: expected 0 or EINVAL, "
			 "got %s", strerror(saved));
		return;
	}

	if (fstat(fd, &after) != 0) {
		complain("case4: fstat after: %s", strerror(errno));
		return;
	}
	if (after.st_size != before.st_size)
		complain("case4: size changed across zero-length punch "
			 "(%lld -> %lld)",
			 (long long)before.st_size,
			 (long long)after.st_size);
	if (after.st_blocks != before.st_blocks && !Sflag)
		printf("NOTE: %s: case4 zero-length punch changed "
		       "st_blocks (%lld -> %lld)\n", myname,
		       (long long)before.st_blocks,
		       (long long)after.st_blocks);

	/* Content untouched. */
	unsigned char *buf = malloc(FILE_LEN);
	unsigned char *exp = malloc(FILE_LEN);
	if (!buf || !exp) {
		complain("case4: malloc");
	} else if (pread_all(fd, buf, FILE_LEN, 0, "case4:verify") == 0) {
		fill_pattern(exp, FILE_LEN, 0x42);
		if (memcmp(buf, exp, FILE_LEN) != 0)
			complain("case4: content altered by zero-length punch");
	}
	free(buf);
	free(exp);
}

static void case_negative_offset_or_length(int fd)
{
	if (write_pattern(fd, 0x63) < 0)
		return;
	fdatasync(fd);

	int mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;

	errno = 0;
	if (fallocate(fd, mode, -1, 4096) == 0)
		complain("case5: negative offset accepted (must EINVAL)");
	else if (errno != EINVAL && errno != EOPNOTSUPP && errno != ENOSYS)
		complain("case5: negative offset returned %s (expected EINVAL)",
			 strerror(errno));

	errno = 0;
	if (fallocate(fd, mode, 0, -1) == 0)
		complain("case5: negative length accepted (must EINVAL)");
	else if (errno != EINVAL && errno != EOPNOTSUPP && errno != ENOSYS)
		complain("case5: negative length returned %s (expected EINVAL)",
			 strerror(errno));

	/* Content untouched after the rejected calls. */
	unsigned char *buf = malloc(FILE_LEN);
	unsigned char *exp = malloc(FILE_LEN);
	if (!buf || !exp) {
		complain("case5: malloc");
	} else if (pread_all(fd, buf, FILE_LEN, 0, "case5:verify") == 0) {
		fill_pattern(exp, FILE_LEN, 0x63);
		if (memcmp(buf, exp, FILE_LEN) != 0)
			complain("case5: content altered by rejected punch "
				 "(server translated negative to huge "
				 "unsigned and punched the whole file?)");
	}
	free(buf);
	free(exp);
}

static void case_overlapping_punches(int fd)
{
	if (write_pattern(fd, 0x77) < 0)
		return;
	fdatasync(fd);

	off_t off_a = 0;
	off_t len_a = 64 * 1024;
	off_t off_b = 32 * 1024;
	off_t len_b = 64 * 1024;   /* b ends at 96 K */
	off_t combined_end = off_b + len_b;

	if (punch(fd, off_a, len_a) != 0) {
		complain("case6: first punch: %s", strerror(errno));
		return;
	}
	if (punch(fd, off_b, len_b) != 0) {
		complain("case6: second punch (overlapping): %s",
			 strerror(errno));
		return;
	}

	struct stat st;
	if (fstat(fd, &st) != 0) {
		complain("case6: fstat: %s", strerror(errno));
		return;
	}
	if (st.st_size != FILE_LEN)
		complain("case6: size changed across overlapping punches "
			 "(got %lld expected %lld)",
			 (long long)st.st_size, (long long)FILE_LEN);

	/* Punched union [0..96K) reads zero. */
	unsigned char *z = malloc(combined_end);
	if (!z) {
		complain("case6: malloc z");
	} else if (pread_all(fd, z, (size_t)combined_end, 0,
			     "case6:union") == 0) {
		if (!all_zero(z, (size_t)combined_end))
			complain("case6: union [0..%lld) not zero after "
				 "overlapping punches",
				 (long long)combined_end);
	}
	free(z);

	/* Tail [96K..EOF) still pattern. */
	size_t tail_len = FILE_LEN - combined_end;
	unsigned char *tail = malloc(tail_len);
	unsigned char *exp  = malloc(FILE_LEN);
	if (!tail || !exp) {
		complain("case6: malloc tail/exp");
	} else if (pread_all(fd, tail, tail_len, combined_end,
			     "case6:tail") == 0) {
		fill_pattern(exp, FILE_LEN, 0x77);
		if (memcmp(tail, exp + combined_end, tail_len) != 0)
			complain("case6: tail corrupted past overlapping "
				 "punch union (second punch leaked past "
				 "its length?)");
	}
	free(tail);
	free(exp);
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
		"fallocate PUNCH_HOLE -> NFSv4.2 DEALLOCATE (RFC 7862 S4)");
	cd_or_skip(myname, dir, Nflag);

	char name[64];
	int fd = scratch_open("t14", name, sizeof(name));

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_basic_punch", case_basic_punch(fd));
	RUN_CASE("case_hole_at_eof", case_hole_at_eof(fd));
	RUN_CASE("case_full_punch", case_full_punch(fd));
	RUN_CASE("case_zero_length_punch", case_zero_length_punch(fd));
	RUN_CASE("case_negative_offset_or_length",
		 case_negative_offset_or_length(fd));
	RUN_CASE("case_overlapping_punches",
		 case_overlapping_punches(fd));

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
