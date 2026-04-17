/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_overwrite.c -- exercise data overwrite patterns.
 *
 * op_read_write case 1 covers the trivial write+read round-trip.
 * op_overwrite covers what happens when subsequent writes modify
 * data that is already present.  NFS clients often coalesce or
 * cache writes; a bug in invalidation can drop an overwrite
 * silently.
 *
 * Every case fdatasyncs between writes and reads so we are
 * observing the server's view of the file, not a stale client
 * page cache.
 *
 * Cases:
 *
 *   1. Full overwrite, same length.  write A (len L), pwrite B at
 *      offset 0 (len L).  read -> all B.
 *
 *   2. Partial middle overwrite.  write AAAAAAAAAA, pwrite BBB at
 *      offset 3.  read -> AAABBBAAAA.
 *
 *   3. Overwrite that extends past original EOF.  write AAAA,
 *      pwrite BBBBBB at offset 2.  read -> AABBBBBB; size = 8.
 *
 *   4. Overwrite at unaligned offset that spans multiple NFS
 *      blocks.  write a pattern of 4 KiB + 4 KiB + 4 KiB = 12
 *      KiB, pwrite a 4 KiB overwrite at offset 2048 (half into
 *      block 0, half into block 1).  Verify the unchanged
 *      regions of blocks 0, 1, and block 2 are intact.
 *
 *   5. Repeated overwrite.  Write A, overwrite with B, overwrite
 *      with C, read.  Only C should remain -- tests that
 *      intermediate writes don't linger in client caches.
 *
 *   6. Overwrite with zeros.  Write A (non-zero), overwrite with
 *      zeros same range.  Data reads back as zeros -- catches
 *      servers that silently drop explicit-zero writes on an
 *      already-allocated block (the buggy-dedup path).
 *
 * Portable: POSIX.1-2008.
 */

#define _POSIX_C_SOURCE 200809L

#include "tests.h"

#include <errno.h>
#include <fcntl.h>
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

static const char *myname = "op_overwrite";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  data overwrite patterns\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static int create_scratch(char *out, size_t sz, int casenum)
{
	snprintf(out, sz, "t_ov.%d.%ld", casenum, (long)getpid());
	unlink(out);
	return open(out, O_RDWR | O_CREAT | O_TRUNC, 0644);
}

static void fsync_or_note(int fd, int casenum)
{
	if (fdatasync(fd) != 0 && !Sflag)
		printf("NOTE: %s: case%d fdatasync: %s\n",
		       myname, casenum, strerror(errno));
}

static void case_full_same_length(void)
{
	char a[64];
	int fd = create_scratch(a, sizeof(a), 1);
	if (fd < 0) {
		complain("case1: create: %s", strerror(errno));
		return;
	}

	char pa[16], pb[16];
	memset(pa, 'A', 16);
	memset(pb, 'B', 16);

	if (pwrite(fd, pa, 16, 0) != 16) {
		complain("case1: pwrite A: %s", strerror(errno));
		close(fd); unlink(a); return;
	}
	fsync_or_note(fd, 1);
	if (pwrite(fd, pb, 16, 0) != 16) {
		complain("case1: pwrite B: %s", strerror(errno));
		close(fd); unlink(a); return;
	}
	fsync_or_note(fd, 1);

	char got[16];
	if (pread(fd, got, 16, 0) != 16)
		complain("case1: pread: %s", strerror(errno));
	else if (memcmp(got, pb, 16) != 0)
		complain("case1: overwrite lost -- file still contains 'A'");

	close(fd);
	unlink(a);
}

static void case_partial_middle(void)
{
	char a[64];
	int fd = create_scratch(a, sizeof(a), 2);
	if (fd < 0) {
		complain("case2: create: %s", strerror(errno));
		return;
	}

	if (pwrite(fd, "AAAAAAAAAA", 10, 0) != 10) {
		complain("case2: pwrite base: %s", strerror(errno));
		close(fd); unlink(a); return;
	}
	fsync_or_note(fd, 2);
	if (pwrite(fd, "BBB", 3, 3) != 3) {
		complain("case2: pwrite overwrite: %s", strerror(errno));
		close(fd); unlink(a); return;
	}
	fsync_or_note(fd, 2);

	char got[11] = {0};
	if (pread(fd, got, 10, 0) != 10)
		complain("case2: pread: %s", strerror(errno));
	else if (memcmp(got, "AAABBBAAAA", 10) != 0)
		complain("case2: got '%.10s' (expected 'AAABBBAAAA')", got);

	close(fd);
	unlink(a);
}

static void case_extends_past_eof(void)
{
	char a[64];
	int fd = create_scratch(a, sizeof(a), 3);
	if (fd < 0) {
		complain("case3: create: %s", strerror(errno));
		return;
	}

	if (pwrite(fd, "AAAA", 4, 0) != 4) {
		complain("case3: pwrite base: %s", strerror(errno));
		close(fd); unlink(a); return;
	}
	fsync_or_note(fd, 3);
	if (pwrite(fd, "BBBBBB", 6, 2) != 6) {
		complain("case3: pwrite extending: %s", strerror(errno));
		close(fd); unlink(a); return;
	}
	fsync_or_note(fd, 3);

	struct stat st;
	if (fstat(fd, &st) != 0)
		complain("case3: fstat: %s", strerror(errno));
	else if (st.st_size != 8)
		complain("case3: size %lld (expected 8)",
			 (long long)st.st_size);

	char got[9] = {0};
	if (pread(fd, got, 8, 0) != 8)
		complain("case3: pread: %s", strerror(errno));
	else if (memcmp(got, "AABBBBBB", 8) != 0)
		complain("case3: got '%.8s' (expected 'AABBBBBB')", got);

	close(fd);
	unlink(a);
}

static void case_unaligned_span(void)
{
	char a[64];
	int fd = create_scratch(a, sizeof(a), 4);
	if (fd < 0) {
		complain("case4: create: %s", strerror(errno));
		return;
	}

	unsigned char base[12 * 1024];
	for (size_t i = 0; i < sizeof(base); i++)
		base[i] = (unsigned char)((i / 4096) + 0x30); /* 0x30,0x31,0x32 */
	if (pwrite(fd, base, sizeof(base), 0) != (ssize_t)sizeof(base)) {
		complain("case4: pwrite base: %s", strerror(errno));
		close(fd); unlink(a); return;
	}
	fsync_or_note(fd, 4);

	unsigned char ow[4096];
	memset(ow, 0xFF, sizeof(ow));
	/* Overwrite [2048, 6144) -- spans boundary at 4096. */
	if (pwrite(fd, ow, sizeof(ow), 2048) != (ssize_t)sizeof(ow)) {
		complain("case4: pwrite overwrite: %s", strerror(errno));
		close(fd); unlink(a); return;
	}
	fsync_or_note(fd, 4);

	unsigned char got[12 * 1024];
	if (pread(fd, got, sizeof(got), 0) != (ssize_t)sizeof(got)) {
		complain("case4: pread: %s", strerror(errno));
		close(fd); unlink(a); return;
	}

	/* Region [0, 2048): block-0 original '0'. */
	for (size_t i = 0; i < 2048; i++)
		if (got[i] != '0') {
			complain("case4: block 0 prefix byte %zu = 0x%02x "
				 "(expected 0x30)", i, got[i]);
			goto out;
		}
	/* Region [2048, 6144): overwrite 0xFF. */
	for (size_t i = 2048; i < 6144; i++)
		if (got[i] != 0xFF) {
			complain("case4: overwrite region byte %zu = 0x%02x "
				 "(expected 0xFF)", i, got[i]);
			goto out;
		}
	/* Region [6144, 8192): block-1 original '1'. */
	for (size_t i = 6144; i < 8192; i++)
		if (got[i] != '1') {
			complain("case4: block 1 suffix byte %zu = 0x%02x "
				 "(expected 0x31)", i, got[i]);
			goto out;
		}
	/* Region [8192, 12288): block-2 original '2'. */
	for (size_t i = 8192; i < 12288; i++)
		if (got[i] != '2') {
			complain("case4: block 2 byte %zu = 0x%02x "
				 "(expected 0x32)", i, got[i]);
			goto out;
		}

out:
	close(fd);
	unlink(a);
}

static void case_repeated(void)
{
	char a[64];
	int fd = create_scratch(a, sizeof(a), 5);
	if (fd < 0) {
		complain("case5: create: %s", strerror(errno));
		return;
	}
	char pa[32], pb[32], pc[32];
	memset(pa, 'A', 32); memset(pb, 'B', 32); memset(pc, 'C', 32);

	if (pwrite(fd, pa, 32, 0) != 32) {
		complain("case5: pwrite A: %s", strerror(errno));
		close(fd); unlink(a); return;
	}
	fsync_or_note(fd, 5);
	if (pwrite(fd, pb, 32, 0) != 32) {
		complain("case5: pwrite B: %s", strerror(errno));
		close(fd); unlink(a); return;
	}
	fsync_or_note(fd, 5);
	if (pwrite(fd, pc, 32, 0) != 32) {
		complain("case5: pwrite C: %s", strerror(errno));
		close(fd); unlink(a); return;
	}
	fsync_or_note(fd, 5);

	char got[32];
	if (pread(fd, got, 32, 0) != 32)
		complain("case5: pread: %s", strerror(errno));
	else if (memcmp(got, pc, 32) != 0)
		complain("case5: final read != 'C' -- an intermediate "
			 "overwrite survived");

	close(fd);
	unlink(a);
}

static void case_overwrite_with_zeros(void)
{
	char a[64];
	int fd = create_scratch(a, sizeof(a), 6);
	if (fd < 0) {
		complain("case6: create: %s", strerror(errno));
		return;
	}
	unsigned char data[4096];
	memset(data, 0xA5, sizeof(data));
	if (pwrite(fd, data, sizeof(data), 0) != (ssize_t)sizeof(data)) {
		complain("case6: pwrite data: %s", strerror(errno));
		close(fd); unlink(a); return;
	}
	fsync_or_note(fd, 6);

	unsigned char zeros[4096] = {0};
	if (pwrite(fd, zeros, sizeof(zeros), 0) != (ssize_t)sizeof(zeros)) {
		complain("case6: pwrite zeros: %s", strerror(errno));
		close(fd); unlink(a); return;
	}
	fsync_or_note(fd, 6);

	unsigned char got[4096];
	if (pread(fd, got, sizeof(got), 0) != (ssize_t)sizeof(got)) {
		complain("case6: pread: %s", strerror(errno));
		close(fd); unlink(a); return;
	}
	for (size_t i = 0; i < sizeof(got); i++) {
		if (got[i] != 0) {
			complain("case6: byte %zu = 0x%02x (expected 0x00) "
				 "-- zero overwrite was dropped; original "
				 "0xA5 survived",
				 i, got[i]);
			break;
		}
	}

	close(fd);
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

	prelude(myname, "data overwrite patterns");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_full_same_length", case_full_same_length());
	RUN_CASE("case_partial_middle", case_partial_middle());
	RUN_CASE("case_extends_past_eof", case_extends_past_eof());
	RUN_CASE("case_unaligned_span", case_unaligned_span());
	RUN_CASE("case_repeated", case_repeated());
	RUN_CASE("case_overwrite_with_zeros",
		 case_overwrite_with_zeros());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
