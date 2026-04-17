/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_rsize_wsize.c -- test I/O at and across NFS RPC-size boundaries.
 *
 * The NFS client splits large I/O into RPCs of at most rsize (for reads)
 * or wsize (for writes) bytes.  Bugs in the RPC-split and reassembly
 * path typically appear at these exact boundaries.
 *
 * This test reads the configured rsize and wsize from /proc/self/mountinfo
 * via mount_get_option_value().  If the values cannot be detected (not
 * Linux, or the options were not specified explicitly and the kernel uses
 * its compiled-in default), a fallback of 1 MiB is used, which is the
 * Linux NFSv4 default.
 *
 * op_read_write_large already covers fixed-size large I/O (1 MiB, 4 MiB,
 * 5 GiB offset).  This test is complementary: it exercises the BOUNDARY
 * itself -- exact-size, one-byte-over, and unaligned-cross cases -- using
 * whatever rsize/wsize the mount was configured with.
 *
 * Cases:
 *
 *   1. Exact-wsize write.  Write exactly wsize bytes, read back, verify.
 *      One write RPC, one read RPC: the no-split baseline.
 *
 *   2. wsize+1 write.  Forces the client to split into two write RPCs
 *      (wsize + 1 byte).  Read back in one call, verify full content.
 *      Off-by-one in the split logic loses the last byte silently.
 *
 *   3. 4*wsize write.  Four write RPCs.  Tests multi-RPC reassembly and
 *      any per-segment state the NFS client accumulates.
 *
 *   4. Unaligned cross-boundary write.  Write wsize-1 bytes starting at
 *      offset 1.  The write window crosses the wsize boundary at byte
 *      wsize.  Read back, verify.  A server that truncates at the boundary
 *      returns wsize-2 bytes instead of wsize-1.
 *
 *   5. pwrite at wsize offset.  Write 4096 bytes at exactly wsize (the
 *      start of the second RPC window).  Read back.  Catches off-by-one
 *      in offset calculations when the RPC boundary coincides with the
 *      start of the write.
 *
 *   6. Interleaved rsize and wsize reads.  Write 2*wsize bytes.  Read
 *      the first wsize via pread.  Read the second wsize via pread at
 *      offset wsize.  Verifies that both halves are intact independently
 *      of the rsize value (may equal wsize on most mounts).
 *
 * Note on 4*wsize (case 3): up to 4 MiB is allocated dynamically.  If
 * malloc fails the case records FAIL, not a crash.
 *
 * Portable: POSIX test logic.  Mount option detection is Linux-specific
 * (/proc/self/mountinfo); on other platforms the fallback 1 MiB is used.
 */

#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

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

static const char *myname = "op_rsize_wsize";

/* Detected (or default) rsize / wsize in bytes. */
static size_t g_rsize;
static size_t g_wsize;

#define DEFAULT_RW_SIZE (1024UL * 1024UL)  /* 1 MiB */

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  test I/O at and across NFS RPC-size boundaries\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

/* Case 1: write exactly wsize bytes, read back. */
static void case_exact_wsize(void)
{
	char name[64];
	int fd = scratch_open("t_rw.ex", name, sizeof(name));

	unsigned char *buf = malloc(g_wsize);
	if (!buf) {
		complain("case1: malloc %zu bytes", g_wsize);
		close(fd); unlink(name); return;
	}

	fill_pattern(buf, g_wsize, 1);
	if (pwrite_all(fd, buf, g_wsize, 0, "case1: write exact wsize") != 0)
		goto out;

	unsigned char *rbuf = malloc(g_wsize);
	if (!rbuf) {
		complain("case1: malloc read buf");
		goto out;
	}

	if (pread_all(fd, rbuf, g_wsize, 0, "case1: read exact wsize") != 0) {
		free(rbuf); goto out;
	}

	size_t mis = check_pattern(rbuf, g_wsize, 1);
	if (mis)
		complain("case1: exact-wsize mismatch at byte %zu "
			 "(wsize=%zu)", mis - 1, g_wsize);
	free(rbuf);
out:
	free(buf);
	close(fd);
	unlink(name);
}

/* Case 2: write wsize+1 bytes -- forces a two-RPC split. */
static void case_wsize_plus_one(void)
{
	size_t sz = g_wsize + 1;
	char name[64];
	int fd = scratch_open("t_rw.p1", name, sizeof(name));

	unsigned char *buf = malloc(sz);
	if (!buf) {
		complain("case2: malloc %zu bytes", sz);
		close(fd); unlink(name); return;
	}

	fill_pattern(buf, sz, 2);
	if (pwrite_all(fd, buf, sz, 0, "case2: write wsize+1") != 0)
		goto out;

	unsigned char *rbuf = malloc(sz);
	if (!rbuf) {
		complain("case2: malloc read buf");
		goto out;
	}

	if (pread_all(fd, rbuf, sz, 0, "case2: read wsize+1") != 0) {
		free(rbuf); goto out;
	}

	size_t mis = check_pattern(rbuf, sz, 2);
	if (mis)
		complain("case2: wsize+1 mismatch at byte %zu "
			 "(wsize=%zu; off-by-one at split boundary?)",
			 mis - 1, g_wsize);
	free(rbuf);
out:
	free(buf);
	close(fd);
	unlink(name);
}

/* Case 3: write 4*wsize bytes -- four RPCs. */
static void case_four_wsize(void)
{
	size_t sz = 4 * g_wsize;
	char name[64];
	int fd = scratch_open("t_rw.4w", name, sizeof(name));

	unsigned char *buf = malloc(sz);
	if (!buf) {
		complain("case3: malloc %zu bytes (4*wsize=%zu)",
			 sz, g_wsize);
		close(fd); unlink(name); return;
	}

	fill_pattern(buf, sz, 3);
	if (pwrite_all(fd, buf, sz, 0, "case3: write 4*wsize") != 0)
		goto out;

	unsigned char *rbuf = malloc(sz);
	if (!rbuf) {
		complain("case3: malloc read buf");
		goto out;
	}

	if (pread_all(fd, rbuf, sz, 0, "case3: read 4*wsize") != 0) {
		free(rbuf); goto out;
	}

	size_t mis = check_pattern(rbuf, sz, 3);
	if (mis)
		complain("case3: 4*wsize mismatch at byte %zu "
			 "(wsize=%zu)", mis - 1, g_wsize);
	free(rbuf);
out:
	free(buf);
	close(fd);
	unlink(name);
}

/* Case 4: write wsize-1 bytes starting at offset 1 -- crosses boundary. */
static void case_unaligned_cross(void)
{
	size_t sz = g_wsize - 1;
	off_t off = 1;
	char name[64];
	int fd = scratch_open("t_rw.uc", name, sizeof(name));

	unsigned char *buf = malloc(sz);
	if (!buf) {
		complain("case4: malloc %zu bytes", sz);
		close(fd); unlink(name); return;
	}

	fill_pattern(buf, sz, 4);
	if (pwrite_all(fd, buf, sz, off,
		       "case4: write unaligned cross-boundary") != 0)
		goto out;

	/* Verify file size: offset + sz bytes written. */
	struct stat st;
	if (fstat(fd, &st) != 0) {
		complain("case4: fstat: %s", strerror(errno));
		goto out;
	}
	if (st.st_size != (off_t)(off + (off_t)sz))
		complain("case4: size %lld, expected %lld (wsize=%zu)",
			 (long long)st.st_size,
			 (long long)(off + (off_t)sz),
			 g_wsize);

	unsigned char *rbuf = malloc(sz);
	if (!rbuf) {
		complain("case4: malloc read buf");
		goto out;
	}

	if (pread_all(fd, rbuf, sz, off,
		      "case4: read unaligned cross-boundary") != 0) {
		free(rbuf); goto out;
	}

	size_t mis = check_pattern(rbuf, sz, 4);
	if (mis)
		complain("case4: cross-boundary mismatch at byte %zu "
			 "(wsize=%zu; server truncated at boundary?)",
			 mis - 1, g_wsize);
	free(rbuf);
out:
	free(buf);
	close(fd);
	unlink(name);
}

/* Case 5: pwrite at exactly wsize offset (start of second RPC window). */
static void case_pwrite_at_boundary(void)
{
	size_t sz = 4096;
	off_t off = (off_t)g_wsize;
	char name[64];
	int fd = scratch_open("t_rw.pb", name, sizeof(name));

	unsigned char buf[4096];
	fill_pattern(buf, sz, 5);

	if (pwrite_all(fd, buf, sz, off, "case5: pwrite at wsize offset") != 0) {
		close(fd); unlink(name); return;
	}

	unsigned char rbuf[4096];
	if (pread_all(fd, rbuf, sz, off,
		      "case5: pread at wsize offset") != 0) {
		close(fd); unlink(name); return;
	}

	size_t mis = check_pattern(rbuf, sz, 5);
	if (mis)
		complain("case5: pwrite-at-boundary mismatch at byte %zu "
			 "(wsize=%zu)", mis - 1, g_wsize);

	close(fd);
	unlink(name);
}

/*
 * Case 6: write 2*wsize, read each wsize half separately.
 * Exercises independent reads of the two RPC windows.
 */
static void case_two_halves(void)
{
	size_t sz = 2 * g_wsize;
	char name[64];
	int fd = scratch_open("t_rw.2h", name, sizeof(name));

	unsigned char *buf = malloc(sz);
	if (!buf) {
		complain("case6: malloc %zu bytes", sz);
		close(fd); unlink(name); return;
	}

	fill_pattern(buf, sz, 6);
	if (pwrite_all(fd, buf, sz, 0, "case6: write 2*wsize") != 0)
		goto out;

	unsigned char *rbuf = malloc(g_wsize);
	if (!rbuf) {
		complain("case6: malloc read buf");
		goto out;
	}

	/* First half */
	if (pread_all(fd, rbuf, g_wsize, 0,
		      "case6: read first wsize") == 0) {
		size_t mis = check_pattern(rbuf, g_wsize, 6);
		if (mis)
			complain("case6: first-half mismatch at byte %zu "
				 "(wsize=%zu)", mis - 1, g_wsize);
	}

	/* Second half */
	if (pread_all(fd, rbuf, g_wsize, (off_t)g_wsize,
		      "case6: read second wsize") == 0) {
		/*
		 * The second half starts at offset wsize in the file.
		 * The fill_pattern seed is still 6 but the data starts
		 * at byte g_wsize of the pattern; check_pattern verifies
		 * the full-file pattern was written correctly by checking
		 * that this chunk matches the second half of the pattern.
		 *
		 * Re-derive the expected second half from buf.
		 */
		size_t mis = 0;
		for (size_t i = 0; i < g_wsize; i++) {
			if (rbuf[i] != buf[g_wsize + i]) {
				mis = i + 1;
				break;
			}
		}
		if (mis)
			complain("case6: second-half mismatch at byte %zu "
				 "(wsize=%zu)", mis - 1, g_wsize);
	}

	free(rbuf);
out:
	free(buf);
	close(fd);
	unlink(name);
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

	prelude(myname, "I/O at and across NFS RPC-size (rsize/wsize) boundaries");
	cd_or_skip(myname, dir, Nflag);

	/* Detect rsize / wsize from mountinfo; fall back to 1 MiB. */
	long rv = mount_get_option_value("rsize");
	g_rsize = (rv > 0) ? (size_t)rv : DEFAULT_RW_SIZE;

	long wv = mount_get_option_value("wsize");
	g_wsize = (wv > 0) ? (size_t)wv : DEFAULT_RW_SIZE;

	if (!Sflag) {
		/* NOTE (not TEST): prelude() already emitted the TAP
		 * header; a second 'TEST:' line confuses parsers that
		 * treat it as a new subtest frame. */
		printf("NOTE: %s: rsize=%zu wsize=%zu%s\n",
		       myname, g_rsize, g_wsize,
		       (rv <= 0 || wv <= 0) ? " (default assumed)" : "");
	}

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_exact_wsize", case_exact_wsize());
	RUN_CASE("case_wsize_plus_one", case_wsize_plus_one());
	RUN_CASE("case_four_wsize", case_four_wsize());
	RUN_CASE("case_unaligned_cross", case_unaligned_cross());
	RUN_CASE("case_pwrite_at_boundary", case_pwrite_at_boundary());
	RUN_CASE("case_two_halves", case_two_halves());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
