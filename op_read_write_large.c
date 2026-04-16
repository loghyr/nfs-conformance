/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_read_write_large.c -- stress-test NFSv4 READ/WRITE with large
 * I/O sizes and file offsets.
 *
 * Existing tests (op_commit, op_copy, etc.) exercise moderate I/O.
 * This test pushes the boundaries that NFS servers sometimes get
 * wrong: maximum single-RPC sizes, multi-megabyte writes, large
 * file offsets (>4 GiB to catch 32-bit truncation), and pattern
 * verification across I/O that spans multiple rsize/wsize chunks.
 *
 * Cases:
 *
 *   1. 1 MiB sequential write + verify.  Write 1 MiB in a single
 *      write(), read back, verify pattern.  Exercises the NFS
 *      client's rsize/wsize chunking.
 *
 *   2. 4 MiB sequential write + verify.  Same but 4 MiB — beyond
 *      typical wsize (1 MiB default on Linux NFS).
 *
 *   3. Large offset write.  Write 4 KiB at offset 5 GiB.  Read
 *      back at the same offset.  Catches 32-bit offset truncation
 *      in the server.  Verify file size is 5 GiB + 4 KiB.
 *
 *   4. Sparse + dense.  Write 4 KiB at offset 0, skip 10 MiB,
 *      write 4 KiB at offset 10 MiB.  Read the hole (should be
 *      zero).  Read both written regions.  Exercises the server's
 *      sparse-file handling.
 *
 *   5. Many small writes.  Write 1024 individual 1-byte writes at
 *      sequential offsets via pwrite.  Read back in one shot.
 *      Catches coalescing bugs in the NFS write path.
 *
 *   6. Unaligned I/O.  Write 4097 bytes at offset 1 (not page-
 *      aligned, not rsize-aligned).  Read back.  NFS clients must
 *      handle unaligned-to-page I/O correctly.
 *
 * Note: case 3 creates a file >5 GiB (sparse, so disk usage is
 * minimal).  Skipped if the filesystem reports < 6 GiB free or
 * if the test mount does not support large files.
 *
 * Portable: POSIX across Linux / FreeBSD / macOS / Solaris.
 */

#define _GNU_SOURCE
#define _DARWIN_C_SOURCE
#define _FILE_OFFSET_BITS 64

#include "tests.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

int Hflag = 0;
int Sflag = 0;
int Tflag = 0;
int Fflag = 0;
int Nflag = 0;

static const char *myname = "op_read_write_large";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  stress-test READ/WRITE with large sizes and offsets\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static void case_1mib(void)
{
	char name[64];
	int fd = scratch_open("t_rwl.1m", name, sizeof(name));

	size_t sz = 1024 * 1024;
	unsigned char *buf = malloc(sz);
	if (!buf) { complain("case1: malloc"); close(fd); unlink(name); return; }

	fill_pattern(buf, sz, 1);
	if (pwrite_all(fd, buf, sz, 0, "case1: write 1MiB") != 0)
		goto out;

	unsigned char *rbuf = malloc(sz);
	if (!rbuf) { complain("case1: malloc read"); goto out; }

	if (pread_all(fd, rbuf, sz, 0, "case1: read 1MiB") != 0) {
		free(rbuf); goto out;
	}

	size_t mis = check_pattern(rbuf, sz, 1);
	if (mis)
		complain("case1: 1MiB mismatch at byte %zu", mis - 1);
	free(rbuf);
out:
	free(buf);
	close(fd);
	unlink(name);
}

static void case_4mib(void)
{
	char name[64];
	int fd = scratch_open("t_rwl.4m", name, sizeof(name));

	size_t sz = 4 * 1024 * 1024;
	unsigned char *buf = malloc(sz);
	if (!buf) { complain("case2: malloc"); close(fd); unlink(name); return; }

	fill_pattern(buf, sz, 2);
	if (pwrite_all(fd, buf, sz, 0, "case2: write 4MiB") != 0)
		goto out;

	unsigned char *rbuf = malloc(sz);
	if (!rbuf) { complain("case2: malloc read"); goto out; }

	if (pread_all(fd, rbuf, sz, 0, "case2: read 4MiB") != 0) {
		free(rbuf); goto out;
	}

	size_t mis = check_pattern(rbuf, sz, 2);
	if (mis)
		complain("case2: 4MiB mismatch at byte %zu", mis - 1);
	free(rbuf);
out:
	free(buf);
	close(fd);
	unlink(name);
}

static void case_large_offset(void)
{
	struct statvfs sv;
	if (statvfs(".", &sv) == 0) {
		unsigned long long avail =
			(unsigned long long)sv.f_bavail * sv.f_bsize;
		if (avail < (6ULL * 1024 * 1024 * 1024)) {
			if (!Sflag)
				printf("NOTE: %s: case3 skipped (< 6 GiB "
				       "free; sparse file may exceed quota)\n",
				       myname);
			return;
		}
	}

	char name[64];
	int fd = scratch_open("t_rwl.lg", name, sizeof(name));

	off_t off = (off_t)5 * 1024 * 1024 * 1024;  /* 5 GiB */
	size_t sz = 4096;
	unsigned char buf[4096];
	fill_pattern(buf, sz, 3);

	if (pwrite_all(fd, buf, sz, off, "case3: write at 5GiB") != 0) {
		close(fd); unlink(name); return;
	}

	struct stat st;
	if (fstat(fd, &st) != 0) {
		complain("case3: fstat: %s", strerror(errno));
		close(fd); unlink(name); return;
	}
	if (st.st_size != off + (off_t)sz)
		complain("case3: size %lld, expected %lld",
			 (long long)st.st_size, (long long)(off + sz));

	unsigned char rbuf[4096];
	if (pread_all(fd, rbuf, sz, off, "case3: read at 5GiB") != 0) {
		close(fd); unlink(name); return;
	}
	size_t mis = check_pattern(rbuf, sz, 3);
	if (mis)
		complain("case3: large-offset mismatch at byte %zu "
			 "(32-bit offset truncation?)", mis - 1);

	close(fd);
	unlink(name);
}

static void case_sparse_dense(void)
{
	char name[64];
	int fd = scratch_open("t_rwl.sd", name, sizeof(name));

	size_t sz = 4096;
	off_t gap = 10 * 1024 * 1024;  /* 10 MiB hole */
	unsigned char buf[4096];

	fill_pattern(buf, sz, 10);
	if (pwrite_all(fd, buf, sz, 0, "case4: write at 0") != 0) {
		close(fd); unlink(name); return;
	}

	fill_pattern(buf, sz, 11);
	if (pwrite_all(fd, buf, sz, gap, "case4: write at 10MiB") != 0) {
		close(fd); unlink(name); return;
	}

	/* Read the hole — should be zero. */
	unsigned char rbuf[4096];
	if (pread_all(fd, rbuf, sz, sz, "case4: read hole") == 0) {
		if (!all_zero(rbuf, sz))
			complain("case4: hole region not zero "
				 "(server sparse-file handling)");
	}

	/* Verify both written regions. */
	if (pread_all(fd, rbuf, sz, 0, "case4: read start") == 0) {
		size_t mis = check_pattern(rbuf, sz, 10);
		if (mis) complain("case4: start mismatch at byte %zu", mis - 1);
	}
	if (pread_all(fd, rbuf, sz, gap, "case4: read 10MiB") == 0) {
		size_t mis = check_pattern(rbuf, sz, 11);
		if (mis) complain("case4: 10MiB mismatch at byte %zu", mis - 1);
	}

	close(fd);
	unlink(name);
}

static void case_many_small(void)
{
	char name[64];
	int fd = scratch_open("t_rwl.ms", name, sizeof(name));

	unsigned char expected[1024];
	for (int i = 0; i < 1024; i++) {
		unsigned char b = (unsigned char)(i ^ 0x5A);
		expected[i] = b;
		if (pwrite(fd, &b, 1, i) != 1) {
			complain("case5: pwrite byte %d: %s", i,
				 strerror(errno));
			close(fd); unlink(name); return;
		}
	}

	unsigned char rbuf[1024];
	if (pread_all(fd, rbuf, 1024, 0, "case5: read back") != 0) {
		close(fd); unlink(name); return;
	}

	if (memcmp(rbuf, expected, 1024) != 0) {
		for (int i = 0; i < 1024; i++) {
			if (rbuf[i] != expected[i]) {
				complain("case5: mismatch at byte %d "
					 "(got 0x%02x, expected 0x%02x) — "
					 "small-write coalescing bug?",
					 i, rbuf[i], expected[i]);
				break;
			}
		}
	}

	close(fd);
	unlink(name);
}

static void case_unaligned(void)
{
	char name[64];
	int fd = scratch_open("t_rwl.ua", name, sizeof(name));

	size_t sz = 4097;
	off_t off = 1;
	unsigned char *buf = malloc(sz);
	if (!buf) { complain("case6: malloc"); close(fd); unlink(name); return; }

	fill_pattern(buf, sz, 6);
	if (pwrite_all(fd, buf, sz, off, "case6: write unaligned") != 0) {
		free(buf); close(fd); unlink(name); return;
	}

	unsigned char *rbuf = malloc(sz);
	if (!rbuf) { complain("case6: malloc read"); free(buf); close(fd); unlink(name); return; }

	if (pread_all(fd, rbuf, sz, off, "case6: read unaligned") != 0) {
		free(rbuf); free(buf); close(fd); unlink(name); return;
	}

	size_t mis = check_pattern(rbuf, sz, 6);
	if (mis)
		complain("case6: unaligned I/O mismatch at byte %zu", mis - 1);

	free(rbuf);
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

	prelude(myname,
		"large READ/WRITE sizes and offsets (>4 GiB, multi-MiB, "
		"unaligned)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_1mib", case_1mib());
	RUN_CASE("case_4mib", case_4mib());
	RUN_CASE("case_large_offset", case_large_offset());
	RUN_CASE("case_sparse_dense", case_sparse_dense());
	RUN_CASE("case_many_small", case_many_small());
	RUN_CASE("case_unaligned", case_unaligned());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
