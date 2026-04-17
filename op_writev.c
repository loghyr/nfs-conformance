/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_writev.c -- exercise vectored I/O: writev(2), readv(2),
 * pwritev(2), preadv(2).
 *
 * POSIX.1-2008 guarantees that a single writev() is equivalent to
 * writing each iovec element in order, atomically with respect to
 * other threads in the same process.  NFS clients translate writev
 * into one or more WRITE RPCs -- the translation is an implementation
 * detail but must preserve byte ordering, aggregate length, and the
 * atomic "all-or-nothing" semantics at the syscall level.  Bugs can
 * lurk in the iovec-to-RPC fragmentation on both the client and the
 * server.
 *
 * Cases:
 *
 *   1. Small writev round-trip: 3 buffers, short.  readv reads back
 *      into a matching iovec; verify each element.
 *
 *   2. Many small iovecs: 16 buffers of 64 bytes each.  writev
 *      returns 1024; readv reads 1024 back into the same shape.
 *
 *   3. Mixed-size writev: buffers of 1 B, 4 KiB, 100 B, 64 KiB, 7 B.
 *      Total crosses typical NFS wsize boundaries.  Data must land
 *      contiguous in the file in the same order as the iovec.
 *
 *   4. pwritev + preadv at arbitrary offset.  Vectored I/O at
 *      offset 1 MiB into a sparse file; verify via pread.
 *
 *   5. writev + read (non-vectored): what writev produces must be
 *      readable as a flat stream.  Tests the writev->WRITE and
 *      read->READ paths interact correctly.
 *
 *   6. Zero-length element in middle: iovec has a 0-length element
 *      between two non-empty ones.  POSIX: zero-length elements
 *      are valid and contribute nothing; total = sum of nonzero.
 *
 * Portable: POSIX.1-2008 writev / readv / pwritev / preadv.
 */

#define _POSIX_C_SOURCE 200809L
#if defined(__APPLE__)
/* macOS: pwritev / preadv are POSIX.1-2008 but gated on _DARWIN_C_SOURCE. */
#define _DARWIN_C_SOURCE
#endif

#include "tests.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

int Hflag = 0;
int Sflag = 0;
int Tflag = 0;
int Fflag = 0;
int Nflag = 0;

static const char *myname = "op_writev";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  vectored I/O: writev / readv / pwritev / preadv\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static int create_scratch(char *out, size_t sz, int casenum)
{
	snprintf(out, sz, "t_wv.%d.%ld", casenum, (long)getpid());
	unlink(out);
	return open(out, O_RDWR | O_CREAT | O_TRUNC, 0644);
}

static void case_small_round_trip(void)
{
	char a[64];
	int fd = create_scratch(a, sizeof(a), 1);
	if (fd < 0) {
		complain("case1: create: %s", strerror(errno));
		return;
	}

	char b1[] = "hello ", b2[] = "brave ", b3[] = "world";
	struct iovec wv[3] = {
		{ b1, sizeof(b1) - 1 },
		{ b2, sizeof(b2) - 1 },
		{ b3, sizeof(b3) - 1 },
	};
	ssize_t w = writev(fd, wv, 3);
	if (w != 17) {
		complain("case1: writev returned %zd (expected 17)", w);
		close(fd); unlink(a); return;
	}
	if (lseek(fd, 0, SEEK_SET) != 0) {
		complain("case1: lseek: %s", strerror(errno));
		close(fd); unlink(a); return;
	}

	char r1[6], r2[6], r3[5];
	struct iovec rv[3] = {
		{ r1, sizeof(r1) },
		{ r2, sizeof(r2) },
		{ r3, sizeof(r3) },
	};
	ssize_t r = readv(fd, rv, 3);
	close(fd);
	unlink(a);

	if (r != 17) {
		complain("case1: readv returned %zd (expected 17)", r);
		return;
	}
	if (memcmp(r1, "hello ", 6) != 0)
		complain("case1: iovec[0] mismatch ('%.6s')", r1);
	if (memcmp(r2, "brave ", 6) != 0)
		complain("case1: iovec[1] mismatch ('%.6s')", r2);
	if (memcmp(r3, "world", 5) != 0)
		complain("case1: iovec[2] mismatch ('%.5s')", r3);
}

static void case_many_small_iovecs(void)
{
	char a[64];
	int fd = create_scratch(a, sizeof(a), 2);
	if (fd < 0) {
		complain("case2: create: %s", strerror(errno));
		return;
	}

	enum { N = 16, EACH = 64 };
	unsigned char src[N][EACH];
	struct iovec wv[N];
	for (int i = 0; i < N; i++) {
		memset(src[i], (unsigned char)(0x40 + i), EACH);
		wv[i].iov_base = src[i];
		wv[i].iov_len = EACH;
	}
	ssize_t w = writev(fd, wv, N);
	if (w != N * EACH) {
		complain("case2: writev returned %zd (expected %d)",
			 w, N * EACH);
		close(fd); unlink(a); return;
	}

	close(fd);
	int rfd = open(a, O_RDONLY);
	if (rfd < 0) {
		complain("case2: reopen: %s", strerror(errno));
		unlink(a); return;
	}

	unsigned char dst[N][EACH];
	struct iovec rv[N];
	for (int i = 0; i < N; i++) {
		rv[i].iov_base = dst[i];
		rv[i].iov_len = EACH;
	}
	ssize_t r = readv(rfd, rv, N);
	close(rfd);
	unlink(a);

	if (r != N * EACH) {
		complain("case2: readv returned %zd (expected %d)",
			 r, N * EACH);
		return;
	}
	for (int i = 0; i < N; i++) {
		for (int j = 0; j < EACH; j++) {
			if (dst[i][j] != (unsigned char)(0x40 + i)) {
				complain("case2: iovec[%d] byte %d = "
					 "0x%02x (expected 0x%02x)",
					 i, j, dst[i][j],
					 (unsigned)(0x40 + i));
				return;
			}
		}
	}
}

static void case_mixed_sizes(void)
{
	char a[64];
	int fd = create_scratch(a, sizeof(a), 3);
	if (fd < 0) {
		complain("case3: create: %s", strerror(errno));
		return;
	}

	size_t sizes[] = { 1, 4096, 100, 65536, 7 };
	size_t total = 0;
	for (size_t i = 0; i < 5; i++) total += sizes[i];

	unsigned char *bufs[5];
	struct iovec wv[5];
	for (size_t i = 0; i < 5; i++) {
		bufs[i] = malloc(sizes[i]);
		if (!bufs[i]) {
			complain("case3: malloc %zu", sizes[i]);
			for (size_t j = 0; j < i; j++) free(bufs[j]);
			close(fd); unlink(a); return;
		}
		memset(bufs[i], (unsigned char)('a' + i), sizes[i]);
		wv[i].iov_base = bufs[i];
		wv[i].iov_len = sizes[i];
	}

	ssize_t w = writev(fd, wv, 5);
	if (w != (ssize_t)total) {
		complain("case3: writev returned %zd (expected %zu)",
			 w, total);
		goto out;
	}

	unsigned char *check = malloc(total);
	if (!check) { complain("case3: malloc check"); goto out; }
	if (pread(fd, check, total, 0) != (ssize_t)total) {
		complain("case3: pread: %s", strerror(errno));
		free(check);
		goto out;
	}
	size_t off = 0;
	for (size_t i = 0; i < 5; i++) {
		if (memcmp(check + off, bufs[i], sizes[i]) != 0) {
			complain("case3: segment %zu (size %zu at "
				 "offset %zu) mismatched -- iovec "
				 "ordering broken",
				 i, sizes[i], off);
			break;
		}
		off += sizes[i];
	}
	free(check);

out:
	for (size_t i = 0; i < 5; i++) free(bufs[i]);
	close(fd);
	unlink(a);
}

static void case_pwritev_preadv(void)
{
	char a[64];
	int fd = create_scratch(a, sizeof(a), 4);
	if (fd < 0) {
		complain("case4: create: %s", strerror(errno));
		return;
	}
	if (ftruncate(fd, 2 * 1024 * 1024) != 0) {
		complain("case4: ftruncate: %s", strerror(errno));
		close(fd); unlink(a); return;
	}

	const off_t off = 1024 * 1024;
	char b1[] = "alpha", b2[] = "beta", b3[] = "gamma";
	struct iovec wv[3] = {
		{ b1, sizeof(b1) - 1 },
		{ b2, sizeof(b2) - 1 },
		{ b3, sizeof(b3) - 1 },
	};
	ssize_t w = pwritev(fd, wv, 3, off);
	if (w != 14) {
		complain("case4: pwritev %zd (expected 14): %s",
			 w, strerror(errno));
		close(fd); unlink(a); return;
	}

	char r1[5], r2[4], r3[5];
	struct iovec rv[3] = {
		{ r1, sizeof(r1) },
		{ r2, sizeof(r2) },
		{ r3, sizeof(r3) },
	};
	ssize_t r = preadv(fd, rv, 3, off);
	close(fd);
	unlink(a);

	if (r != 14) {
		complain("case4: preadv %zd (expected 14)", r);
		return;
	}
	if (memcmp(r1, "alpha", 5) || memcmp(r2, "beta", 4)
	    || memcmp(r3, "gamma", 5))
		complain("case4: pwritev/preadv data mismatch at offset %lld",
			 (long long)off);
}

static void case_writev_plain_read(void)
{
	char a[64];
	int fd = create_scratch(a, sizeof(a), 5);
	if (fd < 0) {
		complain("case5: create: %s", strerror(errno));
		return;
	}
	char b1[] = "ABC", b2[] = "DEFG", b3[] = "HIJKL";
	struct iovec wv[3] = {
		{ b1, 3 }, { b2, 4 }, { b3, 5 },
	};
	ssize_t w = writev(fd, wv, 3);
	if (w != 12) {
		complain("case5: writev %zd", w);
		close(fd); unlink(a); return;
	}
	close(fd);

	int rfd = open(a, O_RDONLY);
	if (rfd < 0) {
		complain("case5: reopen: %s", strerror(errno));
		unlink(a);
		return;
	}
	char buf[13] = {0};
	ssize_t r = read(rfd, buf, sizeof(buf) - 1);
	close(rfd);
	unlink(a);

	if (r != 12 || strcmp(buf, "ABCDEFGHIJKL") != 0)
		complain("case5: flat read after writev got '%s' (expected "
			 "'ABCDEFGHIJKL')", buf);
}

static void case_zero_length_in_middle(void)
{
	char a[64];
	int fd = create_scratch(a, sizeof(a), 6);
	if (fd < 0) {
		complain("case6: create: %s", strerror(errno));
		return;
	}
	/*
	 * POSIX allows iov_base to be invalid when iov_len is 0, but
	 * some older BSDs return EFAULT on NULL + 0.  Use a real
	 * byte to be uniformly safe.
	 */
	char b1[] = "XY", b3[] = "Z";
	char unused_byte = 0;
	struct iovec wv[3] = {
		{ b1, 2 },
		{ &unused_byte, 0 },      /* zero-length; POSIX-legal no-op */
		{ b3, 1 },
	};
	ssize_t w = writev(fd, wv, 3);
	if (w != 3) {
		complain("case6: writev returned %zd (expected 3)", w);
		close(fd); unlink(a); return;
	}
	char got[4] = {0};
	if (pread(fd, got, 3, 0) == 3) {
		if (memcmp(got, "XYZ", 3) != 0)
			complain("case6: got '%s' (expected 'XYZ')", got);
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

	prelude(myname,
		"vectored I/O: writev / readv / pwritev / preadv");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_small_round_trip", case_small_round_trip());
	RUN_CASE("case_many_small_iovecs", case_many_small_iovecs());
	RUN_CASE("case_mixed_sizes", case_mixed_sizes());
	RUN_CASE("case_pwritev_preadv", case_pwritev_preadv());
	RUN_CASE("case_writev_plain_read", case_writev_plain_read());
	RUN_CASE("case_zero_length_in_middle",
		 case_zero_length_in_middle());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
