/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * subr.c -- shared test-harness implementation.
 *
 * Intentionally thin: no threads, no signal handlers, no dynamic
 * state beyond a single file-local int that tracks whether
 * complain() has been called.  Each test binary links subr.o and
 * one test<N>.c / op_<feature>.c source.
 */

#include "tests.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * Shared failure flag.  Set by complain(); read by finish().
 * File-local so tests can't accidentally observe or mutate it.
 */
static int test_failed;

/*
 * Sflag is defined by each test as a file-scope int.  We read it
 * via an extern declaration so that finish() / prelude() can honour
 * -s without each test having to pass the flag in explicitly.
 * Every test in this tree declares `int Sflag = 0;` at file scope.
 */
extern int Sflag;

void complain(const char *fmt, ...)
{
	va_list ap;
	fprintf(stderr, "FAIL: ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	test_failed = 1;
}

void bail(const char *fmt, ...)
{
	va_list ap;
	fprintf(stderr, "FAIL: ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	exit(TEST_FAIL);
}

void skip(const char *fmt, ...)
{
	va_list ap;
	fprintf(stdout, "SKIP: ");
	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
	fprintf(stdout, "\n");
	exit(TEST_SKIP);
}

int finish(const char *testname)
{
	if (test_failed)
		return TEST_FAIL;
	if (!Sflag)
		printf("PASS: %s\n", testname);
	return TEST_PASS;
}

void prelude(const char *testname, const char *purpose)
{
	if (!Sflag)
		printf("TEST: %s: %s\n", testname, purpose);
}

void cd_or_skip(const char *testname, const char *dir, int nflag)
{
	struct stat st;

	if (!dir)
		dir = ".";

	if (stat(dir, &st) != 0) {
		if (nflag) {
			skip("%s: %s does not exist and -n set",
			     testname, dir);
		}
		if (mkdir(dir, 0777) != 0 && errno != EEXIST) {
			skip("%s: cannot mkdir %s: %s", testname, dir,
			     strerror(errno));
		}
		if (stat(dir, &st) != 0) {
			skip("%s: %s still missing after mkdir: %s",
			     testname, dir, strerror(errno));
		}
	}
	if (!S_ISDIR(st.st_mode))
		skip("%s: %s is not a directory", testname, dir);

	if (chdir(dir) != 0)
		skip("%s: cannot chdir %s: %s", testname, dir, strerror(errno));
}

/*
 * pread_all -- read exactly len bytes starting at off.  Handles
 * EINTR and short reads.  On any non-EINTR short/error, complains
 * and returns -1.  On full read returns 0.
 */
int pread_all(int fd, void *buf, size_t len, off_t off, const char *ctx)
{
	unsigned char *p = buf;
	size_t total = 0;

	while (total < len) {
		ssize_t n = pread(fd, p + total, len - total,
				  off + (off_t)total);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			complain("%s: pread at off=%lld len=%zu: %s",
				 ctx, (long long)(off + (off_t)total),
				 len - total, strerror(errno));
			return -1;
		}
		if (n == 0) {
			complain("%s: pread short at off=%lld "
				 "(got %zu of %zu)",
				 ctx, (long long)(off + (off_t)total),
				 total, len);
			return -1;
		}
		total += (size_t)n;
	}
	return 0;
}

/*
 * pwrite_all -- symmetric writer.  Same error semantics as
 * pread_all; we let EINTR retry and complain on any other failure.
 */
int pwrite_all(int fd, const void *buf, size_t len, off_t off, const char *ctx)
{
	const unsigned char *p = buf;
	size_t total = 0;

	while (total < len) {
		ssize_t n = pwrite(fd, p + total, len - total,
				   off + (off_t)total);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			complain("%s: pwrite at off=%lld len=%zu: %s",
				 ctx, (long long)(off + (off_t)total),
				 len - total, strerror(errno));
			return -1;
		}
		if (n == 0) {
			complain("%s: pwrite returned 0 at off=%lld "
				 "(ENOSPC?)",
				 ctx, (long long)(off + (off_t)total));
			return -1;
		}
		total += (size_t)n;
	}
	return 0;
}

/*
 * scratch_open -- create a per-process scratch file in cwd.
 * Name is "<prefix>.<pid>" so parallel runs of the same test in the
 * same directory do not collide.
 */
int scratch_open(const char *prefix, char *out_name, size_t out_name_sz)
{
	int n = snprintf(out_name, out_name_sz, "%s.%ld", prefix,
			 (long)getpid());
	if (n < 0 || (size_t)n >= out_name_sz)
		bail("scratch_open: name buffer too small for prefix %s",
		     prefix);

	int fd = open(out_name, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		bail("scratch_open: open(%s): %s", out_name, strerror(errno));
	return fd;
}

/*
 * Deterministic 32-bit LCG (Numerical Recipes).  Reproducible from a
 * given seed; sufficient to distinguish "data corrupted" from "data
 * wrong" without a crypto RNG.
 */
static unsigned lcg_next(unsigned *s)
{
	*s = *s * 1664525u + 1013904223u;
	return *s;
}

void fill_pattern(unsigned char *buf, size_t n, unsigned seed)
{
	unsigned s = seed ? seed : 1;
	for (size_t i = 0; i < n; i++)
		buf[i] = (unsigned char)(lcg_next(&s) >> 24);
}

size_t check_pattern(const unsigned char *buf, size_t n, unsigned seed)
{
	unsigned s = seed ? seed : 1;
	for (size_t i = 0; i < n; i++) {
		unsigned char want = (unsigned char)(lcg_next(&s) >> 24);
		if (buf[i] != want)
			return i + 1;
	}
	return 0;
}

int all_zero(const unsigned char *buf, size_t n)
{
	for (size_t i = 0; i < n; i++)
		if (buf[i] != 0)
			return 0;
	return 1;
}
