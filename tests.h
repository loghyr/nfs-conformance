/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * tests.h -- shared test-harness declarations.
 *
 * Each test binary includes this header for:
 *
 *   - exit-code conventions (PASS=0, FAIL=1, SKIP=77, BUG=99) mirroring
 *     the GNU automake TESTS convention;
 *
 *   - a small common flag set (-h/-s/-t/-f/-n/-d) matching the
 *     Connectathon cthon04 flag shape so anyone coming from that
 *     test suite recognises the command-line grammar;
 *
 *   - the reporting and I/O helpers defined in subr.c.
 *
 * Failure plumbing:
 *   complain() prints "FAIL: ..." to stderr AND sets a shared
 *   test-failed flag inside subr.c.  At end of main() the test calls
 *   finish(testname), which prints "PASS: <name>" and returns
 *   TEST_PASS if the flag is clear, or returns TEST_FAIL silently
 *   otherwise.  No per-test int failed = 0; bookkeeping required.
 */

#ifndef NFSV42_TESTS_H
#define NFSV42_TESTS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>

/* GNU automake TESTS exit-code convention. */
#define TEST_PASS	0
#define TEST_FAIL	1
#define TEST_SKIP	77
#define TEST_BUG	99

/*
 * Common flags, declared by each test and parsed by each test's own
 * argv loop (hand-rolled to match cthon04's -h/-s/-t/-f/-n/-d shape).
 *
 *   Hflag : -h  help requested
 *   Sflag : -s  silent; suppress non-error, non-result output
 *   Tflag : -t  print timing
 *   Fflag : -f  function-only (skip any inner stress / timed loop)
 *   Nflag : -n  do not create the working directory (-d target)
 *
 * -d takes an argument (the working directory / mount point) handled
 * per-test as a const char *.
 */

/*
 * complain -- record a test failure.  Prints "FAIL: " + formatted
 * reason to stderr AND sets the shared test-failed flag.  Returns
 * void so the call site doesn't have to track per-test `failed`
 * variables any more.
 */
void complain(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/*
 * bail -- fatal failure.  Print "FAIL: " + reason, exit TEST_FAIL.
 * Use when continuing makes no sense (e.g. cannot open scratch file).
 */
__attribute__((noreturn, format(printf, 1, 2)))
void bail(const char *fmt, ...);

/*
 * skip -- print "SKIP: " + reason, exit TEST_SKIP.  Use for
 * missing-kernel-feature, missing-syscall, unsupported-filesystem.
 */
__attribute__((noreturn, format(printf, 1, 2)))
void skip(const char *fmt, ...);

/*
 * finish -- end-of-main exit.  If complain() was ever called during
 * this test, return TEST_FAIL (silent; each complain already
 * printed its own FAIL line).  Otherwise print "PASS: <name>"
 * (suppressed when Sflag is set) and return TEST_PASS.
 *
 * Callers use:   return finish(myname);
 */
int finish(const char *testname);

/*
 * prelude -- print "TEST: <name>: <purpose>" unless silent.  Called
 * at the top of main() after flag parsing so log files have a clear
 * "which test / what it does" header.
 */
void prelude(const char *testname, const char *purpose);

/*
 * cd_or_skip -- chdir into dir (creating it first if Nflag == 0 and
 * it is missing).  On any failure, calls skip() so the test does
 * not report FAIL against a mount-point issue it cannot itself fix.
 */
void cd_or_skip(const char *testname, const char *dir, int nflag);

/*
 * pread_all / pwrite_all -- loop over pread/pwrite until `len` bytes
 * have been transferred, or the first short/error.  On short or
 * error, call complain() with a meaningful message including ctx
 * (e.g. "case1: read src prefix") and return -1.  On full transfer
 * return 0.
 *
 * Tests should ALWAYS use these instead of bare pread/pwrite so
 * that silent short-read scenarios don't look like data-corruption
 * FAILs.
 */
int pread_all(int fd, void *buf, size_t len, off_t off, const char *ctx);
int pwrite_all(int fd, const void *buf, size_t len, off_t off,
	       const char *ctx);

/*
 * scratch_open -- create and truncate a scratch file unique to this
 * process.  Name is "<prefix>.<pid>" in the current working directory.
 * On success, out_name (capacity at least 64) receives the name so
 * the test can unlink it later; return value is an O_RDWR fd.  On
 * any failure calls bail().
 */
int scratch_open(const char *prefix, char *out_name, size_t out_name_sz);

/*
 * fill_pattern -- fill buf[0..n) with a deterministic pattern
 * derived from seed, so tests can verify reads by re-running the
 * pattern.
 */
void fill_pattern(unsigned char *buf, size_t n, unsigned seed);

/*
 * check_pattern -- return 0 if buf[0..n) matches fill_pattern(seed),
 * else return (index_of_first_mismatch + 1).  Adding 1 means 0
 * unambiguously says "all match" and any positive value points at
 * the offending byte.
 */
size_t check_pattern(const unsigned char *buf, size_t n, unsigned seed);

/*
 * all_zero -- 1 if every byte in buf[0..n) is 0, else 0.
 */
int all_zero(const unsigned char *buf, size_t n);

#endif /* NFSV42_TESTS_H */
