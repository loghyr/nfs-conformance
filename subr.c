/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
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
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef __linux__
#include <sys/sysmacros.h>
#endif
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

/*
 * TAP13 output mode.
 *
 * Enabled when the environment variable NFSV42_TESTS_TAP is set to a
 * non-empty, non-"0" value.  In TAP mode each test binary emits a
 * self-contained TAP stream:
 *
 *   1..1
 *   # TEST: name: purpose            (from prelude())
 *   # FAIL: reason                   (from each complain())
 *   ok 1 - name                      (from finish(), no complain() fired)
 *   not ok 1 - name                  (from finish(), complain() did fire)
 *   ok 1 - name # SKIP reason        (from skip())
 *   Bail out! reason                 (from bail())
 *
 * Each binary is one TAP test; per-case granularity is left as a future
 * refinement.  This mapping means `prove -j N ./op_*` works directly
 * and parallelism comes from prove, not from the harness.
 *
 * Non-TAP mode is unchanged so existing runtests parsing and human
 * readers see the same "TEST/PASS/FAIL/SKIP" lines as before.
 */
static int tap_mode(void)
{
	static int cached = -1;
	if (cached == -1) {
		const char *e = getenv("NFSV42_TESTS_TAP");
		cached = (e && *e && !(e[0] == '0' && e[1] == '\0')) ? 1 : 0;
	}
	return cached;
}

/*
 * Name captured from prelude() so skip() can emit a TAP description
 * without each skip() caller having to thread the name through.
 */
static const char *tap_name = "test";

/*
 * Case-level TAP state.
 *
 * tap_cases_started flips to 1 on the first tap_case_begin() call and
 * tells finish() to emit a delayed "1..N" plan across the cases that
 * ran rather than the legacy "1..1" single-test plan.  tap_case_num
 * is the 1-based index of the next case to emit.  tap_case_failed
 * tracks whether complain() fired since the last tap_case_begin().
 *
 * Outside TAP mode these are still maintained (cheap) so case-level
 * semantics behave identically; only the printf calls are gated.
 */
static int tap_cases_started;
static int tap_case_num;
static int tap_case_failed_flag;
static char tap_case_name[128];

/*
 * tap_emit_header -- write "TAP version 13" exactly once, before any
 * other TAP output.  Called from prelude() and from the first TAP
 * emitter if prelude() was somehow skipped.
 */
static int tap_header_emitted;
static void tap_emit_header(void)
{
	if (tap_mode() && !tap_header_emitted) {
		printf("TAP version 13\n");
		tap_header_emitted = 1;
	}
}

void complain(const char *fmt, ...)
{
	va_list ap;
	if (tap_mode()) {
		tap_emit_header();
		printf("# FAIL: ");
		va_start(ap, fmt);
		vprintf(fmt, ap);
		va_end(ap);
		printf("\n");
		fflush(stdout);
	} else {
		fprintf(stderr, "FAIL: ");
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
		fprintf(stderr, "\n");
	}
	test_failed = 1;
	tap_case_failed_flag = 1;
}

void bail(const char *fmt, ...)
{
	va_list ap;
	if (tap_mode()) {
		tap_emit_header();
		printf("Bail out! ");
		va_start(ap, fmt);
		vprintf(fmt, ap);
		va_end(ap);
		printf("\n");
		fflush(stdout);
	} else {
		fprintf(stderr, "FAIL: ");
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
		fprintf(stderr, "\n");
	}
	exit(TEST_FAIL);
}

void skip(const char *fmt, ...)
{
	va_list ap;
	if (tap_mode()) {
		tap_emit_header();
		/*
		 * TAP 13 allows a "1..0 # SKIP reason" plan to short-
		 * circuit the whole binary; prove reports the binary as
		 * "skipped" without expecting any ok/not ok lines.  Use
		 * that form when no cases have been begun yet; if a case
		 * was mid-flight, emit the skip as a case-level SKIP
		 * inside an ongoing plan.
		 */
		if (tap_cases_started) {
			tap_case_num++;
			printf("ok %d - %s # SKIP ",
			       tap_case_num,
			       tap_case_name[0] ? tap_case_name : tap_name);
			va_start(ap, fmt);
			vprintf(fmt, ap);
			va_end(ap);
			printf("\n");
			/*
			 * Emit the delayed plan before exiting.  Without
			 * this, prove(1) flags the stream as "no plan
			 * found" because the exit() below skips finish().
			 */
			printf("1..%d\n", tap_case_num);
		} else {
			printf("1..0 # SKIP ");
			va_start(ap, fmt);
			vprintf(fmt, ap);
			va_end(ap);
			printf("\n");
		}
		fflush(stdout);
	} else {
		fprintf(stdout, "SKIP: ");
		va_start(ap, fmt);
		vfprintf(stdout, fmt, ap);
		va_end(ap);
		fprintf(stdout, "\n");
	}
	exit(TEST_SKIP);
}

int finish(const char *testname)
{
	if (tap_mode()) {
		tap_emit_header();
		if (tap_cases_started) {
			/* Delayed plan across the cases that ran. */
			printf("1..%d\n", tap_case_num);
		} else {
			/* Legacy: one TAP test per binary. */
			printf("1..1\n%s 1 - %s\n",
			       test_failed ? "not ok" : "ok", testname);
		}
		fflush(stdout);
		return test_failed ? TEST_FAIL : TEST_PASS;
	}
	if (test_failed)
		return TEST_FAIL;
	if (!Sflag)
		printf("PASS: %s\n", testname);
	return TEST_PASS;
}

void prelude(const char *testname, const char *purpose)
{
	tap_name = testname;
	if (tap_mode()) {
		tap_emit_header();
		printf("# TEST: %s: %s\n", testname, purpose);
		fflush(stdout);
	} else if (!Sflag) {
		printf("TEST: %s: %s\n", testname, purpose);
	}
}

void tap_case_begin(const char *name)
{
	tap_cases_started = 1;
	tap_case_failed_flag = 0;
	if (name) {
		size_t n = strlen(name);
		if (n >= sizeof(tap_case_name))
			n = sizeof(tap_case_name) - 1;
		memcpy(tap_case_name, name, n);
		tap_case_name[n] = '\0';
	} else {
		tap_case_name[0] = '\0';
	}
}

void tap_case_end(void)
{
	tap_case_num++;
	if (tap_mode()) {
		tap_emit_header();
		printf("%s %d - %s\n",
		       tap_case_failed_flag ? "not ok" : "ok",
		       tap_case_num,
		       tap_case_name[0] ? tap_case_name : "unnamed");
		fflush(stdout);
	}
	tap_case_failed_flag = 0;
	tap_case_name[0] = '\0';
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

/*
 * mount_has_option -- check whether the filesystem at cwd was mounted
 * with a given option (e.g., "noac", "soft", "vers=4.2").
 *
 * Returns  1 if the option is present in the mount options string.
 * Returns  0 if the option is absent.
 * Returns -1 if mount option detection is not supported (non-Linux).
 *
 * On Linux, parses /proc/self/mountinfo to find the mount entry whose
 * mount point matches cwd (longest prefix match on st_dev).  The
 * "super options" field (field 11+, after the " - " separator) and
 * the "mount options" field (field 6) are both searched.
 */
int mount_has_option(const char *opt)
{
#ifndef __linux__
	(void)opt;
	return -1;
#else
	struct stat st_cwd;
	if (stat(".", &st_cwd) != 0)
		return -1;

	FILE *fp = fopen("/proc/self/mountinfo", "r");
	if (!fp)
		return -1;

	char line[4096];
	int found = -1;

	while (fgets(line, sizeof(line), fp)) {
		/*
		 * mountinfo format (space-separated):
		 *   0: mount_id
		 *   1: parent_id
		 *   2: major:minor
		 *   3: root
		 *   4: mount_point
		 *   5: mount_options
		 *   6..N-1: optional fields (tag:value)
		 *   N: separator "-"
		 *   N+1: fs_type
		 *   N+2: mount_source
		 *   N+3: super_options
		 */
		unsigned int major, minor;
		char mount_point[2048];
		char mount_opts[2048];

		if (sscanf(line, "%*d %*d %u:%u %*s %2047s %2047s",
			   &major, &minor, mount_point, mount_opts) < 4)
			continue;

		dev_t dev = makedev(major, minor);
		if (dev != st_cwd.st_dev)
			continue;

		/* Check mount_options (field 6). */
		char search[256];
		snprintf(search, sizeof(search), "%s", opt);

		char *p = mount_opts;
		char *tok;
		while ((tok = strsep(&p, ",")) != NULL) {
			if (strcmp(tok, search) == 0) {
				found = 1;
				goto done;
			}
		}

		/* Check super_options (after " - " separator). */
		char *sep = strstr(line, " - ");
		if (sep) {
			char *super = sep + 3;
			/* Skip fs_type and mount_source. */
			char *sp1 = strchr(super, ' ');
			if (sp1) {
				char *sp2 = strchr(sp1 + 1, ' ');
				if (sp2) {
					sp2++;
					/* sp2 points at super_options. */
					char so[2048];
					snprintf(so, sizeof(so), "%s", sp2);
					/* Remove trailing newline. */
					char *nl = strchr(so, '\n');
					if (nl) *nl = '\0';

					char *q = so;
					while ((tok = strsep(&q, ",")) != NULL) {
						if (strcmp(tok, search) == 0) {
							found = 1;
							goto done;
						}
					}
				}
			}
		}

		found = 0;
		break;
	}

done:
	fclose(fp);
	return found;
#endif
}

/*
 * mount_get_option_value -- extract the numeric value of a key=value
 * mount option (e.g., "rsize" -> 1048576).
 *
 * Returns the value on success, 0 if not found, -1 if unsupported.
 */
long mount_get_option_value(const char *key)
{
#ifndef __linux__
	(void)key;
	return -1;
#else
	struct stat st_cwd;
	if (stat(".", &st_cwd) != 0)
		return -1;

	FILE *fp = fopen("/proc/self/mountinfo", "r");
	if (!fp)
		return -1;

	char line[4096];
	long result = 0;
	size_t keylen = strlen(key);

	while (fgets(line, sizeof(line), fp)) {
		unsigned int major, minor;
		char mount_opts[2048];

		if (sscanf(line, "%*d %*d %u:%u %*s %*s %2047s",
			   &major, &minor, mount_opts) < 3)
			continue;

		dev_t dev = makedev(major, minor);
		if (dev != st_cwd.st_dev)
			continue;

		/* Search mount_options and super_options for key=value. */
		char *sources[2] = { mount_opts, NULL };

		char *sep = strstr(line, " - ");
		if (sep) {
			char *sp1 = strchr(sep + 3, ' ');
			if (sp1) {
				char *sp2 = strchr(sp1 + 1, ' ');
				if (sp2) {
					sp2++;
					char *nl = strchr(sp2, '\n');
					if (nl) *nl = '\0';
					sources[1] = sp2;
				}
			}
		}

		for (int s = 0; s < 2; s++) {
			if (!sources[s]) continue;
			char buf[2048];
			snprintf(buf, sizeof(buf), "%s", sources[s]);
			char *p = buf;
			char *tok;
			while ((tok = strsep(&p, ",")) != NULL) {
				if (strncmp(tok, key, keylen) == 0 &&
				    tok[keylen] == '=') {
					result = strtol(tok + keylen + 1,
							NULL, 10);
					goto done;
				}
			}
		}
		break;
	}

done:
	fclose(fp);
	return result;
#endif
}
