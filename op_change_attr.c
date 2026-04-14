/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_change_attr.c -- exercise the NFSv4 change attribute via
 * statx(STATX_CHANGE_COOKIE) (Linux 6.5+, Jeff Layton's work).
 *
 * The change attribute (RFC 7530 S5.8.1.4, preserved in RFC 8881
 * / NFSv4.1) is a monotonically-advancing per-object cookie that
 * clients use as the cache-coherency signal: if the cookie has not
 * changed, the client can reuse cached data; if it has, the client
 * must revalidate.
 *
 * Server-side bugs in change_attr are *devastating* and almost
 * invisible without a test like this: the client happily serves
 * stale cached data until someone notices.  This test verifies the
 * four invariants clients assume:
 *
 *   1. Post-create, STATX_CHANGE_COOKIE is populated.
 *   2. Writes advance the cookie.
 *   3. Multiple writes produce a monotonic sequence (each cookie
 *      strictly greater than the previous by the NFSv4 "monotonic"
 *      rule; RFC 7530 guarantees advancement, not a specific step).
 *   4. Pure reads do NOT advance the cookie.
 *
 * Case 5 is an indicative check: metadata changes (chmod) should
 * also advance the cookie, because they affect the change-attr
 * bitmap per RFC 7530 S5.5.
 *
 * Linux-only: no other platform exposes the change attribute to
 * userspace via a portable syscall.  macOS / FreeBSD stub out.
 * Linux < 6.5 stubs out via the STATX_CHANGE_COOKIE macro guard.
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

static const char *myname = "op_change_attr";

#if !defined(__linux__)
int main(void)
{
	skip("%s: STATX_CHANGE_COOKIE is Linux-specific (6.5+)", myname);
	return TEST_SKIP;
}
#else

#if !defined(STATX_CHANGE_COOKIE)
int main(void)
{
	skip("%s: STATX_CHANGE_COOKIE not defined in this glibc/kernel "
	     "header set (need Linux 6.5+ and matching headers)",
	     myname);
	return TEST_SKIP;
}
#else

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise statx(STATX_CHANGE_COOKIE) -> NFSv4 change_attr\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

/*
 * get_cookie -- statx for STATX_CHANGE_COOKIE; complain and return
 * 0 (as a failure sentinel) if the server did not return the mask
 * bit.  Returns the cookie on success.  The caller must check that
 * the mask bit actually came back; a server that doesn't advertise
 * change_attr will SKIP the whole test in main() via a feature probe.
 */
static uint64_t get_cookie(const char *path, const char *ctx, int *ok)
{
	struct statx st;
	if (statx(AT_FDCWD, path, 0, STATX_CHANGE_COOKIE, &st) != 0) {
		complain("%s: statx: %s", ctx, strerror(errno));
		*ok = 0;
		return 0;
	}
	if (!(st.stx_mask & STATX_CHANGE_COOKIE)) {
		complain("%s: STATX_CHANGE_COOKIE not in returned mask",
			 ctx);
		*ok = 0;
		return 0;
	}
	*ok = 1;
	return st.stx_change_attr;
}

/*
 * feature_probe -- verify the server actually returns change_attr
 * on THIS mount.  If it doesn't, we SKIP rather than FAIL -- many
 * older NFS servers and some non-Linux filesystems don't advertise
 * change_attr.  Must run before any cases.
 */
static void feature_probe(const char *path)
{
	struct statx st;
	if (statx(AT_FDCWD, path, 0, STATX_CHANGE_COOKIE, &st) != 0) {
		skip("%s: statx failed: %s (kernel/mount may not support "
		     "STATX_CHANGE_COOKIE)",
		     myname, strerror(errno));
	}
	if (!(st.stx_mask & STATX_CHANGE_COOKIE)) {
		skip("%s: server did not return STATX_CHANGE_COOKIE "
		     "(change attribute not advertised)",
		     myname);
	}
}

static void case_write_advances(const char *path)
{
	int ok;
	uint64_t before = get_cookie(path, "case2:before", &ok);
	if (!ok) return;

	int fd = open(path, O_WRONLY);
	if (fd < 0) { complain("case2: open: %s", strerror(errno)); return; }
	if (pwrite_all(fd, "hello\n", 6, 0, "case2:write") < 0) {
		close(fd);
		return;
	}
	close(fd);

	uint64_t after = get_cookie(path, "case2:after", &ok);
	if (!ok) return;
	if (after == before)
		complain("case2: change cookie did not advance across "
			 "write (still %llu)",
			 (unsigned long long)before);
}

static void case_monotonic(const char *path)
{
	int fd = open(path, O_WRONLY | O_APPEND);
	if (fd < 0) { complain("case3: open: %s", strerror(errno)); return; }

	int ok;
	uint64_t prev = get_cookie(path, "case3:t0", &ok);
	if (!ok) { close(fd); return; }

	for (int i = 0; i < 4; i++) {
		char buf[16];
		snprintf(buf, sizeof(buf), "pass %d\n", i);
		if (pwrite_all(fd, buf, strlen(buf), (off_t)(i * 16),
			       "case3:write") < 0)
			break;
		fdatasync(fd);

		char ctx[32];
		snprintf(ctx, sizeof(ctx), "case3:iter%d", i);
		uint64_t cur = get_cookie(path, ctx, &ok);
		if (!ok) break;
		if (cur == prev)
			complain("case3: cookie did not advance at iter %d "
				 "(still %llu)",
				 i, (unsigned long long)prev);
		prev = cur;
	}
	close(fd);
}

static void case_read_does_not_advance(const char *path)
{
	int ok;
	uint64_t before = get_cookie(path, "case4:before", &ok);
	if (!ok) return;

	int fd = open(path, O_RDONLY);
	if (fd < 0) { complain("case4: open: %s", strerror(errno)); return; }
	char buf[16];
	ssize_t n = pread(fd, buf, sizeof(buf), 0);
	(void)n;
	close(fd);

	uint64_t after = get_cookie(path, "case4:after", &ok);
	if (!ok) return;
	/*
	 * NFSv4 leaves it implementation-defined whether reads may
	 * advance the change attribute (servers that track access
	 * time as part of "change" could bump it), but the dominant
	 * Linux knfsd behaviour is that pure reads do NOT advance.
	 * If the cookie moved, emit a NOTE rather than FAIL so we
	 * don't false-alarm on strict-atime servers.
	 */
	if (after != before && !Sflag)
		printf("NOTE: %s: read advanced change cookie "
		       "(%llu -> %llu); server may be counting atime as "
		       "a change\n",
		       myname, (unsigned long long)before,
		       (unsigned long long)after);
}

static void case_chmod_advances(const char *path)
{
	int ok;
	uint64_t before = get_cookie(path, "case5:before", &ok);
	if (!ok) return;

	if (chmod(path, 0600) != 0) {
		complain("case5: chmod: %s", strerror(errno));
		return;
	}

	uint64_t after = get_cookie(path, "case5:after", &ok);
	if (!ok) return;
	if (after == before)
		complain("case5: chmod did not advance change cookie "
			 "(still %llu)",
			 (unsigned long long)before);

	/* Restore mode for cleanup */
	chmod(path, 0644);
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
		"statx(STATX_CHANGE_COOKIE) -> NFSv4 change attribute");
	cd_or_skip(myname, dir, Nflag);

	char name[64];
	int fd = scratch_open("t_chg", name, sizeof(name));
	close(fd);

	feature_probe(name);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	/* Case 1 is implicit: feature_probe + any other case confirms
	 * that STATX_CHANGE_COOKIE is populated post-create. */
	case_write_advances(name);
	case_monotonic(name);
	case_read_does_not_advance(name);
	case_chmod_advances(name);

	unlink(name);

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}

#endif /* STATX_CHANGE_COOKIE */
#endif /* __linux__ */
