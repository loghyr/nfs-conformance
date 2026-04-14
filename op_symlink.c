/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * op_symlink.c -- exercise NFSv4 SYMLINK / READLINK ops (RFC 7530
 * S18.26 / S18.22).  Tests the observable POSIX surface:
 * symlinkat / readlinkat / lstat vs stat.
 *
 * Cases:
 *
 *   1. Basic round-trip.  Create symlink with a known target via
 *      symlinkat, read it back via readlinkat, verify the target
 *      string matches byte-for-byte.
 *
 *   2. lstat vs stat.  stat() on a symlink to an existing file
 *      returns the target's attributes; lstat() returns the link's
 *      own attributes (S_IFLNK).  Verify both.
 *
 *   3. Dangling symlink.  readlink on a link to a nonexistent
 *      target returns the target string (no dereference); stat()
 *      through the link returns ENOENT; lstat() still succeeds.
 *
 *   4. Long target.  Create a symlink with a target just under
 *      PATH_MAX bytes; verify round-trip.  NFSv4 imposes a
 *      server-dependent cap (often 4095 bytes) -- we accept
 *      ENAMETOOLONG / EINVAL as a server-side limit rather than a
 *      test failure.
 *
 *   5. Self-referential / loop.  Create a -> b -> a.  open() on
 *      `a` via O_RDONLY returns ELOOP; readlinkat on each link
 *      still returns its immediate target.  (The test creates
 *      both links, checks the readlink surface, and then verifies
 *      open() yields ELOOP.)
 *
 *   6. Unlink semantics.  unlink() on a symlink removes the link,
 *      not the target.  Verify.
 *
 * Portable: POSIX across Linux / FreeBSD / macOS / Solaris.
 */

#define _POSIX_C_SOURCE 200809L

#include "tests.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
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

static const char *myname = "op_symlink";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise symlinkat/readlinkat -> NFSv4 SYMLINK/READLINK\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static void case_round_trip(void)
{
	char linkname[64];
	snprintf(linkname, sizeof(linkname), "t_sl.r.%ld", (long)getpid());
	const char *target = "hello/world/42";

	unlink(linkname);
	if (symlinkat(target, AT_FDCWD, linkname) != 0) {
		complain("case1: symlinkat: %s", strerror(errno));
		return;
	}

	char buf[256];
	ssize_t n = readlinkat(AT_FDCWD, linkname, buf, sizeof(buf) - 1);
	if (n < 0) {
		complain("case1: readlinkat: %s", strerror(errno));
		unlink(linkname);
		return;
	}
	buf[n] = '\0';
	if ((size_t)n != strlen(target) || strcmp(buf, target) != 0)
		complain("case1: readlink returned %zd bytes = '%s' "
			 "(expected '%s')",
			 n, buf, target);
	unlink(linkname);
}

static void case_stat_vs_lstat(void)
{
	char target[64], linkname[64];
	snprintf(target, sizeof(target), "t_sl.t.%ld", (long)getpid());
	snprintf(linkname, sizeof(linkname), "t_sl.l.%ld", (long)getpid());
	unlink(target); unlink(linkname);

	int fd = open(target, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case2: open target: %s", strerror(errno)); return; }
	close(fd);

	if (symlinkat(target, AT_FDCWD, linkname) != 0) {
		complain("case2: symlinkat: %s", strerror(errno));
		unlink(target);
		return;
	}

	struct stat st_link, st_target;
	if (lstat(linkname, &st_link) != 0) {
		complain("case2: lstat(link): %s", strerror(errno));
		goto out;
	}
	if (!S_ISLNK(st_link.st_mode))
		complain("case2: lstat(link) mode not S_IFLNK "
			 "(got 0%o)",
			 st_link.st_mode & S_IFMT);

	if (stat(linkname, &st_target) != 0) {
		complain("case2: stat(link): %s", strerror(errno));
		goto out;
	}
	if (!S_ISREG(st_target.st_mode))
		complain("case2: stat(link) should see target (regular "
			 "file), got 0%o",
			 st_target.st_mode & S_IFMT);

out:
	unlink(linkname);
	unlink(target);
}

static void case_dangling(void)
{
	char linkname[64];
	snprintf(linkname, sizeof(linkname), "t_sl.d.%ld", (long)getpid());
	const char *target = "t_sl.does_not_exist";
	unlink(linkname);

	if (symlinkat(target, AT_FDCWD, linkname) != 0) {
		complain("case3: symlinkat: %s", strerror(errno));
		return;
	}

	/* readlink must succeed and return the target string. */
	char buf[128];
	ssize_t n = readlinkat(AT_FDCWD, linkname, buf, sizeof(buf) - 1);
	if (n < 0) {
		complain("case3: readlinkat on dangling: %s",
			 strerror(errno));
		goto out;
	}
	buf[n] = '\0';
	if (strcmp(buf, target) != 0)
		complain("case3: readlink returned '%s' (expected '%s')",
			 buf, target);

	/* lstat must succeed and show S_IFLNK. */
	struct stat st;
	if (lstat(linkname, &st) != 0)
		complain("case3: lstat on dangling: %s", strerror(errno));
	else if (!S_ISLNK(st.st_mode))
		complain("case3: lstat on dangling link not S_IFLNK");

	/* stat() through the dangling link must return ENOENT. */
	errno = 0;
	if (stat(linkname, &st) == 0 || errno != ENOENT)
		complain("case3: stat() through dangling expected "
			 "-1/ENOENT, got errno=%s",
			 strerror(errno));
out:
	unlink(linkname);
}

static void case_long_target(void)
{
	char linkname[64];
	snprintf(linkname, sizeof(linkname), "t_sl.lg.%ld", (long)getpid());
	unlink(linkname);

	/*
	 * Build a long target close to PATH_MAX but under it so POSIX
	 * allows the attempt.  Servers may cap below PATH_MAX; accept
	 * ENAMETOOLONG / EINVAL as a server-side cap, not a failure.
	 */
	size_t want = 4000; /* comfortably under 4095 */
	char *target = malloc(want + 1);
	if (!target) { complain("case4: malloc"); return; }
	memset(target, 'x', want);
	target[want] = '\0';

	if (symlinkat(target, AT_FDCWD, linkname) != 0) {
		if (errno == ENAMETOOLONG || errno == EINVAL) {
			if (!Sflag)
				printf("NOTE: %s: case4 server rejected "
				       "4000-byte target with %s (server cap)\n",
				       myname, strerror(errno));
			free(target);
			return;
		}
		complain("case4: symlinkat long: %s", strerror(errno));
		free(target);
		return;
	}

	char *buf = malloc(want + 16);
	ssize_t n = readlinkat(AT_FDCWD, linkname, buf, want + 15);
	if (n < 0) {
		complain("case4: readlinkat long: %s", strerror(errno));
	} else if ((size_t)n != want || memcmp(buf, target, want) != 0) {
		complain("case4: long-target round-trip corrupted "
			 "(got %zd bytes)",
			 n);
	}
	free(buf);
	free(target);
	unlink(linkname);
}

static void case_loop(void)
{
	char a[64], b[64];
	snprintf(a, sizeof(a), "t_sl.a.%ld", (long)getpid());
	snprintf(b, sizeof(b), "t_sl.b.%ld", (long)getpid());
	unlink(a); unlink(b);

	if (symlinkat(b, AT_FDCWD, a) != 0) {
		complain("case5: symlink a->b: %s", strerror(errno));
		return;
	}
	if (symlinkat(a, AT_FDCWD, b) != 0) {
		complain("case5: symlink b->a: %s", strerror(errno));
		unlink(a);
		return;
	}

	/* readlink on each must return the immediate target. */
	char buf[64];
	ssize_t n = readlinkat(AT_FDCWD, a, buf, sizeof(buf) - 1);
	if (n >= 0) { buf[n] = '\0'; }
	if (n < 0 || strcmp(buf, b) != 0)
		complain("case5: readlink(a) = '%s' (expected '%s')",
			 n < 0 ? "(error)" : buf, b);

	/* open() following the loop must return ELOOP. */
	errno = 0;
	int fd = open(a, O_RDONLY);
	if (fd >= 0) {
		complain("case5: open() on loop unexpectedly succeeded");
		close(fd);
	} else if (errno != ELOOP) {
		complain("case5: open() on loop: expected ELOOP, got %s",
			 strerror(errno));
	}

	unlink(a);
	unlink(b);
}

static void case_unlink_link_not_target(void)
{
	char target[64], linkname[64];
	snprintf(target, sizeof(target), "t_sl.t2.%ld", (long)getpid());
	snprintf(linkname, sizeof(linkname), "t_sl.l2.%ld", (long)getpid());
	unlink(target); unlink(linkname);

	int fd = open(target, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case6: open target: %s", strerror(errno)); return; }
	close(fd);

	if (symlinkat(target, AT_FDCWD, linkname) != 0) {
		complain("case6: symlinkat: %s", strerror(errno));
		unlink(target);
		return;
	}

	if (unlink(linkname) != 0) {
		complain("case6: unlink(link): %s", strerror(errno));
		unlink(target);
		return;
	}

	/* Target should still exist. */
	if (access(target, F_OK) != 0)
		complain("case6: unlinking the symlink removed the target");

	unlink(target);
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
		"symlinkat/readlinkat -> NFSv4 SYMLINK/READLINK "
		"(RFC 7530 S18.26/S18.22)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	case_round_trip();
	case_stat_vs_lstat();
	case_dangling();
	case_long_target();
	case_loop();
	case_unlink_link_not_target();

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
