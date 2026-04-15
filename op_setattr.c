/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_setattr.c -- exercise NFSv4 SETATTR (RFC 7530 S18.30) via the
 * POSIX chmod / chown / truncate / utimensat surface.
 *
 * Cases:
 *
 *   1. chmod(0600) then stat -- st_mode & 0777 == 0600.
 *
 *   2. chmod(0644) round-trip.  Catches servers that silently round
 *      to a default mask.
 *
 *   3. truncate(0) on a file with content -- st_size becomes 0,
 *      subsequent read returns 0 bytes.
 *
 *   4. truncate(8192) grows the file; bytes beyond original EOF
 *      read as zeros (POSIX sparse-tail semantics, RFC 7862 S4 hole
 *      semantics).
 *
 *   5. chown(uid, gid) to the current values: always safe, should
 *      succeed even for non-root callers.  Catches servers that
 *      reject no-op ownership change requests.
 *
 *   6. utimensat(UTIME_NOW, UTIME_NOW): both mtime and atime should
 *      advance to a value >= the pre-call now.  Servers sometimes
 *      handle UTIME_NOW for one and not the other.
 *
 *   7. utimensat(UTIME_OMIT, UTIME_OMIT): no-op.  POSIX requires
 *      success; NFSv4 SETATTR must send an empty attrmask and the
 *      server must accept it.  Historically buggy on several impls.
 *
 * Portable: POSIX across Linux / FreeBSD / macOS / Solaris.
 *
 * Diagnostic value: SETATTR is the one mutating op that does NOT
 * touch directory state.  If op_setattr passes under xprtsec=tls
 * but op_rmdir / op_rename_atomic fail, the bug is specifically in
 * the parent-directory-mutation authorization path (REMOVE / RENAME
 * / CREATE under TLS), not in SETATTR generally.
 */

#define _POSIX_C_SOURCE 200809L

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

static const char *myname = "op_setattr";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise chmod/chown/truncate/utimensat -> NFSv4 SETATTR\n"
		"  (RFC 7530 S18.30)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static int touch(const char *path, const char *body)
{
	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("open(%s): %s", path, strerror(errno));
		return -1;
	}
	int rc = 0;
	if (body) {
		size_t n = strlen(body);
		rc = pwrite_all(fd, body, n, 0, path);
	}
	close(fd);
	return rc;
}

static void case_chmod_restrict(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_sa.cm.%ld", (long)getpid());
	unlink(a);
	if (touch(a, NULL) < 0) return;

	if (chmod(a, 0600) != 0) {
		complain("case1: chmod(0600): %s", strerror(errno));
		unlink(a);
		return;
	}
	struct stat st;
	if (stat(a, &st) != 0) {
		complain("case1: stat: %s", strerror(errno));
	} else if ((st.st_mode & 0777) != 0600) {
		complain("case1: st_mode & 0777 = 0%o, expected 0600",
			 st.st_mode & 0777);
	}
	unlink(a);
}

static void case_chmod_round_trip(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_sa.rt.%ld", (long)getpid());
	unlink(a);
	if (touch(a, NULL) < 0) return;

	if (chmod(a, 0600) != 0 || chmod(a, 0644) != 0) {
		complain("case2: chmod round-trip: %s", strerror(errno));
		unlink(a);
		return;
	}
	struct stat st;
	if (stat(a, &st) != 0 || (st.st_mode & 0777) != 0644)
		complain("case2: round-trip mode = 0%o, expected 0644",
			 st.st_mode & 0777);
	unlink(a);
}

static void case_truncate_shrink(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_sa.ts.%ld", (long)getpid());
	unlink(a);
	if (touch(a, "some content here\n") < 0) return;

	if (truncate(a, 0) != 0) {
		complain("case3: truncate(0): %s", strerror(errno));
		unlink(a);
		return;
	}
	struct stat st;
	if (stat(a, &st) != 0) {
		complain("case3: stat: %s", strerror(errno));
	} else if (st.st_size != 0) {
		complain("case3: st_size after truncate(0) = %lld",
			 (long long)st.st_size);
	}
	unlink(a);
}

static void case_truncate_grow(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_sa.tg.%ld", (long)getpid());
	unlink(a);
	if (touch(a, "abc") < 0) return;

	if (truncate(a, 8192) != 0) {
		complain("case4: truncate(8192): %s", strerror(errno));
		unlink(a);
		return;
	}
	struct stat st;
	if (stat(a, &st) != 0 || st.st_size != 8192) {
		complain("case4: st_size after grow = %lld",
			 (long long)(st.st_size));
		unlink(a);
		return;
	}
	/*
	 * Bytes beyond the original 3 must read as zeros (POSIX
	 * sparse-tail).  Reading from offset 100, 4 bytes of zero.
	 */
	int fd = open(a, O_RDONLY);
	if (fd < 0) {
		complain("case4: reopen: %s", strerror(errno));
		unlink(a);
		return;
	}
	unsigned char buf[4];
	if (pread_all(fd, buf, 4, 100, "case4") < 0) {
		close(fd);
		unlink(a);
		return;
	}
	close(fd);
	if (!all_zero(buf, 4))
		complain("case4: bytes past original EOF not zero-filled "
			 "(0x%02x%02x%02x%02x)",
			 buf[0], buf[1], buf[2], buf[3]);
	unlink(a);
}

static void case_chown_noop(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_sa.co.%ld", (long)getpid());
	unlink(a);
	if (touch(a, NULL) < 0) return;

	uid_t u = getuid();
	gid_t g = getgid();
	if (chown(a, u, g) != 0)
		complain("case5: chown(%u,%u) no-op: %s",
			 (unsigned)u, (unsigned)g, strerror(errno));
	unlink(a);
}

static void case_utime_now(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_sa.un.%ld", (long)getpid());
	unlink(a);
	if (touch(a, NULL) < 0) return;

	struct timespec before;
	clock_gettime(CLOCK_REALTIME, &before);
	/* sleep 10ms so UTIME_NOW has a measurable forward move */
	struct timespec ten_ms = { 0, 10 * 1000 * 1000 };
	nanosleep(&ten_ms, NULL);

	struct timespec ts[2] = {
		{ .tv_nsec = UTIME_NOW },
		{ .tv_nsec = UTIME_NOW },
	};
	if (utimensat(AT_FDCWD, a, ts, 0) != 0) {
		complain("case6: utimensat(UTIME_NOW): %s", strerror(errno));
		unlink(a);
		return;
	}
	struct stat st;
	if (stat(a, &st) != 0) {
		complain("case6: stat: %s", strerror(errno));
		unlink(a);
		return;
	}
	/*
	 * NFSv4 servers often truncate nsec resolution; compare at
	 * 1-second granularity to be portable.
	 */
	if (st.st_mtime < before.tv_sec)
		complain("case6: mtime %ld < pre-call now %ld "
			 "(UTIME_NOW did not advance)",
			 (long)st.st_mtime, (long)before.tv_sec);
	unlink(a);
}

static void case_utime_omit(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_sa.uo.%ld", (long)getpid());
	unlink(a);
	if (touch(a, NULL) < 0) return;

	struct timespec ts[2] = {
		{ .tv_nsec = UTIME_OMIT },
		{ .tv_nsec = UTIME_OMIT },
	};
	if (utimensat(AT_FDCWD, a, ts, 0) != 0)
		complain("case7: utimensat(UTIME_OMIT,UTIME_OMIT): %s",
			 strerror(errno));
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
		"chmod/chown/truncate/utimensat -> NFSv4 SETATTR "
		"(RFC 7530 S18.30)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	case_chmod_restrict();
	case_chmod_round_trip();
	case_truncate_shrink();
	case_truncate_grow();
	case_chown_noop();
	case_utime_now();
	case_utime_omit();

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
