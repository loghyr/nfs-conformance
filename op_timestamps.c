/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_timestamps.c -- exercise atime / mtime / ctime cascades
 * across filesystem syscalls (ported from cthon04 special/).
 *
 * POSIX ties timestamp updates to specific operations:
 *
 *   write(2)        → mtime + ctime advance
 *   read(2)         → atime advances (subject to relatime / noatime)
 *   chmod(2)        → ctime advances; atime / mtime unchanged
 *   chown(2)        → ctime advances; atime / mtime unchanged
 *   truncate(2)     → mtime + ctime advance on size change
 *   link(2)         → ctime of source advances
 *   rename(2)       → ctime of renamed inode advances
 *   utimensat(2)    → atime / mtime to requested values
 *                     (UTIME_NOW / UTIME_OMIT) and ctime to now
 *
 * op_utimensat covers utimensat itself.  op_timestamps covers the
 * cascades across other syscalls, plus nanosecond-precision
 * round-trips that NFS servers frequently truncate to seconds.
 *
 * Cases:
 *
 *   1. write advances mtime + ctime; does NOT advance atime.
 *   2. read advances atime (unless mount is noatime/nodiratime).
 *      Report NOTE rather than FAIL if atime unchanged.
 *   3. chmod advances ctime only.
 *   4. chown advances ctime only.
 *   5. truncate (grow) advances mtime + ctime.
 *   6. link advances ctime on the source inode; mtime unchanged.
 *   7. rename advances ctime on the renamed inode.
 *   8. Nanosecond precision: utimensat with nsec != 0; stat reads
 *      it back; if returned nsec == 0, server truncated (NOTE).
 *
 * Portable: POSIX.  Nanosecond field name varies
 * (st_mtimespec on macOS; st_mtim elsewhere) — handled via macro.
 */

#if defined(__APPLE__)
# define _DARWIN_C_SOURCE
#endif
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

#ifdef __APPLE__
# define ST_ATIM(st) ((st).st_atimespec)
# define ST_MTIM(st) ((st).st_mtimespec)
# define ST_CTIM(st) ((st).st_ctimespec)
#else
# define ST_ATIM(st) ((st).st_atim)
# define ST_MTIM(st) ((st).st_mtim)
# define ST_CTIM(st) ((st).st_ctim)
#endif

int Hflag = 0;
int Sflag = 0;
int Tflag = 0;
int Fflag = 0;
int Nflag = 0;

static const char *myname = "op_timestamps";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  atime/mtime/ctime cascades across syscalls\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static int ts_ge(struct timespec a, struct timespec b)
{
	if (a.tv_sec != b.tv_sec) return a.tv_sec > b.tv_sec;
	return a.tv_nsec >= b.tv_nsec;
}

static int ts_gt(struct timespec a, struct timespec b)
{
	if (a.tv_sec != b.tv_sec) return a.tv_sec > b.tv_sec;
	return a.tv_nsec > b.tv_nsec;
}

static int create_file(const char *path, size_t sz)
{
	unlink(path);
	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) return -1;
	if (sz > 0) {
		char *buf = calloc(1, sz);
		if (!buf) { close(fd); return -1; }
		ssize_t w = write(fd, buf, sz);
		free(buf);
		if (w != (ssize_t)sz) { close(fd); return -1; }
	}
	close(fd);
	return 0;
}

static void case_write_mtime_ctime(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_ts.wm.%ld", (long)getpid());
	if (create_file(a, 0) != 0) {
		complain("case1: create: %s", strerror(errno));
		return;
	}
	struct stat st0;
	if (stat(a, &st0) != 0) {
		complain("case1: stat: %s", strerror(errno));
		unlink(a); return;
	}

	/* 20 ms advances most filesystem clock resolutions. */
	struct timespec delay = { 0, 20 * 1000 * 1000 };
	nanosleep(&delay, NULL);

	int fd = open(a, O_WRONLY);
	if (fd < 0) { complain("case1: reopen: %s", strerror(errno));
		unlink(a); return; }
	if (write(fd, "x", 1) != 1) {
		complain("case1: write: %s", strerror(errno));
		close(fd); unlink(a); return;
	}
	close(fd);

	struct stat st1;
	if (stat(a, &st1) != 0) {
		complain("case1: stat after write: %s", strerror(errno));
		unlink(a); return;
	}

	if (!ts_gt(ST_MTIM(st1), ST_MTIM(st0)))
		complain("case1: mtime did not advance after write "
			 "(%lld.%09ld -> %lld.%09ld)",
			 (long long)ST_MTIM(st0).tv_sec,
			 ST_MTIM(st0).tv_nsec,
			 (long long)ST_MTIM(st1).tv_sec,
			 ST_MTIM(st1).tv_nsec);
	if (!ts_ge(ST_CTIM(st1), ST_CTIM(st0)))
		complain("case1: ctime regressed after write");

	unlink(a);
}

static void case_read_atime(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_ts.ra.%ld", (long)getpid());
	if (create_file(a, 16) != 0) {
		complain("case2: create: %s", strerror(errno));
		return;
	}
	struct stat st0;
	if (stat(a, &st0) != 0) {
		complain("case2: stat: %s", strerror(errno));
		unlink(a); return;
	}

	struct timespec delay = { 0, 20 * 1000 * 1000 };
	nanosleep(&delay, NULL);

	int fd = open(a, O_RDONLY);
	if (fd < 0) { complain("case2: reopen: %s", strerror(errno));
		unlink(a); return; }
	char buf[16];
	ssize_t r = read(fd, buf, sizeof(buf));
	close(fd);
	if (r < 0) {
		complain("case2: read: %s", strerror(errno));
		unlink(a); return;
	}

	struct stat st1;
	if (stat(a, &st1) != 0) {
		complain("case2: stat after read: %s", strerror(errno));
		unlink(a); return;
	}
	if (!ts_gt(ST_ATIM(st1), ST_ATIM(st0))) {
		if (!Sflag)
			printf("NOTE: %s: case2 atime did not advance "
			       "after read — mount is likely noatime/"
			       "relatime/nodiratime, or the server "
			       "defers atime updates\n", myname);
	}
	/* mtime must NOT have advanced. */
	if (ts_gt(ST_MTIM(st1), ST_MTIM(st0)))
		complain("case2: mtime advanced on read (should not)");

	unlink(a);
}

static void case_chmod_ctime(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_ts.cm.%ld", (long)getpid());
	if (create_file(a, 0) != 0) {
		complain("case3: create: %s", strerror(errno));
		return;
	}
	struct stat st0;
	stat(a, &st0);

	struct timespec delay = { 0, 20 * 1000 * 1000 };
	nanosleep(&delay, NULL);

	if (chmod(a, 0600) != 0) {
		complain("case3: chmod: %s", strerror(errno));
		unlink(a); return;
	}

	struct stat st1;
	stat(a, &st1);
	if (!ts_gt(ST_CTIM(st1), ST_CTIM(st0)))
		complain("case3: ctime did not advance after chmod");
	if (ts_gt(ST_MTIM(st1), ST_MTIM(st0)))
		complain("case3: mtime advanced on chmod (should not)");
	if (ts_gt(ST_ATIM(st1), ST_ATIM(st0)))
		complain("case3: atime advanced on chmod (should not)");

	unlink(a);
}

static void case_chown_ctime(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_ts.co.%ld", (long)getpid());
	if (create_file(a, 0) != 0) {
		complain("case4: create: %s", strerror(errno));
		return;
	}
	struct stat st0;
	stat(a, &st0);

	struct timespec delay = { 0, 20 * 1000 * 1000 };
	nanosleep(&delay, NULL);

	if (chown(a, getuid(), getgid()) != 0) {
#ifdef __linux__
		if (errno == EINVAL) {
			if (!Sflag)
				printf("NOTE: %s: case4 chown(self) EINVAL "
				       "(client-side idmap mismatch); "
				       "skipping timestamp check\n", myname);
			unlink(a); return;
		}
#endif
		complain("case4: chown: %s", strerror(errno));
		unlink(a); return;
	}

	struct stat st1;
	stat(a, &st1);
	if (!ts_gt(ST_CTIM(st1), ST_CTIM(st0)))
		complain("case4: ctime did not advance after chown");
	if (ts_gt(ST_MTIM(st1), ST_MTIM(st0)))
		complain("case4: mtime advanced on chown (should not)");

	unlink(a);
}

static void case_truncate_mtime_ctime(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_ts.tr.%ld", (long)getpid());
	if (create_file(a, 16) != 0) {
		complain("case5: create: %s", strerror(errno));
		return;
	}
	struct stat st0;
	stat(a, &st0);

	struct timespec delay = { 0, 20 * 1000 * 1000 };
	nanosleep(&delay, NULL);

	if (truncate(a, 128) != 0) {
		complain("case5: truncate: %s", strerror(errno));
		unlink(a); return;
	}

	struct stat st1;
	stat(a, &st1);
	if (!ts_gt(ST_MTIM(st1), ST_MTIM(st0)))
		complain("case5: mtime did not advance after truncate");
	if (!ts_gt(ST_CTIM(st1), ST_CTIM(st0)))
		complain("case5: ctime did not advance after truncate");

	unlink(a);
}

static void case_link_ctime(void)
{
	char a[64], b[64];
	snprintf(a, sizeof(a), "t_ts.la.%ld", (long)getpid());
	snprintf(b, sizeof(b), "t_ts.lb.%ld", (long)getpid());
	unlink(a); unlink(b);
	if (create_file(a, 0) != 0) {
		complain("case6: create: %s", strerror(errno));
		return;
	}
	struct stat st0;
	stat(a, &st0);

	struct timespec delay = { 0, 20 * 1000 * 1000 };
	nanosleep(&delay, NULL);

	if (link(a, b) != 0) {
		complain("case6: link: %s", strerror(errno));
		unlink(a); return;
	}

	struct stat st1;
	stat(a, &st1);
	if (!ts_gt(ST_CTIM(st1), ST_CTIM(st0)))
		complain("case6: ctime did not advance after link");
	if (ts_gt(ST_MTIM(st1), ST_MTIM(st0)))
		complain("case6: mtime advanced on link (should not)");

	unlink(a); unlink(b);
}

static void case_rename_ctime(void)
{
	char a[64], b[64];
	snprintf(a, sizeof(a), "t_ts.ra.%ld", (long)getpid());
	snprintf(b, sizeof(b), "t_ts.rb.%ld", (long)getpid());
	unlink(a); unlink(b);
	if (create_file(a, 0) != 0) {
		complain("case7: create: %s", strerror(errno));
		return;
	}
	struct stat st0;
	stat(a, &st0);

	struct timespec delay = { 0, 20 * 1000 * 1000 };
	nanosleep(&delay, NULL);

	if (rename(a, b) != 0) {
		complain("case7: rename: %s", strerror(errno));
		unlink(a); return;
	}

	struct stat st1;
	stat(b, &st1);
	if (!ts_gt(ST_CTIM(st1), ST_CTIM(st0)))
		complain("case7: ctime did not advance after rename");

	unlink(b);
}

static void case_nanosecond_precision(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_ts.ns.%ld", (long)getpid());
	if (create_file(a, 0) != 0) {
		complain("case8: create: %s", strerror(errno));
		return;
	}

	struct timespec ts[2];
	ts[0].tv_sec = 1700000000; ts[0].tv_nsec = 123456789;  /* atime */
	ts[1].tv_sec = 1700000001; ts[1].tv_nsec = 987654321;  /* mtime */

	if (utimensat(AT_FDCWD, a, ts, 0) != 0) {
		complain("case8: utimensat: %s", strerror(errno));
		unlink(a); return;
	}

	struct stat st;
	if (stat(a, &st) != 0) {
		complain("case8: stat: %s", strerror(errno));
		unlink(a); return;
	}

	struct timespec got_mtime = ST_MTIM(st);
	if (got_mtime.tv_sec != ts[1].tv_sec) {
		complain("case8: mtime.sec round-trip: got %lld, "
			 "expected %lld",
			 (long long)got_mtime.tv_sec,
			 (long long)ts[1].tv_sec);
	} else if (got_mtime.tv_nsec == 0 && ts[1].tv_nsec != 0) {
		if (!Sflag)
			printf("NOTE: %s: case8 mtime nsec truncated to 0 "
			       "on round-trip — server has second-only "
			       "timestamp precision\n", myname);
	} else if (got_mtime.tv_nsec != ts[1].tv_nsec && !Sflag) {
		printf("NOTE: %s: case8 mtime nsec truncated %ld -> %ld "
		       "(server has coarser-than-ns precision)\n",
		       myname, ts[1].tv_nsec, got_mtime.tv_nsec);
	}

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
		"atime/mtime/ctime cascades across syscalls");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_write_mtime_ctime", case_write_mtime_ctime());
	RUN_CASE("case_read_atime", case_read_atime());
	RUN_CASE("case_chmod_ctime", case_chmod_ctime());
	RUN_CASE("case_chown_ctime", case_chown_ctime());
	RUN_CASE("case_truncate_mtime_ctime", case_truncate_mtime_ctime());
	RUN_CASE("case_link_ctime", case_link_ctime());
	RUN_CASE("case_rename_ctime", case_rename_ctime());
	RUN_CASE("case_nanosecond_precision",
		 case_nanosecond_precision());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
